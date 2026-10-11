"""Core firewall (Phase 3 + 6 glue): validate -> route -> detect -> policy -> execute.

Fail-closed: any unexpected exception produces a BLOCKED response.
Order of authority: detection can only *block*; only the policy engine can *permit*.
"""
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import config
from audit import AuditLog, new_event_id
from banking_simulator import BankSimulator
from detector import Detector, noisy_or
from hell_track import HellTrack, redact, sender_ref
from policy_engine import authorize, issue_ticket
from pydantic import ValidationError
from schemas import (Action, AnalysisStatus, BankRequest, BankResponse, Route, Status,
                     ThreatCategory as TC)
from trust_router import TrustRouter

_KNOWN_FIELDS = set(BankRequest.model_fields)
_ATTACK_TEXT = {
    TC.PROMPT_INJECTION: "Prompt-injection instructions detected in {where}.",
    TC.JAILBREAK: "Jailbreak / roleplay attempt detected in {where}.",
    TC.MALICIOUS_MEMO: "Tool-directed instructions detected in the transaction memo.",
    TC.ABUSE_PATTERN: "Abusive request pattern (request rate or repeated blocked requests).",
    TC.NONE: "Suspicious content detected in {where}.",
}


@dataclass
class Decision:
    status: Status
    risk: float
    category: TC
    route: Route
    explanation: str
    sender_id: str = "unknown"
    account_id: str = "-"
    action: str = "-"
    result: Optional[dict] = None
    rules: list = field(default_factory=list)
    markers: list = field(default_factory=list)
    memo: str = ""
    message: str = ""
    hell: bool = False
    clarification: bool = False


class Firewall:
    def __init__(self, bank: Optional[BankSimulator] = None, audit: Optional[AuditLog] = None,
                 router: Optional[TrustRouter] = None, detector: Optional[Detector] = None,
                 hell_track: Optional[HellTrack] = None):
        self.bank = bank or BankSimulator()
        self.audit = audit or AuditLog()
        self.router = router or TrustRouter()
        self.detector = detector or Detector()
        self.hell = hell_track or HellTrack(sink=self._on_analysis)
        self._exec_lock = threading.Lock()       # serialises policy-check + execution
        self._idem: dict = {}
        self._event_sender: dict = {}

    # ---------------------------------------------------------------- public
    def handle(self, raw) -> BankResponse:
        t0 = time.perf_counter()
        event_id = new_event_id()
        try:
            dec = self._decide(raw, event_id)
        except Exception:                        # fail closed
            dec = Decision(Status.BLOCKED, 0.5, TC.POLICY_VIOLATION, Route.STANDARD,
                           "Internal error; request denied (fail-closed).")
        return self._finalize(dec, event_id, t0)

    def reset(self) -> None:
        """Restore the demo to a clean state: fresh balances, reputation, idempotency cache, audit log."""
        with self._exec_lock:
            self.hell.drain(2)
            self.bank = BankSimulator()
            self.router = TrustRouter()
            self._idem.clear()
            self._event_sender.clear()
            self.hell.reset()
            self.audit.clear()

    # --------------------------------------------------------------- pipeline
    def _decide(self, raw, event_id: str) -> Decision:
        data, err = self._parse(raw)
        if err:
            return Decision(Status.BLOCKED, 0.5, TC.MALFORMED_REQUEST, Route.STANDARD, err)
        try:
            req = BankRequest.model_validate(data)
        except ValidationError as e:
            return self._malformed(data, e)

        base = dict(sender_id=req.sender_id, account_id=req.account_id, action=req.action.value,
                    memo=req.memo, message=req.message)
        identity = self.bank.authenticate(req.sender_id, req.auth_token)
        rate = self.router.note_request(req.sender_id)
        lane = self.router.decide(req, identity, self.bank).lane

        det = self.detector.inspect(req.message, req.memo, deep=(lane == Route.STANDARD))
        if lane == Route.SUPERFAST and det.risk >= config.THRESH_FAST_ESCALATE:
            lane = Route.STANDARD                # suspicious content: deeper inspection, trust is irrelevant now
            det = self.detector.inspect(req.message, req.memo, deep=True)

        rep = self.router.reputation_penalty(req.sender_id)
        abuse = rate > config.RATE_LIMIT_PER_MIN
        risk = noisy_or([det.risk, rep, 0.7 if abuse else 0.0])
        base.update(rules=det.rules, markers=det.markers)

        # 1) detection can only block
        if risk >= config.THRESH_SUSPICIOUS:
            self.router.record_block(req.sender_id)
            cat = det.category if (det.category != TC.NONE and det.risk >= config.THRESH_FAST_ESCALATE) else TC.ABUSE_PATTERN
            where = " and ".join(det.fields) or "request"
            return Decision(Status.BLOCKED, risk, cat, Route.HELL_TRACK,
                            _ATTACK_TEXT[cat].format(where=where), hell=True, **base)

        if identity is None:
            return Decision(Status.BLOCKED, max(risk, 0.5), TC.POLICY_VIOLATION, lane,
                            "Authentication failed.", **base)

        # 2) semantic validation: ambiguous / contradictory requests are never guessed at
        amb = self._ambiguity(req)
        if amb:
            return Decision(Status.BLOCKED, max(risk, 0.3), TC.AMBIGUOUS_REQUEST, lane,
                            amb, clarification=True, **base)

        # 3) idempotency + policy gate + execution (serialised)
        with self._exec_lock:
            fp = hashlib.sha256(json.dumps([req.account_id, req.action.value, req.recipient_id, str(req.amount),
                                            req.memo, req.message]).encode()).hexdigest()
            if req.idempotency_key:
                prior = self._idem.get((req.sender_id, req.idempotency_key))
                if prior:
                    if prior[0] != fp:
                        return Decision(Status.BLOCKED, max(risk, 0.5), TC.POLICY_VIOLATION, lane,
                                        "Idempotency key reused with a different payload.", **base)
                    return prior[1]                # replay: same outcome, never a second execution
            pol = authorize(req, self.bank)
            if not pol.allowed:
                dec = Decision(Status.BLOCKED, max(risk, 0.5), TC.POLICY_VIOLATION, lane, pol.reason, **base)
            else:
                result = self._execute(req, event_id)
                dec = Decision(Status.APPROVED, risk, TC.NONE, lane,
                               f"Validated on the {lane.value.title()} lane; all policy checks passed.",
                               result=result, **base)
            if req.idempotency_key:
                if len(self._idem) >= 10_000:            # bounded: no unbounded memory growth
                    self._idem.pop(next(iter(self._idem)))
                self._idem[(req.sender_id, req.idempotency_key)] = (fp, dec)
            return dec

    def _execute(self, req: BankRequest, event_id: str) -> dict:
        if req.action == Action.BALANCE:
            return {"balance": str(self.bank.balance(req.account_id)), "currency": "USD"}
        if req.action == Action.HISTORY:
            return {"transactions": self.bank.history(req.account_id)}
        ticket = issue_ticket(event_id, req.account_id, req.recipient_id, req.amount)
        return self.bank.execute_transfer(ticket, req.account_id, req.recipient_id, req.amount, req.memo)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _ambiguity(req: BankRequest) -> Optional[str]:
        if req.action == Action.TRANSFER:
            if req.recipient_id is None or req.amount is None:
                return "Transfer needs both a recipient and an amount; please clarify."
        else:
            if req.recipient_id is not None or req.amount is not None or req.memo:
                return "Request contains fields that contradict its action; please clarify."
        return None

    def _parse(self, raw):
        if isinstance(raw, (bytes, str)):
            if len(raw) > config.MAX_RAW_BYTES:
                return None, "Request exceeds the maximum size."
            try:
                raw = json.loads(raw)
            except (ValueError, RecursionError):
                return None, "Request is not valid JSON."
        if not isinstance(raw, dict):
            return None, "Request must be a JSON object."
        return raw, None

    def _malformed(self, data: dict, e: ValidationError) -> Decision:
        """Malformed requests are still scanned: a broken envelope may carry an attack."""
        strings = [v[:2000] for v in data.values() if isinstance(v, str)][:20]
        det = self.detector.inspect(memo="\n".join(strings), deep=True)
        sid = data.get("sender_id") if isinstance(data.get("sender_id"), str) else "unknown"
        if not (sid and sid.replace("_", "").replace("-", "").isalnum() and len(sid) <= 64):
            sid = "unknown"
        if det.risk >= config.THRESH_SUSPICIOUS:
            cat = det.category if det.category != TC.NONE else TC.PROMPT_INJECTION
            return Decision(Status.BLOCKED, det.risk, cat, Route.HELL_TRACK,
                            "Malformed request carrying attack content.", sender_id=sid,
                            rules=det.rules, markers=det.markers, memo="\n".join(strings)[:500], hell=True)
        bad = sorted({str(x["loc"][0]) for x in e.errors() if x["loc"] and str(x["loc"][0]) in _KNOWN_FIELDS})
        detail = f" Invalid fields: {', '.join(bad)}." if bad else ""
        return Decision(Status.BLOCKED, 0.5, TC.MALFORMED_REQUEST, Route.STANDARD,
                        "Request failed schema validation." + detail, sender_id=sid)

    def _finalize(self, d: Decision, event_id: str, t0: float) -> BankResponse:
        latency = round((time.perf_counter() - t0) * 1000, 2)
        analysis = AnalysisStatus.NOT_REQUIRED
        if d.hell:
            analysis = AnalysisStatus.PENDING
        memo_red = redact(d.memo or d.message)
        resp = BankResponse(
            event_id=event_id, status=d.status, risk_score=round(min(d.risk, 1.0), 4),
            threat_category=d.category, route=d.route, explanation=d.explanation,
            execution_allowed=(d.status == Status.APPROVED), analysis_status=analysis,
            latency_ms=latency, result=d.result if d.status == Status.APPROVED else None)

        # The decision is final and recorded BEFORE any analysis is queued.
        if d.hell:
            self._event_sender[event_id] = d.sender_id
            if len(self._event_sender) > 5000:
                self._event_sender.pop(next(iter(self._event_sender)))
        self.audit.append({
            "event_id": event_id, "ts": time.time(), "sender_id": d.sender_id, "account_id": d.account_id,
            "action": d.action, "route": d.route.value, "status": d.status.value, "risk": resp.risk_score,
            "category": d.category.value, "explanation": d.explanation,
            "execution_allowed": resp.execution_allowed, "latency_ms": latency, "rules": d.rules,
            "markers": d.markers, "memo_redacted": memo_red, "clarification": d.clarification,
        }, analysis.value)

        if d.hell:
            ok = self.hell.submit({
                "event_id": event_id, "sender_ref": sender_ref(d.sender_id), "risk": resp.risk_score,
                "category": d.category.value, "rules": d.rules, "markers": d.markers,
                "memo": redact(d.memo), "message": redact(d.message), "ts": time.time(),
            })
            if not ok:
                self.audit.set_analysis(event_id, AnalysisStatus.UNAVAILABLE.value)
                resp = resp.model_copy(update={"analysis_status": AnalysisStatus.UNAVAILABLE})
        return resp

    def _on_analysis(self, event_id: str, status: str, finding: Optional[dict]) -> None:
        """Narrow sink for the Hell Track worker: updates analysis status, and may only
        make a sender's treatment stricter."""
        self.audit.set_analysis(event_id, status, finding)
        if finding and finding.get("repeat_offender"):
            sid = self._event_sender.get(event_id)
            if sid:
                self.router.flag_sender(sid)
