"""Hell Track (Phase 5): containment-first, isolated post-block analysis.

Isolation rules enforced by construction:
  * This module imports NO banking code (banking_simulator, policy_engine, firewall).
    tests/test_security.py checks that.
  * It only ever receives a *sanitized* event (redacted text, hashed sender ref).
  * It has no way to approve, release or replay the original request.
  * Its only output is a finding handed to a narrow `sink` callback.
  * Work is bounded: fixed queue size, time budget, truncated inputs.
Limitation: this is a thread in the same process. For real isolation run it as a
separate process/container with no credentials and restricted network.
"""
import hashlib
import queue
import re
import threading
import time
from collections import Counter
from typing import Callable, Optional

import config
from detector import Detector
from schemas import AnalysisStatus

# --- redaction ----------------------------------------------------------------
_REDACTIONS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD]"),
    (re.compile(r"\bACC-\d{3,}\b", re.I), "[ACCOUNT]"),
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "[IBAN]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"(?<!\w)\+?\d[\d ()-]{8,}\d\b"), "[PHONE]"),
]


def redact(text: str, limit: int = 500) -> str:
    """Strip personal/sensitive data. Uses Microsoft Presidio when enabled and installed."""
    text = (text or "")[:limit]
    if config.USE_PRESIDIO:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            found = AnalyzerEngine().analyze(text=text, language="en")
            text = AnonymizerEngine().anonymize(text=text, analyzer_results=found).text
        except Exception:
            pass
    for pat, tag in _REDACTIONS:
        text = pat.sub(tag, text)
    return text


def sender_ref(sender_id: str) -> str:
    return hashlib.sha256(sender_id.encode()).hexdigest()[:12]


# --- analysis -------------------------------------------------------------------
_FAMILY = {
    "ignore_instructions": "instruction_override", "disregard_above": "instruction_override",
    "forget_everything": "instruction_override", "new_instructions": "instruction_override",
    "reveal_system_prompt": "prompt_leak", "fake_role_marker": "role_hijack",
    "you_are_now": "role_hijack", "from_now_on": "role_hijack", "dan_jailbreak": "jailbreak",
    "special_mode": "jailbreak", "roleplay_unrestricted": "jailbreak", "pretend": "jailbreak",
    "hypothetical_no_rules": "jailbreak", "no_restrictions_ai": "jailbreak",
    "tool_call_syntax": "tool_hijack", "drain_funds": "tool_hijack", "approve_directive": "tool_hijack",
    "trust_manipulation": "privilege_escalation", "limit_change": "privilege_escalation",
    "safety_disable": "control_evasion", "coercion": "social_engineering", "urgency": "social_engineering",
    "addresses_assistant": "tool_hijack", "exfiltration": "data_exfiltration",
    "markdown_exfil": "data_exfiltration", "code_injection": "code_injection", "memo_url": "link_in_memo",
}


class HellTrack:
    def __init__(self, sink: Callable[[str, str, Optional[dict]], None],
                 maxsize: int = config.HELL_QUEUE_SIZE, delay: float = config.HELL_ANALYSIS_DELAY_S,
                 autostart: bool = True):
        self._sink = sink
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._delay = delay
        self._detector = Detector()        # pure-text second opinion (deep mode)
        self._seen: Counter = Counter()    # incidents per hashed sender (worker-local memory)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="hell-track", daemon=True)
        if autostart:
            self._thread.start()

    def submit(self, event: dict) -> bool:
        """Non-blocking. False means the queue is full (analysis UNAVAILABLE); the request
        stays blocked either way."""
        try:
            self._q.put_nowait(event)
            return True
        except queue.Full:
            return False

    def drain(self, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:
            time.sleep(0.005)
        return self._q.unfinished_tasks == 0

    def reset(self) -> None:
        self._seen.clear()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                ev = self._q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._sink(ev["event_id"], AnalysisStatus.ANALYZING.value, None)
                if self._delay:
                    time.sleep(self._delay)
                finding = self.analyze(ev)
                self._sink(ev["event_id"], AnalysisStatus.COMPLETE.value, finding)
            except Exception as exc:       # never let the worker die; report failure
                self._sink(ev.get("event_id", "?"), AnalysisStatus.FAILED.value, {"error": type(exc).__name__})
            finally:
                self._q.task_done()

    def analyze(self, ev: dict) -> dict:
        t0 = time.perf_counter()
        text_memo, text_msg = ev.get("memo", ""), ev.get("message", "")
        second = self._detector.inspect(message=text_msg, memo=text_memo, deep=True)
        if time.perf_counter() - t0 > config.HELL_TIME_BUDGET_S:
            raise TimeoutError("analysis budget exceeded")

        rules = sorted(set(ev.get("rules", [])) | set(second.rules))
        families = sorted({_FAMILY.get(r, "other") for r in rules}) or ["unclassified"]
        markers = sorted(set(ev.get("markers", [])) | set(second.markers))
        risk = max(ev.get("risk", 0.0), second.risk)

        ref = ev["sender_ref"]
        self._seen[ref] += 1
        repeat = self._seen[ref] >= 2
        severity = "CRITICAL" if risk >= config.THRESH_CRITICAL else "HIGH" if risk >= 0.75 else "MEDIUM"
        action = ("recommend suspending trusted status and manual review" if repeat or severity == "CRITICAL"
                  else "keep blocked; monitor sender")
        return {
            "severity": severity, "attack_families": families, "indicators": rules,
            "obfuscation": markers, "second_opinion_risk": second.risk,
            "repeat_offender": repeat, "recommended_action": action,
            "analysis_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
