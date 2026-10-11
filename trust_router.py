"""Adaptive Trust Routing (Phase 4): picks Superfast vs Standard and tracks reputation.

Trust only influences *which inspection path* a request takes. It never grants
permission (policy_engine) and never lowers a risk score.
"""
import threading
import time
from collections import deque
from dataclasses import dataclass

import config
from schemas import Action, BankRequest, Route


@dataclass(frozen=True)
class RouteDecision:
    lane: Route
    reason: str


class TrustRouter:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._requests: dict[str, deque] = {}
        self._blocks: dict[str, deque] = {}
        self._flagged: set[str] = set()      # set by Hell Track findings (can only make things stricter)

    # --- reputation / abuse signals -------------------------------------
    def note_request(self, sender_id: str) -> int:
        now = self._clock()
        with self._lock:
            dq = self._requests.setdefault(sender_id, deque())
            dq.append(now)
            while dq and dq[0] < now - 60:
                dq.popleft()
            return len(dq)

    def record_block(self, sender_id: str) -> None:
        with self._lock:
            self._blocks.setdefault(sender_id, deque()).append(self._clock())

    def flag_sender(self, sender_id: str) -> None:
        with self._lock:
            self._flagged.add(sender_id)

    def recent_blocks(self, sender_id: str) -> int:
        now = self._clock()
        with self._lock:
            dq = self._blocks.get(sender_id, deque())
            while dq and dq[0] < now - config.REPUTATION_WINDOW_S:
                dq.popleft()
            return len(dq)

    def reputation_penalty(self, sender_id: str) -> float:
        p = self.recent_blocks(sender_id) * config.REPUTATION_PENALTY_PER_BLOCK
        if sender_id in self._flagged:
            p += 0.10
        return min(p, config.REPUTATION_PENALTY_MAX)

    def is_demoted(self, sender_id: str) -> bool:
        return sender_id in self._flagged or self.recent_blocks(sender_id) >= config.DEMOTE_AFTER_BLOCKS

    # --- routing ---------------------------------------------------------
    def decide(self, req: BankRequest, identity, bank) -> RouteDecision:
        if identity is None:
            return RouteDecision(Route.STANDARD, "unauthenticated sender")
        rec = bank.trust_record(req.account_id, req.sender_id)
        if rec is None or not rec.verified:
            return RouteDecision(Route.STANDARD, "sender is not a verified trusted identity for this account")
        if self.is_demoted(req.sender_id):
            return RouteDecision(Route.STANDARD, "trust suspended after repeated blocked requests")
        if req.action == Action.TRANSFER and (req.amount is None or req.amount > config.FAST_TRANSFER_MAX):
            return RouteDecision(Route.STANDARD, "transfer above fast-lane amount")
        if len(req.memo) + len(req.message) > config.LONG_TEXT_FOR_FAST_LANE:
            return RouteDecision(Route.STANDARD, "free text too long for lightweight inspection")
        return RouteDecision(Route.SUPERFAST, "verified trusted identity, routine request")
