"""Authorization & transaction policy (Phase 6).

This module is deterministic code only. A risk score or trust tier is never an input
that can *grant* permission here. The engine also mints single-purpose approval
tickets: the banking simulator refuses to move money without a valid ticket, so no
alternate code path (retry, queued job, other endpoint) can execute a transfer that
the policy gate did not approve.
"""
import hashlib
import hmac
from dataclasses import dataclass
from decimal import Decimal

import config
from schemas import Action, BankRequest


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str


def _deny(code: str, reason: str) -> PolicyDecision:
    return PolicyDecision(False, code, reason)


def authorize(req: BankRequest, bank) -> PolicyDecision:
    """Check identity-based permissions, recipient validity, limits and funds."""
    account = bank.account(req.account_id)
    if account is None:
        return _deny("NO_ACCOUNT", "Account not found.")
    if account.frozen:
        return _deny("ACCOUNT_FROZEN", "Account is frozen.")

    rec = bank.trust_record(req.account_id, req.sender_id)
    if rec is None:
        return _deny("NOT_AUTHORIZED", "Sender has no permissions on this account.")
    if req.action.value not in rec.permissions:
        return _deny("ACTION_NOT_PERMITTED", "Sender is not permitted to perform this action.")

    if req.action == Action.TRANSFER:
        assert req.amount is not None and req.recipient_id is not None  # guaranteed by firewall
        recipient = bank.account(req.recipient_id)
        if recipient is None or recipient.frozen:
            return _deny("BAD_RECIPIENT", "Recipient is unknown or unavailable.")
        if req.recipient_id == req.account_id:
            return _deny("SELF_TRANSFER", "Source and destination accounts are identical.")
        if req.amount > rec.txn_limit:
            return _deny("TXN_LIMIT", "Amount exceeds the per-transaction limit for this sender.")
        if bank.spent_today(req.account_id) + req.amount > config.DAILY_LIMIT:
            return _deny("DAILY_LIMIT", "Daily transfer limit would be exceeded.")
        if account.balance < req.amount:
            return _deny("INSUFFICIENT_FUNDS", "Insufficient funds.")
    return PolicyDecision(True, "OK", "Authorized.")


# --- approval tickets --------------------------------------------------------
@dataclass(frozen=True)
class ApprovalTicket:
    event_id: str
    mac: str


def _mac(event_id: str, account_id: str, recipient_id: str, amount: Decimal) -> str:
    msg = f"{event_id}|{account_id}|{recipient_id}|{amount:.2f}".encode()
    return hmac.new(config.TICKET_SECRET, msg, hashlib.sha256).hexdigest()


def issue_ticket(event_id: str, account_id: str, recipient_id: str, amount: Decimal) -> ApprovalTicket:
    return ApprovalTicket(event_id, _mac(event_id, account_id, recipient_id, amount))


def verify_ticket(ticket, account_id: str, recipient_id: str, amount: Decimal) -> bool:
    if not isinstance(ticket, ApprovalTicket):
        return False
    return hmac.compare_digest(ticket.mac, _mac(ticket.event_id, account_id, recipient_id, amount))
