"""Mock banking tools (Phase 2). No real accounts, no real money.

The ONLY method that mutates balances is `execute_transfer`, and it requires a valid,
single-use approval ticket issued by policy_engine.
"""
import hashlib
import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional

import config
from policy_engine import verify_ticket

ALL_ACTIONS = frozenset({"BALANCE", "TRANSFER", "HISTORY"})


@dataclass
class Identity:
    sender_id: str
    token_hash: str
    own_account: str
    verified: bool            # explicitly verified identity (KYC / step-up)


@dataclass
class Account:
    account_id: str
    owner: str
    balance: Decimal
    frozen: bool = False


@dataclass
class TrustRecord:
    verified: bool
    permissions: frozenset
    txn_limit: Decimal


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class BankSimulator:
    def __init__(self):
        self._lock = threading.RLock()
        self._used_tickets: set[str] = set()
        self.txns: list[dict] = []
        self.identities = {
            "alice":   Identity("alice",   _h("tok_alice"),   "ACC-1001", True),
            "bob":     Identity("bob",     _h("tok_bob"),     "ACC-2001", True),
            "carol":   Identity("carol",   _h("tok_carol"),   "ACC-3001", True),
            "dave":    Identity("dave",    _h("tok_dave"),    "ACC-4001", False),   # unverified
            "mallory": Identity("mallory", _h("tok_mallory"), "ACC-6001", False),   # unknown / hostile
        }
        self.accounts = {
            "ACC-1001": Account("ACC-1001", "alice", Decimal("2500.00")),
            "ACC-2001": Account("ACC-2001", "bob", Decimal("800.00")),
            "ACC-3001": Account("ACC-3001", "carol", Decimal("12000.00")),
            "ACC-4001": Account("ACC-4001", "dave", Decimal("300.00")),
            "ACC-6001": Account("ACC-6001", "mallory", Decimal("50.00")),
            "ACC-7001": Account("ACC-7001", "frozen_user", Decimal("100.00"), frozen=True),
        }
        # Explicit, verified delegates ("trusted contacts") of an account.
        self.trust: dict[str, dict[str, TrustRecord]] = {
            "ACC-1001": {"bob": TrustRecord(True, frozenset({"BALANCE", "TRANSFER"}), Decimal("500.00"))},
        }

    # --- identity -----------------------------------------------------------
    def authenticate(self, sender_id: str, token: str) -> Optional[Identity]:
        ident = self.identities.get(sender_id)
        # compare against a dummy hash for unknown users so timing is uniform
        expected = ident.token_hash if ident else _h("no-such-user")
        ok = hmac.compare_digest(expected, _h(token))
        return ident if (ident and ok) else None

    def trust_record(self, account_id: str, sender_id: str) -> Optional[TrustRecord]:
        acct = self.accounts.get(account_id)
        ident = self.identities.get(sender_id)
        if acct is None or ident is None:
            return None
        if acct.owner == sender_id:
            return TrustRecord(ident.verified, ALL_ACTIONS, config.OWNER_TXN_LIMIT)
        return self.trust.get(account_id, {}).get(sender_id)

    # --- reads --------------------------------------------------------------
    def account(self, account_id: str) -> Optional[Account]:
        with self._lock:
            a = self.accounts.get(account_id)
            return Account(a.account_id, a.owner, a.balance, a.frozen) if a else None

    def balance(self, account_id: str) -> Decimal:
        with self._lock:
            return self.accounts[account_id].balance

    def history(self, account_id: str, n: int = 5) -> list[dict]:
        with self._lock:
            rows = [t for t in self.txns if account_id in (t["from"], t["to"])]
            return [{k: (str(v) if isinstance(v, Decimal) else v) for k, v in t.items() if k != "memo"}
                    for t in rows[-n:]]

    def spent_today(self, account_id: str) -> Decimal:
        cutoff = time.time() - 86400
        with self._lock:
            return sum((t["amount"] for t in self.txns if t["from"] == account_id and t["ts"] >= cutoff),
                       Decimal("0"))

    # --- the only mutating operation ----------------------------------------
    def execute_transfer(self, ticket, account_id: str, recipient_id: str,
                         amount: Decimal, memo: str) -> dict:
        with self._lock:
            if not verify_ticket(ticket, account_id, recipient_id, amount):
                raise PermissionError("invalid approval ticket")
            if ticket.event_id in self._used_tickets:
                raise PermissionError("approval ticket already used")
            src, dst = self.accounts[account_id], self.accounts[recipient_id]
            if src.frozen or dst.frozen or src.balance < amount:
                raise ValueError("transfer rejected by banking core")
            self._used_tickets.add(ticket.event_id)
            src.balance -= amount
            dst.balance += amount
            tx = {"tx_id": "tx_" + uuid.uuid4().hex[:8], "from": account_id, "to": recipient_id,
                  "amount": amount, "ts": time.time(), "memo": memo}   # memo is stored as inert data
            self.txns.append(tx)
            return {"tx_id": tx["tx_id"], "new_balance": str(src.balance)}
