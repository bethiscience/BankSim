"""Request / response contract (Phase 1). Every response is validated against this."""
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

import config

ID_PATTERN = r"^[A-Za-z0-9_\-]{1,64}$"


class Action(str, Enum):
    BALANCE = "BALANCE"
    TRANSFER = "TRANSFER"
    HISTORY = "HISTORY"


class Status(str, Enum):
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"


class ThreatCategory(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    MALICIOUS_MEMO = "MALICIOUS_MEMO"
    AMBIGUOUS_REQUEST = "AMBIGUOUS_REQUEST"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ABUSE_PATTERN = "ABUSE_PATTERN"


class Route(str, Enum):
    SUPERFAST = "SUPERFAST"
    STANDARD = "STANDARD"
    HELL_TRACK = "HELL_TRACK"


class AnalysisStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    ANALYZING = "ANALYZING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class BankRequest(BaseModel):
    """Structured request produced by the banking assistant.

    `message` is the user's raw utterance; `memo` is the transaction memo.
    Those two are the only free-text fields, everything else is pattern-constrained.
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    sender_id: str = Field(pattern=ID_PATTERN)
    auth_token: str = Field(min_length=1, max_length=128)
    account_id: str = Field(pattern=ID_PATTERN)
    action: Action
    recipient_id: Optional[str] = Field(default=None, pattern=ID_PATTERN)
    amount: Optional[Decimal] = Field(default=None, gt=0, le=Decimal("1000000"),
                                      max_digits=12, decimal_places=2)
    memo: str = Field(default="", max_length=config.MAX_MEMO_LEN)
    message: str = Field(default="", max_length=config.MAX_MESSAGE_LEN)
    idempotency_key: Optional[str] = Field(default=None, pattern=ID_PATTERN)


class BankResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    status: Status
    risk_score: float = Field(ge=0.0, le=1.0)
    threat_category: ThreatCategory
    route: Route
    explanation: str
    execution_allowed: bool
    analysis_status: AnalysisStatus
    latency_ms: float = Field(ge=0.0)
    result: Optional[dict[str, Any]] = None

    @model_validator(mode="after")
    def _invariants(self):
        # Hard invariants of the security contract.
        if self.status == Status.BLOCKED and self.execution_allowed:
            raise ValueError("BLOCKED responses can never allow execution")
        if self.status == Status.APPROVED and not self.execution_allowed:
            raise ValueError("APPROVED responses must allow execution")
        if self.status == Status.BLOCKED and self.result is not None:
            raise ValueError("BLOCKED responses cannot carry a result")
        return self
