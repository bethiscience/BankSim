"""Central configuration: thresholds, limits and feature flags.

All numbers below are *starting points*, not calibrated values. Phase 8
(adversarial testing) is where they should be tuned against a labelled dataset.
"""
import os
import secrets
import tempfile
from decimal import Decimal

# --- storage -----------------------------------------------------------------
DB_PATH = os.environ.get("BANKSIM_DB", os.path.join(tempfile.gettempdir(), "banksim_audit.db"))

# --- input limits ------------------------------------------------------------
MAX_RAW_BYTES = 8192
MAX_MEMO_LEN = 500
MAX_MESSAGE_LEN = 1000
LONG_TEXT_FOR_FAST_LANE = 300   # more free text than this -> Standard lane

# --- risk thresholds (0..1) --------------------------------------------------
THRESH_FAST_ESCALATE = 0.30     # Superfast Lane request at/above this is re-run on Standard
THRESH_SUSPICIOUS = 0.60        # at/above -> BLOCK + Hell Track
THRESH_CRITICAL = 0.90          # "critical" label on dashboard / Hell Track severity

# --- reputation / abuse ------------------------------------------------------
RATE_LIMIT_PER_MIN = 30
REPUTATION_WINDOW_S = 600
REPUTATION_PENALTY_PER_BLOCK = 0.12
REPUTATION_PENALTY_MAX = 0.36
DEMOTE_AFTER_BLOCKS = 3         # recent blocks before a sender loses Superfast eligibility

# --- banking policy ----------------------------------------------------------
OWNER_TXN_LIMIT = Decimal("5000.00")
DAILY_LIMIT = Decimal("10000.00")
FAST_TRANSFER_MAX = Decimal("1000.00")   # bigger transfers never use the Superfast Lane

# --- Hell Track --------------------------------------------------------------
HELL_QUEUE_SIZE = 100
HELL_ANALYSIS_DELAY_S = float(os.environ.get("BANKSIM_HELL_DELAY", "0"))  # demo: make ANALYZING visible
HELL_TIME_BUDGET_S = 2.0

# --- optional open-source components (off by default) -----------------------
USE_HF_CLASSIFIER = os.environ.get("BANKSIM_USE_HF", "0") == "1"
HF_MODEL = os.environ.get("BANKSIM_HF_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
USE_PRESIDIO = os.environ.get("BANKSIM_USE_PRESIDIO", "0") == "1"

# Per-process secret used to sign approval tickets (see policy_engine.py).
TICKET_SECRET = secrets.token_bytes(32)
