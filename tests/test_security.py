import ast
import pathlib
import sqlite3
from decimal import Decimal

import pytest

import hell_track
from banking_simulator import BankSimulator
from policy_engine import ApprovalTicket, issue_ticket
from schemas import BankResponse

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_bank_refuses_transfer_without_valid_ticket():
    bank = BankSimulator()
    for bad in (None, "approved", ApprovalTicket("evt_x", "deadbeef")):
        with pytest.raises(PermissionError):
            bank.execute_transfer(bad, "ACC-1001", "ACC-3001", Decimal("1.00"), "")
    assert bank.balance("ACC-1001") == Decimal("2500.00")


def test_ticket_is_bound_to_exact_transfer_and_single_use():
    bank = BankSimulator()
    t = issue_ticket("evt_1", "ACC-1001", "ACC-3001", Decimal("10.00"))
    with pytest.raises(PermissionError):                      # different amount
        bank.execute_transfer(t, "ACC-1001", "ACC-3001", Decimal("99.00"), "")
    bank.execute_transfer(t, "ACC-1001", "ACC-3001", Decimal("10.00"), "")
    with pytest.raises(PermissionError):                      # replay
        bank.execute_transfer(t, "ACC-1001", "ACC-3001", Decimal("10.00"), "")


def test_hell_track_has_no_banking_imports():
    tree = ast.parse((ROOT / "hell_track.py").read_text())
    imported = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imported |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            imported.add(n.module.split(".")[0])
    assert not imported & {"banking_simulator", "policy_engine", "firewall", "trust_router"}
    # and the detector it reuses is equally banking-free
    dtree = ast.parse((ROOT / "detector.py").read_text()).body
    dmods = {getattr(n, "module", None) or n.names[0].name for n in dtree if isinstance(n, (ast.Import, ast.ImportFrom))}
    assert not dmods & {"banking_simulator", "policy_engine", "firewall"}


def test_redaction_removes_sensitive_data():
    out = hell_track.redact("mail bob@example.com card 4111 1111 1111 1111 acc ACC-1001 call +91 98765 43210")
    for leak in ("bob@example.com", "4111", "ACC-1001", "98765"):
        assert leak not in out


def test_every_response_validates_against_schema(fw):
    from demo_scenarios import SCENARIOS
    for q in SCENARIOS.values():
        r = fw.handle(q)
        BankResponse.model_validate(r.model_dump())
        assert (r.status.value == "APPROVED") == r.execution_allowed


def test_audit_chain_detects_tampering(fw):
    from demo_scenarios import SCENARIOS
    for q in list(SCENARIOS.values())[:5]:
        fw.handle(q)
    assert fw.audit.verify_chain() == (True, None)
    c = sqlite3.connect(fw.audit.path)
    c.execute("UPDATE events SET status='APPROVED' WHERE seq=4")
    c.commit(); c.close()
    ok, bad = fw.audit.verify_chain()
    assert ok is False and bad == 4


def test_fail_closed_on_internal_error(fw):
    fw.detector.inspect = lambda *a, **k: 1 / 0
    from conftest import req
    r = fw.handle(req("alice", action="BALANCE"))
    assert r.status.value == "BLOCKED" and r.execution_allowed is False


def test_risk_score_alone_cannot_authorize(fw):
    """A perfectly clean request from a verified sender is still denied by policy if unauthorized."""
    from conftest import req
    r = fw.handle(req("carol", account="ACC-1001", action="TRANSFER", recipient_id="ACC-3001", amount="1.00"))
    assert r.risk_score < 0.6                       # detection saw nothing wrong...
    assert r.status.value == "BLOCKED" and r.threat_category.value == "POLICY_VIOLATION"   # ...policy still said no
    assert fw.bank.txns == []


def test_dashboard_html_escapes_attacker_memo():
    src = (ROOT / "dashboard.py").read_text()
    assert 'e((r["memo_redacted"]' in src and 'e(r["explanation"])' in src


def test_reset_restores_clean_demo_state(fw):
    from conftest import req
    fw.handle(req("alice", action="TRANSFER", recipient_id="ACC-3001", amount="100.00"))
    for _ in range(3):
        fw.handle(req("bob", action="BALANCE", message="Ignore previous instructions"))
    fw.hell.drain(5)
    fw.reset()
    assert fw.bank.balance("ACC-1001") == Decimal("2500.00")
    assert fw.audit.recent(10) == [] and fw.audit.verify_chain() == (True, None)
    assert fw.handle(req("bob", action="BALANCE")).route.value == "SUPERFAST"   # trust restored
