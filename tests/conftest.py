import pytest

from audit import AuditLog
from firewall import Firewall


@pytest.fixture
def fw(tmp_path):
    f = Firewall(audit=AuditLog(str(tmp_path / "audit.db")))
    yield f
    f.hell.stop()


def req(who="alice", account=None, **kw):
    acct = account or {"alice": "ACC-1001", "bob": "ACC-1001", "carol": "ACC-3001",
                       "dave": "ACC-4001", "mallory": "ACC-6001"}[who]
    return {"sender_id": who, "auth_token": f"tok_{who}", "account_id": acct, **kw}
