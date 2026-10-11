"""Tamper-evident audit log + dashboard queries (SQLite, WAL mode).

Each event row stores the SHA-256 of (previous hash + its own fields), forming a hash
chain: editing or deleting a middle row breaks verification. Analysis results live in a
separate table so that late Hell Track findings never rewrite the decision record.
Limitation: truncating the *tail* of the chain is only detectable if the latest hash is
anchored somewhere external.
"""
import hashlib
import json
import sqlite3
import statistics
import threading
import time
import uuid
from typing import Optional

import config


def new_event_id() -> str:
    return "evt_" + uuid.uuid4().hex[:10]


_COLS = ("event_id", "ts", "sender_id", "account_id", "action", "route", "status", "risk",
         "category", "explanation", "execution_allowed", "latency_ms", "rules", "markers",
         "memo_redacted", "clarification")


def _digest(prev: str, row: dict) -> str:
    payload = json.dumps([row[c] for c in _COLS], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Optional[str] = None):
        self.path = path or config.DB_PATH
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, ts REAL,
              sender_id TEXT, account_id TEXT, action TEXT, route TEXT, status TEXT, risk REAL,
              category TEXT, explanation TEXT, execution_allowed INTEGER, latency_ms REAL,
              rules TEXT, markers TEXT, memo_redacted TEXT, clarification INTEGER,
              prev_hash TEXT, hash TEXT);
            CREATE TABLE IF NOT EXISTS analysis(
              event_id TEXT PRIMARY KEY, status TEXT, updated REAL, finding TEXT);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    # --- writes -----------------------------------------------------------
    def append(self, rec: dict, analysis_status: str) -> None:
        row = {c: rec[c] for c in _COLS}
        row["rules"] = json.dumps(row["rules"])
        row["markers"] = json.dumps(row["markers"])
        row["execution_allowed"] = int(row["execution_allowed"])
        row["clarification"] = int(row["clarification"])
        with self._lock:
            c = self._conn()
            try:
                c.execute("BEGIN IMMEDIATE")
                last = c.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                prev = last["hash"] if last else "GENESIS"
                h = _digest(prev, row)
                c.execute(f"INSERT INTO events({','.join(_COLS)},prev_hash,hash) "
                          f"VALUES({','.join('?' * len(_COLS))},?,?)",
                          [row[k] for k in _COLS] + [prev, h])
                c.execute("INSERT INTO analysis(event_id,status,updated,finding) VALUES(?,?,?,NULL)",
                          (row["event_id"], analysis_status, time.time()))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def clear(self) -> None:
        """Wipe the log (demo reset). The hash chain restarts from GENESIS."""
        with self._lock:
            c = self._conn()
            try:
                c.execute("DELETE FROM events")
                c.execute("DELETE FROM analysis")
            finally:
                c.close()

    def set_analysis(self, event_id: str, status: str, finding: Optional[dict] = None) -> None:
        c = self._conn()
        try:
            c.execute("UPDATE analysis SET status=?, updated=?, finding=? WHERE event_id=?",
                      (status, time.time(), json.dumps(finding) if finding else None, event_id))
        finally:
            c.close()

    # --- reads ------------------------------------------------------------
    def recent(self, limit: int = 100, route=None, category=None, status=None, since: float = 0.0) -> list:
        q = ("SELECT e.*, a.status AS analysis_status, a.finding AS finding FROM events e "
             "LEFT JOIN analysis a USING(event_id) WHERE e.ts >= ?")
        args: list = [since]
        for col, val in (("route", route), ("category", category), ("status", status)):
            if val:
                q += f" AND e.{col} = ?"
                args.append(val)
        q += " ORDER BY e.seq DESC LIMIT ?"
        args.append(limit)
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(q, args).fetchall()]
        finally:
            c.close()

    def stats(self, since: float = 0.0) -> dict:
        c = self._conn()
        try:
            rows = c.execute("SELECT route, status, category, latency_ms FROM events WHERE ts >= ?",
                             (since,)).fetchall()
            queue = c.execute("SELECT COUNT(*) FROM analysis WHERE status IN ('PENDING','ANALYZING')").fetchone()[0]
        finally:
            c.close()
        lat = [r["latency_ms"] for r in rows]

        def pct(vals, p):
            if not vals:
                return 0.0
            vals = sorted(vals)
            return vals[min(len(vals) - 1, int(round(p * (len(vals) - 1))))]

        by_route: dict = {}
        for r in rows:
            by_route.setdefault(r["route"], []).append(r["latency_ms"])
        cats: dict = {}
        for r in rows:
            if r["status"] == "BLOCKED":
                cats[r["category"]] = cats.get(r["category"], 0) + 1
        return {
            "total": len(rows),
            "blocked": sum(r["status"] == "BLOCKED" for r in rows),
            "approved": sum(r["status"] == "APPROVED" for r in rows),
            "median_ms": statistics.median(lat) if lat else 0.0,
            "p95_ms": pct(lat, 0.95),
            "hell_queue": queue,
            "by_route": {k: {"n": len(v), "median_ms": statistics.median(v), "p95_ms": pct(v, 0.95)}
                         for k, v in by_route.items()},
            "blocked_by_category": cats,
        }

    def verify_chain(self) -> tuple:
        """Return (ok, first_bad_seq)."""
        c = self._conn()
        try:
            prev = "GENESIS"
            for r in c.execute("SELECT * FROM events ORDER BY seq"):
                row = {k: r[k] for k in _COLS}
                if r["prev_hash"] != prev or _digest(prev, row) != r["hash"]:
                    return False, r["seq"]
                prev = r["hash"]
            return True, None
        finally:
            c.close()
