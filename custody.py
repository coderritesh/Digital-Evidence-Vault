"""Stage 4 - Chain-of-Custody Ledger.

Every action on evidence is written as a log entry. Each entry stores the hash of
the previous entry and its own hash, so changing or deleting an old entry breaks
the chain and is detected by verify_chain().
"""
import hashlib
import json
from datetime import datetime, timezone

import vault

GENESIS = "0" * 64


def _db():
    conn = vault.get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS custody_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )"""
    )
    conn.commit()
    return conn


def _compute_hash(evidence_id, action, actor, details, timestamp, prev_hash):
    payload = json.dumps(
        {
            "evidence_id": evidence_id,
            "action": action,
            "actor": actor,
            "details": details,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(evidence_id, action, actor, details=""):
    """Append one entry to the chain and return its hash."""
    conn = _db()
    conn.isolation_level = None  # manual transaction so two writers cannot fork the chain
    conn.execute("BEGIN IMMEDIATE")
    try:
        last = conn.execute(
            "SELECT entry_hash FROM custody_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev = last["entry_hash"] if last else GENESIS
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        h = _compute_hash(evidence_id, action, actor, details, ts, prev)
        conn.execute(
            "INSERT INTO custody_log (evidence_id, action, actor, details, timestamp,"
            " prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, action, actor, details, ts, prev, h),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return h


def get_log(evidence_id=None):
    conn = _db()
    if evidence_id is None:
        rows = conn.execute("SELECT * FROM custody_log ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM custody_log WHERE evidence_id = ? ORDER BY id DESC",
            (evidence_id,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def verify_chain():
    """Re-check every link. Returns (ok, message, entry_count, head_hash)."""
    conn = _db()
    rows = conn.execute("SELECT * FROM custody_log ORDER BY id ASC").fetchall()
    conn.close()
    expected_prev = GENESIS
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return False, f"Chain broken at entry #{r['id']}: link to the previous entry does not match (an entry may have been deleted or reordered).", len(rows), expected_prev
        recomputed = _compute_hash(
            r["evidence_id"], r["action"], r["actor"], r["details"], r["timestamp"], r["prev_hash"]
        )
        if recomputed != r["entry_hash"]:
            return False, f"Entry #{r['id']} was modified after it was written.", len(rows), expected_prev
        expected_prev = r["entry_hash"]
    return True, "Chain intact: every entry matches its recorded hash.", len(rows), expected_prev
