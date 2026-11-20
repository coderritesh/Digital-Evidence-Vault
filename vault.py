"""Stage 2 - Evidence Vault.

Rules this module follows:
1. The uploaded bytes are hashed BEFORE anything else touches them.
2. The original file is stored byte-for-byte, never opened with an image library.
3. The stored file is marked read-only and named after its own SHA-256 hash.
4. Integrity can be re-checked at any time by re-hashing the stored file.
"""
import hashlib
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

VAULT_DIR = Path("evidence_vault")
DB_PATH = Path("forensics.db")
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".webp"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            size_bytes INTEGER NOT NULL,
            ingested_at TEXT NOT NULL
        )"""
    )
    return conn


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest(data: bytes, original_name: str):
    """Store evidence. Returns (record_dict, is_new)."""
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"File type {ext or '(none)'} is not allowed.")

    digest = sha256_bytes(data)  # hash first, before any other processing
    conn = get_db()
    row = conn.execute("SELECT * FROM evidence WHERE sha256 = ?", (digest,)).fetchone()
    if row:
        conn.close()
        return dict(row), False  # same file already in the vault

    VAULT_DIR.mkdir(exist_ok=True)
    stored = VAULT_DIR / f"{digest}{ext}"
    with open(stored, "xb") as f:  # "x" refuses to overwrite an existing file
        f.write(data)
    os.chmod(stored, stat.S_IREAD)  # read-only

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    safe_name = Path(original_name).name
    cur = conn.execute(
        "INSERT INTO evidence (original_name, stored_path, sha256, size_bytes, ingested_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (safe_name, str(stored), digest, len(data), now),
    )
    conn.commit()
    rec = dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (cur.lastrowid,)).fetchone())
    conn.close()
    return rec, True


def list_evidence():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM evidence ORDER BY id DESC")]
    conn.close()
    return rows


def verify(evidence_id: int):
    """Re-hash the stored file. Returns (is_intact, current_hash, recorded_hash)."""
    conn = get_db()
    row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    conn.close()
    if row is None:
        raise KeyError("Evidence not found")
    if not Path(row["stored_path"]).exists():
        return False, "FILE MISSING", row["sha256"]
    current = sha256_file(row["stored_path"])
    return current == row["sha256"], current, row["sha256"]
