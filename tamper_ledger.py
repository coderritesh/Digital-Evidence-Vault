"""TEST ONLY. Changes the 'actor' of one ledger entry to prove tampering is detected.

Usage:   python tamper_ledger.py ENTRY_ID "New Name"
Restore: run it again with the original name.
"""
import sqlite3
import sys

entry_id, new_actor = int(sys.argv[1]), sys.argv[2]
conn = sqlite3.connect("forensics.db")
conn.execute("UPDATE custody_log SET actor = ? WHERE id = ?", (new_actor, entry_id))
conn.commit()
print(f"Entry {entry_id} actor set to: {new_actor}")
