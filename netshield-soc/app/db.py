import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "netshield.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  event_type TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  proto TEXT,
  username TEXT,
  uri TEXT,
  query TEXT,
  bytes INTEGER DEFAULT 0,
  raw_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  risk INTEGER NOT NULL,
  mitre_id TEXT,
  mitre_name TEXT,
  description TEXT,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  FOREIGN KEY(event_id) REFERENCES events(id)
);
"""

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
