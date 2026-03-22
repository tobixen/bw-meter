"""Database schema and helper functions for bw-meter."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".local/share/bw-meter/bw-meter.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS process (
    id          INTEGER PRIMARY KEY,
    cmd         TEXT NOT NULL,
    name        TEXT NOT NULL,
    args        TEXT,
    parent_cmd  TEXT,
    parent_args TEXT,
    uid         INTEGER,
    UNIQUE(cmd, args, uid)
);

CREATE TABLE IF NOT EXISTS host (
    id          INTEGER PRIMARY KEY,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS traffic (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    bucket_secs INTEGER NOT NULL,
    interface   TEXT NOT NULL,
    process_id  INTEGER REFERENCES process(id),
    host_id     INTEGER REFERENCES host(id),
    direction   TEXT NOT NULL CHECK(direction IN ('in', 'out')),
    protocol    TEXT,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    remote_port INTEGER
);

CREATE TABLE IF NOT EXISTS capture_file (
    id           INTEGER PRIMARY KEY,
    path         TEXT NOT NULL UNIQUE,
    processed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS traffic_ts        ON traffic(ts);
CREATE INDEX IF NOT EXISTS traffic_process   ON traffic(process_id);
CREATE INDEX IF NOT EXISTS traffic_interface ON traffic(interface, ts);
"""


def open_db(path: Path | str | None = None) -> sqlite3.Connection:
    """Open (or create) the SQLite database, ensuring the schema exists."""
    db_path = Path(path) if path else DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they do not exist (idempotent)."""
    conn.executescript(_SCHEMA_SQL)
    # Migration: add remote_port to traffic for databases created before this column existed.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(traffic)")}
    if "remote_port" not in cols:
        conn.execute("ALTER TABLE traffic ADD COLUMN remote_port INTEGER")
        conn.commit()


def get_processed_files(conn: sqlite3.Connection) -> set[str]:
    """Return the set of pcapng file paths already processed."""
    return {row[0] for row in conn.execute("SELECT path FROM capture_file")}


def mark_file_processed(conn: sqlite3.Connection, path: str) -> None:
    """Record *path* as processed and commit."""
    conn.execute(
        "INSERT OR REPLACE INTO capture_file(path, processed_at) VALUES (?, ?)",
        (path, int(time.time())),
    )
    conn.commit()


def upsert_process(
    conn: sqlite3.Connection,
    *,
    cmd: str,
    name: str,
    args: str | None,
    parent_cmd: str | None,
    parent_args: str | None,
    uid: int | None,
) -> int:
    """Insert or update a process row, returning its id."""
    conn.execute(
        """
        INSERT INTO process(cmd, name, args, parent_cmd, parent_args, uid)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(cmd, args, uid) DO UPDATE SET
            name        = excluded.name,
            parent_cmd  = excluded.parent_cmd,
            parent_args = excluded.parent_args
        """,
        (cmd, name, args, parent_cmd, parent_args, uid),
    )
    row = conn.execute(
        "SELECT id FROM process WHERE cmd=? AND args IS ? AND uid IS ?",
        (cmd, args, uid),
    ).fetchone()
    return int(row[0])


def upsert_host(conn: sqlite3.Connection, ip: str, hostname: str | None = None) -> int:
    """Insert or update a host row, returning its id.

    An existing hostname is preserved if *hostname* is None.
    """
    conn.execute(
        """
        INSERT INTO host(ip, hostname) VALUES (?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, host.hostname)
        """,
        (ip, hostname),
    )
    row = conn.execute("SELECT id FROM host WHERE ip=?", (ip,)).fetchone()
    return int(row[0])


def insert_traffic_batch(conn: sqlite3.Connection, rows: list[dict]) -> None:
    """Bulk-insert traffic rows (does not commit)."""
    if not rows:
        return
    normalized = [{**r, "remote_port": r.get("remote_port")} for r in rows]
    conn.executemany(
        """
        INSERT INTO traffic(ts, bucket_secs, interface, process_id, host_id,
                            direction, protocol, bytes, packets, remote_port)
        VALUES (:ts, :bucket_secs, :interface, :process_id, :host_id,
                :direction, :protocol, :bytes, :packets, :remote_port)
        """,
        normalized,
    )
