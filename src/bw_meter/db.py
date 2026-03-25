"""Database schema and helper functions for bw-meter."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

DEFAULT_DB_PATH = Path("/var/lib/bw-meter/bw-meter.db")


def resolve_db_path(path: Path | str | None = None) -> Path:
    """Return the effective database path.

    Resolution order:
    1. Explicit *path* argument
    2. ``BW_METER_DB`` environment variable
    3. ``DEFAULT_DB_PATH`` (``/var/lib/bw-meter/bw-meter.db``)
    """
    if path:
        return Path(path)
    env = os.environ.get("BW_METER_DB")
    if env:
        return Path(env)
    return DEFAULT_DB_PATH


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS process (
    id          INTEGER PRIMARY KEY,
    cmd         TEXT NOT NULL,
    name        TEXT NOT NULL,
    args        TEXT,
    parent_cmd  TEXT,
    parent_args TEXT,
    uid         INTEGER,
    pid         INTEGER,
    UNIQUE(cmd, args, uid)
);

CREATE TABLE IF NOT EXISTS host (
    id            INTEGER PRIMARY KEY,
    ip            TEXT NOT NULL,
    hostname      TEXT,
    last_observed INTEGER NOT NULL DEFAULT 0
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

_HOST_INDEXES_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS host_ip_hostname
    ON host(ip, hostname) WHERE hostname IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS host_ip_null
    ON host(ip) WHERE hostname IS NULL;
"""


def open_db(path: Path | str | None = None) -> sqlite3.Connection:
    """Open (or create) the SQLite database, ensuring the schema exists."""
    db_path = resolve_db_path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    # Rollback journal rather than WAL: a WAL database cannot be opened by a
    # reader without write access to its directory, and the database lives in
    # root-owned /var/lib/bw-meter while reports run as a regular user.
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_schema(conn)
    return conn


def open_db_readonly(path: Path | str | None = None) -> sqlite3.Connection:
    """Open an existing database read-only, without creating or migrating anything.

    Raises ``sqlite3.OperationalError`` if the file does not exist or cannot be read.
    """
    db_path = resolve_db_path(path).absolute()
    return sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they do not exist (idempotent)."""
    conn.executescript(_SCHEMA_SQL)
    # Migration: add remote_port to traffic for databases created before this column existed.
    traffic_cols = {row[1] for row in conn.execute("PRAGMA table_info(traffic)")}
    if "remote_port" not in traffic_cols:
        conn.execute("ALTER TABLE traffic ADD COLUMN remote_port INTEGER")
        conn.commit()
    # Migration: add pid to process for databases created before this column existed.
    process_cols = {row[1] for row in conn.execute("PRAGMA table_info(process)")}
    if "pid" not in process_cols:
        conn.execute("ALTER TABLE process ADD COLUMN pid INTEGER")
        conn.commit()
    # Migration: update host table to support multiple hostnames per IP with last_observed.
    _migrate_host(conn)


def _host_has_old_unique(conn: sqlite3.Connection) -> bool:
    """True if the host table still carries the old table-level UNIQUE(ip) constraint."""
    return any(
        row[0].startswith("sqlite_autoindex_host")
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='host'")
    )


def _migrate_host(conn: sqlite3.Connection) -> None:
    """Migrate host table to (ip, hostname) partial-unique-index schema with last_observed."""
    # Add last_observed column if missing (old databases lack it).
    host_cols = {row[1] for row in conn.execute("PRAGMA table_info(host)")}
    if "last_observed" not in host_cols:
        conn.execute("ALTER TABLE host ADD COLUMN last_observed INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    # Check whether the partial unique indexes already exist.
    host_indexes = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='host'")
    }
    if "host_ip_hostname" in host_indexes:
        return  # already on new schema
    # Determine whether the old UNIQUE(ip) table-level constraint is present.
    if _host_has_old_unique(conn):
        # Recreate the table to drop the old UNIQUE(ip) constraint, then add
        # the two partial unique indexes.  Foreign-key checks must be disabled
        # while the table is temporarily absent (a no-op inside a transaction,
        # hence before BEGIN).  The recreation is one transaction so that a
        # crash or a concurrent open_db() never sees the table missing.
        conn.execute("PRAGMA foreign_keys=OFF")
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not _host_has_old_unique(conn):
                conn.rollback()  # another process migrated while we waited for the lock
            else:
                conn.execute(
                    """CREATE TABLE host_new (
                        id            INTEGER PRIMARY KEY,
                        ip            TEXT NOT NULL,
                        hostname      TEXT,
                        last_observed INTEGER NOT NULL DEFAULT 0
                    )"""
                )
                conn.execute(
                    "INSERT INTO host_new(id, ip, hostname, last_observed)"
                    " SELECT id, ip, hostname, COALESCE(last_observed, 0) FROM host"
                )
                conn.execute("DROP TABLE host")
                conn.execute("ALTER TABLE host_new RENAME TO host")
                conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys=ON")
    # Create partial unique indexes (works for both fresh installs and migrated tables).
    conn.executescript(_HOST_INDEXES_SQL)


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
    pid: int | None = None,
) -> int:
    """Insert or update a process row, returning its id."""
    conn.execute(
        """
        INSERT INTO process(cmd, name, args, parent_cmd, parent_args, uid, pid)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cmd, args, uid) DO UPDATE SET
            name        = excluded.name,
            parent_cmd  = excluded.parent_cmd,
            parent_args = excluded.parent_args,
            pid         = excluded.pid
        """,
        (cmd, name, args, parent_cmd, parent_args, uid, pid),
    )
    row = conn.execute(
        "SELECT id FROM process WHERE cmd=? AND args IS ? AND uid IS ?",
        (cmd, args, uid),
    ).fetchone()
    return int(row[0])


def upsert_host(
    conn: sqlite3.Connection,
    ip: str,
    hostname: str | None = None,
    last_observed: int | None = None,
) -> int:
    """Insert or update a host row, returning its id.

    The unique key is (ip, hostname): each distinct hostname observed for an IP
    gets its own row.  For a NULL hostname, at most one row per IP is kept.
    last_observed is updated to the maximum of the stored and new values.
    """
    ts = last_observed if last_observed is not None else int(time.time())
    if hostname is not None:
        conn.execute(
            """
            INSERT INTO host(ip, hostname, last_observed) VALUES (?, ?, ?)
            ON CONFLICT(ip, hostname) WHERE hostname IS NOT NULL
            DO UPDATE SET last_observed = MAX(host.last_observed, excluded.last_observed)
            """,
            (ip, hostname, ts),
        )
        row = conn.execute("SELECT id FROM host WHERE ip=? AND hostname=?", (ip, hostname)).fetchone()
    else:
        conn.execute(
            """
            INSERT INTO host(ip, hostname, last_observed) VALUES (?, NULL, ?)
            ON CONFLICT(ip) WHERE hostname IS NULL
            DO UPDATE SET last_observed = MAX(host.last_observed, excluded.last_observed)
            """,
            (ip, ts),
        )
        row = conn.execute("SELECT id FROM host WHERE ip=? AND hostname IS NULL", (ip,)).fetchone()
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
