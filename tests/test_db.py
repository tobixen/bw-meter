"""Tests for bw_meter.db — schema and upsert helpers."""

import sqlite3

import pytest

from bw_meter.db import (
    ensure_schema,
    get_processed_files,
    insert_traffic_batch,
    mark_file_processed,
    upsert_host,
    upsert_process,
)


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    ensure_schema(c)
    yield c
    c.close()


class TestEnsureSchema:
    def test_creates_all_tables(self, conn):
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"process", "host", "traffic", "capture_file"} <= tables

    def test_idempotent(self, conn):
        ensure_schema(conn)  # second call must not raise

    def test_traffic_has_remote_port_column(self, conn):
        cols = {row[1] for row in conn.execute("PRAGMA table_info(traffic)")}
        assert "remote_port" in cols

    def test_migration_adds_remote_port_to_existing_db(self):
        """ensure_schema must add remote_port even when traffic was created without it."""
        c = sqlite3.connect(":memory:")
        # Create traffic table without remote_port (simulates old database)
        c.execute(
            """CREATE TABLE traffic (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                bucket_secs INTEGER NOT NULL,
                interface TEXT NOT NULL,
                process_id INTEGER,
                host_id INTEGER,
                direction TEXT NOT NULL,
                protocol TEXT,
                bytes INTEGER NOT NULL,
                packets INTEGER NOT NULL
            )"""
        )
        ensure_schema(c)
        cols = {row[1] for row in c.execute("PRAGMA table_info(traffic)")}
        assert "remote_port" in cols
        c.close()

    def test_process_table_has_pid_column(self, conn):
        cols = {row[1] for row in conn.execute("PRAGMA table_info(process)")}
        assert "pid" in cols

    def test_migration_adds_pid_to_existing_process_table(self):
        """ensure_schema must add pid even when process was created without it."""
        c = sqlite3.connect(":memory:")
        c.execute(
            """CREATE TABLE process (
                id INTEGER PRIMARY KEY,
                cmd TEXT NOT NULL,
                name TEXT NOT NULL,
                args TEXT,
                parent_cmd TEXT,
                parent_args TEXT,
                uid INTEGER,
                UNIQUE(cmd, args, uid)
            )"""
        )
        ensure_schema(c)
        cols = {row[1] for row in c.execute("PRAGMA table_info(process)")}
        assert "pid" in cols
        c.close()


class TestUpsertProcess:
    def test_inserts_and_returns_id(self, conn):
        pid = upsert_process(
            conn,
            cmd="/usr/bin/foo",
            name="foo",
            args="foo --bar",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
            pid=42,
        )
        assert pid > 0

    def test_pid_stored(self, conn):
        row_id = upsert_process(
            conn,
            cmd="/usr/bin/foo",
            name="foo",
            args="foo --bar",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
            pid=99,
        )
        row = conn.execute("SELECT pid FROM process WHERE id=?", (row_id,)).fetchone()
        assert row[0] == 99

    def test_pid_updated_on_conflict(self, conn):
        # args must be non-NULL so the UNIQUE(cmd, args, uid) constraint fires
        upsert_process(conn, cmd="/bin/sh", name="sh", args="sh", parent_cmd=None, parent_args=None, uid=0, pid=1)
        upsert_process(conn, cmd="/bin/sh", name="sh", args="sh", parent_cmd=None, parent_args=None, uid=0, pid=2)
        row = conn.execute("SELECT pid FROM process WHERE cmd='/bin/sh'").fetchone()
        assert row[0] == 2

    def test_same_cmd_args_uid_deduplicates(self, conn):
        id1 = upsert_process(
            conn,
            cmd="/usr/bin/foo",
            name="foo",
            args="foo",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
        )
        id2 = upsert_process(
            conn,
            cmd="/usr/bin/foo",
            name="foo",
            args="foo",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
        )
        assert id1 == id2

    def test_different_args_gives_different_rows(self, conn):
        id1 = upsert_process(
            conn,
            cmd="/usr/bin/python3",
            name="python3",
            args="python3 a.py",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
        )
        id2 = upsert_process(
            conn,
            cmd="/usr/bin/python3",
            name="python3",
            args="python3 b.py",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
        )
        assert id1 != id2

    def test_none_args_deduplicates(self, conn):
        id1 = upsert_process(
            conn,
            cmd="/bin/sh",
            name="sh",
            args=None,
            parent_cmd=None,
            parent_args=None,
            uid=0,
        )
        id2 = upsert_process(
            conn,
            cmd="/bin/sh",
            name="sh",
            args=None,
            parent_cmd=None,
            parent_args=None,
            uid=0,
        )
        assert id1 == id2


class TestUpsertHost:
    def test_inserts_and_returns_id(self, conn):
        hid = upsert_host(conn, "1.2.3.4")
        assert hid > 0

    def test_same_ip_deduplicates(self, conn):
        id1 = upsert_host(conn, "1.2.3.4")
        id2 = upsert_host(conn, "1.2.3.4")
        assert id1 == id2

    def test_adds_hostname(self, conn):
        upsert_host(conn, "1.2.3.4")
        upsert_host(conn, "1.2.3.4", "example.com")
        row = conn.execute("SELECT hostname FROM host WHERE ip='1.2.3.4'").fetchone()
        assert row[0] == "example.com"

    def test_does_not_overwrite_hostname_with_null(self, conn):
        upsert_host(conn, "1.2.3.4", "example.com")
        upsert_host(conn, "1.2.3.4")
        row = conn.execute("SELECT hostname FROM host WHERE ip='1.2.3.4'").fetchone()
        assert row[0] == "example.com"

    def test_updates_hostname(self, conn):
        upsert_host(conn, "1.2.3.4", "old.example.com")
        upsert_host(conn, "1.2.3.4", "new.example.com")
        row = conn.execute("SELECT hostname FROM host WHERE ip='1.2.3.4'").fetchone()
        assert row[0] == "new.example.com"


class TestCaptureFile:
    def test_mark_then_get(self, conn):
        assert "/path/to/file.pcapng" not in get_processed_files(conn)
        mark_file_processed(conn, "/path/to/file.pcapng")
        assert "/path/to/file.pcapng" in get_processed_files(conn)

    def test_mark_idempotent(self, conn):
        mark_file_processed(conn, "/path/a.pcapng")
        mark_file_processed(conn, "/path/a.pcapng")  # must not raise


class TestInsertTrafficBatch:
    def test_inserts_rows(self, conn):
        host_id = upsert_host(conn, "8.8.8.8", "dns.google")
        proc_id = upsert_process(
            conn,
            cmd="/bin/curl",
            name="curl",
            args="curl https://example.com",
            parent_cmd=None,
            parent_args=None,
            uid=1000,
        )
        rows = [
            {
                "ts": 1711000000,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_id,
                "host_id": host_id,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 1500,
                "packets": 3,
            }
        ]
        insert_traffic_batch(conn, rows)
        count = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
        assert count == 1

    def test_empty_batch_is_noop(self, conn):
        insert_traffic_batch(conn, [])
        count = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
        assert count == 0
