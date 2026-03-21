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
        )
        assert pid > 0

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
