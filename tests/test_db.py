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

    def test_migration_updates_host_table_from_old_schema(self):
        """ensure_schema must add last_observed and switch to partial unique indexes."""
        c = sqlite3.connect(":memory:")
        # Simulate old host table with UNIQUE(ip) but no last_observed
        c.execute(
            """CREATE TABLE host (
                id       INTEGER PRIMARY KEY,
                ip       TEXT NOT NULL,
                hostname TEXT,
                UNIQUE(ip)
            )"""
        )
        c.execute("INSERT INTO host(ip, hostname) VALUES ('1.2.3.4', 'example.com')")
        c.execute("INSERT INTO host(ip, hostname) VALUES ('5.6.7.8', NULL)")
        c.commit()
        ensure_schema(c)
        # last_observed column must now exist
        cols = {row[1] for row in c.execute("PRAGMA table_info(host)")}
        assert "last_observed" in cols
        # Data must be preserved
        rows = {row[0]: row[1] for row in c.execute("SELECT ip, hostname FROM host")}
        assert rows["1.2.3.4"] == "example.com"
        assert rows["5.6.7.8"] is None
        # Partial unique indexes must exist
        indexes = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='host'")}
        assert "host_ip_hostname" in indexes
        assert "host_ip_null" in indexes
        c.close()

    def test_failed_host_migration_leaves_old_table_intact(self, tmp_path):
        """If the table recreation fails half-way (after DROP), nothing must be lost."""
        c = sqlite3.connect(tmp_path / "old.db")
        c.execute("CREATE TABLE host (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT, UNIQUE(ip))")
        c.execute("INSERT INTO host(ip, hostname) VALUES ('1.2.3.4', 'example.com')")
        c.commit()

        def deny_rename(action, _db, table, *_):
            if action == sqlite3.SQLITE_ALTER_TABLE and table == "host_new":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        c.set_authorizer(deny_rename)
        with pytest.raises(sqlite3.DatabaseError):
            ensure_schema(c)
        c.set_authorizer(None)
        assert c.execute("SELECT ip, hostname FROM host").fetchall() == [("1.2.3.4", "example.com")]
        assert c.execute("SELECT name FROM sqlite_master WHERE name='host_new'").fetchall() == []
        c.close()

    def test_host_table_has_last_observed_column(self, conn):
        cols = {row[1] for row in conn.execute("PRAGMA table_info(host)")}
        assert "last_observed" in cols


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

    def test_same_ip_null_hostname_deduplicates(self, conn):
        id1 = upsert_host(conn, "1.2.3.4")
        id2 = upsert_host(conn, "1.2.3.4")
        assert id1 == id2

    def test_same_ip_same_hostname_deduplicates(self, conn):
        id1 = upsert_host(conn, "1.2.3.4", "example.com")
        id2 = upsert_host(conn, "1.2.3.4", "example.com")
        assert id1 == id2

    def test_null_and_non_null_hostname_are_separate_rows(self, conn):
        id_null = upsert_host(conn, "1.2.3.4")
        id_named = upsert_host(conn, "1.2.3.4", "example.com")
        assert id_null != id_named
        rows = conn.execute("SELECT hostname FROM host WHERE ip='1.2.3.4' ORDER BY hostname").fetchall()
        hostnames = {r[0] for r in rows}
        assert None in hostnames
        assert "example.com" in hostnames

    def test_different_hostnames_same_ip_create_separate_rows(self, conn):
        id1 = upsert_host(conn, "1.2.3.4", "a.example.com")
        id2 = upsert_host(conn, "1.2.3.4", "b.example.com")
        assert id1 != id2
        count = conn.execute("SELECT COUNT(*) FROM host WHERE ip='1.2.3.4'").fetchone()[0]
        assert count == 2

    def test_last_observed_is_set(self, conn):
        upsert_host(conn, "1.2.3.4", "example.com", last_observed=1_000_000)
        row = conn.execute("SELECT last_observed FROM host WHERE ip='1.2.3.4' AND hostname='example.com'").fetchone()
        assert row[0] == 1_000_000

    def test_last_observed_updated_to_max_on_conflict(self, conn):
        upsert_host(conn, "1.2.3.4", "example.com", last_observed=1_000_000)
        upsert_host(conn, "1.2.3.4", "example.com", last_observed=2_000_000)
        row = conn.execute("SELECT last_observed FROM host WHERE ip='1.2.3.4' AND hostname='example.com'").fetchone()
        assert row[0] == 2_000_000

    def test_last_observed_not_decreased(self, conn):
        upsert_host(conn, "1.2.3.4", "example.com", last_observed=2_000_000)
        upsert_host(conn, "1.2.3.4", "example.com", last_observed=1_000_000)
        row = conn.execute("SELECT last_observed FROM host WHERE ip='1.2.3.4' AND hostname='example.com'").fetchone()
        assert row[0] == 2_000_000

    def test_null_hostname_last_observed_updated(self, conn):
        upsert_host(conn, "1.2.3.4", last_observed=1_000_000)
        upsert_host(conn, "1.2.3.4", last_observed=3_000_000)
        row = conn.execute("SELECT last_observed FROM host WHERE ip='1.2.3.4' AND hostname IS NULL").fetchone()
        assert row[0] == 3_000_000


class TestCaptureFile:
    def test_mark_then_get(self, conn):
        assert "/path/to/file.pcapng" not in get_processed_files(conn)
        mark_file_processed(conn, "/path/to/file.pcapng")
        assert "/path/to/file.pcapng" in get_processed_files(conn)

    def test_mark_idempotent(self, conn):
        mark_file_processed(conn, "/path/a.pcapng")
        mark_file_processed(conn, "/path/a.pcapng")  # must not raise


class TestOpenDb:
    def test_env_var_sets_db_path(self, tmp_path, monkeypatch):
        """BW_METER_DB env var must be used when no explicit path is given."""
        db_file = tmp_path / "custom.db"
        monkeypatch.setenv("BW_METER_DB", str(db_file))
        from bw_meter.db import open_db

        conn = open_db()
        conn.close()
        assert db_file.exists()

    def test_explicit_path_overrides_env_var(self, tmp_path, monkeypatch):
        """Explicit path must take precedence over BW_METER_DB."""
        monkeypatch.setenv("BW_METER_DB", str(tmp_path / "env.db"))
        explicit = tmp_path / "explicit.db"
        from bw_meter.db import open_db

        conn = open_db(explicit)
        conn.close()
        assert explicit.exists()
        assert not (tmp_path / "env.db").exists()

    def test_open_db_readonly_in_readonly_directory(self, tmp_path):
        from bw_meter.db import open_db, open_db_readonly

        d = tmp_path / "ro"
        d.mkdir()
        open_db(d / "x.db").close()
        d.chmod(0o555)
        try:
            conn = open_db_readonly(d / "x.db")
            assert conn.execute("SELECT COUNT(*) FROM traffic").fetchone() == (0,)
            conn.close()
        finally:
            d.chmod(0o755)

    def test_open_db_readonly_does_not_create(self, tmp_path):
        from bw_meter.db import open_db_readonly

        with pytest.raises(sqlite3.OperationalError):
            open_db_readonly(tmp_path / "missing.db")
        assert not (tmp_path / "missing.db").exists()

    def test_open_db_uses_rollback_journal(self, tmp_path):
        """WAL would stop read-only users from opening the DB in a root-owned directory."""
        from bw_meter.db import open_db

        path = tmp_path / "x.db"
        c = sqlite3.connect(path)
        c.execute("PRAGMA journal_mode=WAL")
        c.close()
        conn = open_db(path)
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        conn.close()


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
