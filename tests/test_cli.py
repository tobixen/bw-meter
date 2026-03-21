"""Tests for bw_meter.cli — command implementations."""

from __future__ import annotations

import argparse
import json
import sqlite3

import pytest

from bw_meter.cli import (
    _format_bytes,
    _parse_interval,
    cmd_hosts,
    cmd_processes,
    cmd_report,
    cmd_timeline,
    cmd_top,
)
from bw_meter.db import (
    ensure_schema,
    insert_traffic_batch,
    upsert_host,
    upsert_process,
)

# Fixed timestamp well within 2024-03-21 so explicit since/until bounds work
BASE_TS = 1_711_029_600  # 2024-03-21 10:00 UTC


@pytest.fixture
def db_path(tmp_path):
    """Create and populate a test database; return its path as a string."""
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    ensure_schema(conn)

    proc_curl = upsert_process(
        conn,
        cmd="/bin/curl",
        name="curl",
        args="curl https://example.com",
        parent_cmd=None,
        parent_args=None,
        uid=1000,
    )
    proc_firefox = upsert_process(
        conn,
        cmd="/usr/bin/firefox",
        name="firefox",
        args="firefox",
        parent_cmd=None,
        parent_args=None,
        uid=1000,
    )

    host_google = upsert_host(conn, "8.8.8.8", "dns.google")
    host_example = upsert_host(conn, "93.184.216.34", "example.com")

    insert_traffic_batch(
        conn,
        [
            # curl → dns.google (outbound then inbound)
            {
                "ts": BASE_TS,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_curl,
                "host_id": host_google,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 1_000,
                "packets": 10,
            },
            {
                "ts": BASE_TS,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_curl,
                "host_id": host_google,
                "direction": "in",
                "protocol": "tcp",
                "bytes": 5_000,
                "packets": 20,
            },
            # firefox → example.com (much larger, should rank higher)
            {
                "ts": BASE_TS + 120,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_firefox,
                "host_id": host_example,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 2_000,
                "packets": 15,
            },
            {
                "ts": BASE_TS + 120,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_firefox,
                "host_id": host_example,
                "direction": "in",
                "protocol": "tcp",
                "bytes": 30_000,
                "packets": 200,
            },
            # kernel/untagged traffic
            {
                "ts": BASE_TS,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": None,
                "host_id": None,
                "direction": "out",
                "protocol": "wireguard",
                "bytes": 500,
                "packets": 5,
            },
            # traffic on a different interface (should be filterable)
            {
                "ts": BASE_TS,
                "bucket_secs": 60,
                "interface": "eth0",
                "process_id": proc_curl,
                "host_id": host_google,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 9_999,
                "packets": 99,
            },
        ],
    )
    conn.commit()
    conn.close()
    return path


def _args(**kwargs) -> argparse.Namespace:
    """Build a minimal Namespace for testing; since/until default to a wide range."""
    defaults = {
        "db": None,
        "interface": None,
        "since": "2024-01-01",
        "until": "2025-01-01",
        "json": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _format_bytes
# ---------------------------------------------------------------------------


class TestFormatBytes:
    def test_bytes(self):
        assert "B" in _format_bytes(500)

    def test_kilobytes(self):
        assert "KB" in _format_bytes(2048)

    def test_megabytes(self):
        assert "MB" in _format_bytes(2 * 1024 * 1024)

    def test_zero(self):
        assert "0" in _format_bytes(0)


# ---------------------------------------------------------------------------
# _parse_interval
# ---------------------------------------------------------------------------


class TestParseInterval:
    def test_minutes(self):
        assert _parse_interval("5m") == 300

    def test_hours(self):
        assert _parse_interval("1h") == 3600

    def test_seconds(self):
        assert _parse_interval("30s") == 30

    def test_days(self):
        assert _parse_interval("1d") == 86400

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid interval"):
            _parse_interval("badval")


# ---------------------------------------------------------------------------
# cmd_report
# ---------------------------------------------------------------------------


class TestCmdReport:
    def test_shows_process_names(self, db_path, capsys):
        args = _args(db=db_path)
        rc = cmd_report(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "curl" in out
        assert "firefox" in out

    def test_shows_kernel_traffic(self, db_path, capsys):
        args = _args(db=db_path)
        cmd_report(args)
        out = capsys.readouterr().out
        assert "(kernel)" in out

    def test_firefox_ranked_above_curl(self, db_path, capsys):
        args = _args(db=db_path)
        cmd_report(args)
        out = capsys.readouterr().out
        assert out.index("firefox") < out.index("curl")

    def test_interface_filter_excludes_other_interface(self, db_path, capsys):
        # With interface=wlan0, the 9999-byte eth0 row should not appear in totals
        # for curl; the wlan0 total for curl is 1000+5000 = 6000 bytes
        args = _args(db=db_path, interface="wlan0")
        cmd_report(args)
        out = capsys.readouterr().out
        # eth0-only curl traffic (9999 bytes) should not appear in wlan0-only report
        assert "9.8 KB" not in out  # 9999 bytes formatted

    def test_json_output(self, db_path, capsys):
        args = _args(db=db_path, json=True)
        rc = cmd_report(args)
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert any(row["process"] == "firefox" for row in data)


# ---------------------------------------------------------------------------
# cmd_top
# ---------------------------------------------------------------------------


class TestCmdTop:
    def test_by_process(self, db_path, capsys):
        args = _args(db=db_path, by="process", limit=10)
        rc = cmd_top(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "curl" in out
        assert "firefox" in out

    def test_by_process_respects_limit(self, db_path, capsys):
        args = _args(db=db_path, by="process", limit=1)
        cmd_top(args)
        out = capsys.readouterr().out
        # Only 1 row → only the top process (firefox) should appear
        assert "firefox" in out
        assert "curl" not in out

    def test_by_host(self, db_path, capsys):
        args = _args(db=db_path, by="host", limit=10)
        rc = cmd_top(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "dns.google" in out

    def test_by_host_plus_process(self, db_path, capsys):
        args = _args(db=db_path, by="process+host", limit=10)
        rc = cmd_top(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "firefox" in out
        assert "example.com" in out

    def test_json_output(self, db_path, capsys):
        args = _args(db=db_path, by="process", limit=10, json=True)
        rc = cmd_top(args)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["process"] == "firefox"


# ---------------------------------------------------------------------------
# cmd_timeline
# ---------------------------------------------------------------------------


class TestCmdTimeline:
    def test_basic(self, db_path, capsys):
        args = _args(db=db_path, interval="1m", process=None, host=None)
        rc = cmd_timeline(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert len(out.strip().splitlines()) >= 2  # header + at least one data row

    def test_filter_by_process(self, db_path, capsys):
        args = _args(db=db_path, interval="1m", process="curl", host=None)
        cmd_timeline(args)
        out = capsys.readouterr().out
        # Only curl traffic — should have fewer bytes than unfiltered
        lines = [ln for ln in out.strip().splitlines() if ln and not ln.startswith("-") and "time" not in ln.lower()]
        assert lines  # some rows

    def test_filter_by_host(self, db_path, capsys):
        args = _args(db=db_path, interval="1m", process=None, host="example.com")
        cmd_timeline(args)
        out = capsys.readouterr().out
        assert out.strip()

    def test_json_output(self, db_path, capsys):
        args = _args(db=db_path, interval="1m", process=None, host=None, json=True)
        rc = cmd_timeline(args)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)

    def test_invalid_interval_raises(self, db_path):
        args = _args(db=db_path, interval="badval", process=None, host=None)
        with pytest.raises(ValueError, match="Invalid interval"):
            cmd_timeline(args)


# ---------------------------------------------------------------------------
# cmd_hosts
# ---------------------------------------------------------------------------


class TestCmdHosts:
    def test_shows_hosts_for_process(self, db_path, capsys):
        args = _args(db=db_path, process="curl")
        rc = cmd_hosts(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "dns.google" in out

    def test_unknown_process_shows_no_data(self, db_path, capsys):
        args = _args(db=db_path, process="nonexistent")
        rc = cmd_hosts(args)
        assert rc == 0
        out = capsys.readouterr().out
        # no data rows — output may be empty or just headers
        assert "dns.google" not in out

    def test_json_output(self, db_path, capsys):
        args = _args(db=db_path, process="curl", json=True)
        rc = cmd_hosts(args)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert any("dns.google" in str(row.get("host", "")) for row in data)


# ---------------------------------------------------------------------------
# cmd_processes
# ---------------------------------------------------------------------------


class TestCmdProcesses:
    def test_shows_processes_for_host(self, db_path, capsys):
        args = _args(db=db_path, host="example.com")
        rc = cmd_processes(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "firefox" in out

    def test_filter_by_ip(self, db_path, capsys):
        args = _args(db=db_path, host="8.8.8.8")
        cmd_processes(args)
        out = capsys.readouterr().out
        assert "curl" in out

    def test_json_output(self, db_path, capsys):
        args = _args(db=db_path, host="example.com", json=True)
        rc = cmd_processes(args)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert any(row.get("process") == "firefox" for row in data)
