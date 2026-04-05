"""Tests for bw_meter.cli — command implementations."""

from __future__ import annotations

import argparse
import json
import sqlite3

import pytest

from bw_meter.cli import (
    _format_bytes,
    _parse_interval,
    cmd_report,
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
        pid=1234,
    )
    proc_firefox = upsert_process(
        conn,
        cmd="/usr/bin/firefox",
        name="firefox",
        args="firefox",
        parent_cmd=None,
        parent_args=None,
        uid=1000,
        pid=5678,
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
                "host_id": host_google,
                "direction": "out",
                "protocol": "wireguard",
                "bytes": 500,
                "packets": 5,
                "remote_port": None,
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
                "remote_port": 443,
            },
            # curl → port 443 on example.com
            {
                "ts": BASE_TS + 60,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_curl,
                "host_id": host_example,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 200,
                "packets": 2,
                "remote_port": 443,
            },
            # curl → port 80 (should be excluded by port=443 filter)
            {
                "ts": BASE_TS + 60,
                "bucket_secs": 60,
                "interface": "wlan0",
                "process_id": proc_curl,
                "host_id": host_example,
                "direction": "out",
                "protocol": "tcp",
                "bytes": 100,
                "packets": 1,
                "remote_port": 80,
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
        "sort": None,
        "group_by": "process",
        "show": "in,out,total",
        "interval": "1h",
        "limit": None,
        "process": None,
        "host": None,
        "port": None,
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
# --group-by process  (default; replaces old cmd_report / cmd_top --by process)
# ---------------------------------------------------------------------------


class TestGroupByProcess:
    def test_shows_process_names(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path))
        assert rc == 0
        out = capsys.readouterr().out
        assert "curl" in out
        assert "firefox" in out

    def test_shows_kernel_traffic(self, db_path, capsys):
        cmd_report(_args(db=db_path))
        assert "(kernel)" in capsys.readouterr().out

    def test_firefox_ranked_above_curl_by_total(self, db_path, capsys):
        cmd_report(_args(db=db_path))
        out = capsys.readouterr().out
        assert out.index("firefox") < out.index("curl")

    def test_sort_by_out_reverses_order(self, db_path, capsys):
        # curl has more outbound than firefox across all interfaces
        cmd_report(_args(db=db_path, sort="out"))
        out = capsys.readouterr().out
        assert out.index("curl") < out.index("firefox")

    def test_sort_by_packets(self, db_path, capsys):
        assert cmd_report(_args(db=db_path, sort="packets")) == 0

    def test_interface_filter(self, db_path, capsys):
        # wlan0 only: the 9999-byte eth0 curl row must not appear
        cmd_report(_args(db=db_path, interface="wlan0"))
        out = capsys.readouterr().out
        assert "9.8 KB" not in out  # 9999 bytes formatted

    def test_limit(self, db_path, capsys):
        cmd_report(_args(db=db_path, limit=1))
        out = capsys.readouterr().out
        assert "firefox" in out
        assert "curl" not in out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert any(row["process"] == "firefox" for row in data)
        assert "bytes_in" in data[0]
        assert "bytes_out" in data[0]
        assert "total_bytes" in data[0]


# ---------------------------------------------------------------------------
# --group-by host  (replaces old cmd_top --by host / cmd_hosts)
# ---------------------------------------------------------------------------


class TestGroupByHost:
    def test_shows_hosts(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="host"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "dns.google" in out

    def test_filter_by_process(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="host", process="curl"))
        out = capsys.readouterr().out
        assert "dns.google" in out

    def test_unknown_process_no_data(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="host", process="nonexistent"))
        out = capsys.readouterr().out
        assert "dns.google" not in out

    def test_kernel_process(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="host", process="(kernel)"))
        out = capsys.readouterr().out
        assert "dns.google" in out

    def test_sort_by_out(self, db_path, capsys):
        # dns.google has more outbound than example.com across all interfaces
        cmd_report(_args(db=db_path, group_by="host", sort="out"))
        out = capsys.readouterr().out
        assert out.index("dns.google") < out.index("example.com")

    def test_port_filter(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="host", process="curl", port=443))
        out = capsys.readouterr().out
        assert "example.com" in out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="host", process="curl", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any("dns.google" in str(row.get("host", "")) for row in data)


# ---------------------------------------------------------------------------
# --group-by process,host  (replaces old cmd_top --by process+host)
# ---------------------------------------------------------------------------


class TestGroupByProcessHost:
    def test_shows_both_columns(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="process,host"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "firefox" in out
        assert "example.com" in out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="process,host", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "process" in data[0]
        assert "host" in data[0]


# ---------------------------------------------------------------------------
# --group-by process --host  (replaces old cmd_processes)
# ---------------------------------------------------------------------------


class TestFilterByHost:
    def test_shows_processes_for_host(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="process", host="example.com"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "firefox" in out

    def test_filter_by_ip(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="process", host="8.8.8.8"))
        out = capsys.readouterr().out
        assert "curl" in out

    def test_port_filter(self, db_path, capsys):
        # example.com has curl on 80 and 443; port=80 should exclude firefox (no port-80 traffic)
        cmd_report(_args(db=db_path, group_by="process", host="example.com", port=80))
        out = capsys.readouterr().out
        assert "curl" in out
        assert "firefox" not in out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="process", host="example.com", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any(row.get("process") == "firefox" for row in data)


# ---------------------------------------------------------------------------
# --group-by port  (replaces old cmd_ports)
# ---------------------------------------------------------------------------


class TestGroupByPort:
    def test_shows_ports(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="port"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "443" in out
        assert "Port" in out

    def test_filter_by_process(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="port", process="curl"))
        out = capsys.readouterr().out
        assert "443" in out

    def test_filter_by_host(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="port", host="example.com"))
        out = capsys.readouterr().out
        assert "443" in out
        assert "80" in out

    def test_null_ports_excluded(self, db_path, capsys):
        # The WireGuard/kernel row has remote_port=NULL; must not appear
        cmd_report(_args(db=db_path, group_by="port", json=True))
        data = json.loads(capsys.readouterr().out)
        assert all(row["port"] is not None for row in data)

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="port", process="curl", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any(row.get("port") == 443 for row in data)


# ---------------------------------------------------------------------------
# --group-by time  (replaces old cmd_timeline)
# ---------------------------------------------------------------------------


class TestGroupByTime:
    def test_basic_timeline(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="time", interval="1m"))
        assert rc == 0
        out = capsys.readouterr().out
        assert len(out.strip().splitlines()) >= 2  # header + at least one row

    def test_default_sort_is_time_asc(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="time", interval="1m"))
        out = capsys.readouterr().out
        lines = [ln for ln in out.splitlines() if "2024" in ln]
        assert lines == sorted(lines)

    def test_filter_by_process(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="time", interval="1m", process="curl"))
        assert rc == 0
        assert capsys.readouterr().out.strip()

    def test_filter_by_host(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="time", interval="1m", host="example.com"))
        assert rc == 0
        assert capsys.readouterr().out.strip()

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="time", interval="1m", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert all("time" in row for row in data)

    def test_invalid_interval_raises(self, db_path):
        with pytest.raises(ValueError, match="Invalid interval"):
            cmd_report(_args(db=db_path, group_by="time", interval="badval"))

    def test_sort_time_without_time_group_errors(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="process", sort="time"))
        assert rc == 1


# ---------------------------------------------------------------------------
# --show variations
# ---------------------------------------------------------------------------


class TestShowColumns:
    def test_show_total_only(self, db_path, capsys):
        cmd_report(_args(db=db_path, show="total"))
        out = capsys.readouterr().out
        assert "Total" in out
        assert "In" not in out
        assert "Out" not in out

    def test_show_packets(self, db_path, capsys):
        cmd_report(_args(db=db_path, show="total,packets"))
        out = capsys.readouterr().out
        assert "Packets" in out

    def test_json_show_total_only(self, db_path, capsys):
        cmd_report(_args(db=db_path, show="total", json=True))
        data = json.loads(capsys.readouterr().out)
        assert "total_bytes" in data[0]
        assert "bytes_in" not in data[0]

    def test_invalid_show_column(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, show="bogus"))
        assert rc == 1


# ---------------------------------------------------------------------------
# --group-by cmdline
# ---------------------------------------------------------------------------


class TestGroupByCmdline:
    def test_shows_full_command_line(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="cmdline"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "curl https://example.com" in out

    def test_shows_kernel_traffic(self, db_path, capsys):
        cmd_report(_args(db=db_path, group_by="cmdline"))
        assert "(kernel)" in capsys.readouterr().out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="cmdline", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any("curl https://example.com" in str(row.get("cmdline", "")) for row in data)


# ---------------------------------------------------------------------------
# --group-by pid
# ---------------------------------------------------------------------------


class TestGroupByPid:
    def test_shows_pids(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="pid"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "1234" in out
        assert "5678" in out

    def test_json_output(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="pid", json=True))
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        pids = [row.get("pid") for row in data]
        assert 1234 in pids or 5678 in pids


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class TestValidation:
    def test_invalid_group_by(self, db_path, capsys):
        rc = cmd_report(_args(db=db_path, group_by="bogus"))
        assert rc == 1
