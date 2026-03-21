"""Tests for bw_meter.distiller."""

import os
import time
from pathlib import Path

from bw_meter.distiller import (
    _aggregate,
    build_hostname_map,
    derive_direction,
    derive_process_name,
    find_distillable_files,
    iter_tshark_packets,
    parse_comment,
)


class TestDeriveProcessName:
    def test_args_bare_name(self):
        assert derive_process_name("/usr/bin/python3", "python3 script.py") == "python3"

    def test_cmd_fallback_when_args_empty(self):
        assert derive_process_name("/usr/local/bin/chrome", "") == "chrome"

    def test_cmd_fallback_when_args_is_full_path(self):
        assert derive_process_name("/usr/bin/python3", "/usr/bin/python3 -c x") == "python3"

    def test_strips_deleted_from_cmd(self):
        assert derive_process_name("/usr/lib/chromium/chromium (deleted)", "chromium --type=renderer") == "chromium"

    def test_claude_versioned_path(self):
        cmd = "/home/user/.local/share/claude/versions/2.1.81/claude"
        assert derive_process_name(cmd, "claude --flag") == "claude"

    def test_args_full_path_falls_back_to_cmd_basename(self):
        assert derive_process_name("/usr/bin/env", "/usr/bin/env python3") == "env"

    def test_strips_deleted_suffix_from_name(self):
        assert derive_process_name("/bin/foo (deleted)", "") == "foo"


class TestParseComment:
    FULL = (
        "PID: 1234\nCmd: /usr/bin/firefox\nArgs: firefox --no-sandbox\n"
        "UserId: 1000\nParentPID: 500\nParentCmd: /bin/bash\nParentArgs: bash"
    )

    def test_full_comment(self):
        r = parse_comment(self.FULL)
        assert r["pid"] == "1234"
        assert r["cmd"] == "/usr/bin/firefox"
        assert r["args"] == "firefox --no-sandbox"
        assert r["uid"] == "1000"
        assert r["ppid"] == "500"
        assert r["parent_cmd"] == "/bin/bash"
        assert r["parent_args"] == "bash"

    def test_empty_string_returns_empty_dict(self):
        assert parse_comment("") == {}

    def test_partial_comment(self):
        r = parse_comment("PID: 42\nCmd: /bin/sh")
        assert r["pid"] == "42"
        assert r["cmd"] == "/bin/sh"
        assert "uid" not in r

    def test_unknown_keys_ignored(self):
        r = parse_comment("PID: 1\nWeird: value")
        assert r["pid"] == "1"
        assert "weird" not in r
        assert "Weird" not in r


class TestDeriveDirection:
    LOCAL = {"192.168.1.10", "fe80::1"}

    def test_outbound_ipv4(self):
        assert derive_direction("192.168.1.10", "8.8.8.8", "", "", self.LOCAL) == "out"

    def test_inbound_ipv4(self):
        assert derive_direction("8.8.8.8", "192.168.1.10", "", "", self.LOCAL) == "in"

    def test_outbound_ipv6(self):
        assert derive_direction("", "", "fe80::1", "2001:db8::1", self.LOCAL) == "out"

    def test_inbound_ipv6(self):
        assert derive_direction("", "", "2001:db8::1", "fe80::1", self.LOCAL) == "in"

    def test_unknown_src_defaults_to_in(self):
        assert derive_direction("9.9.9.9", "8.8.8.8", "", "", self.LOCAL) == "in"

    def test_empty_local_ips_defaults_to_in(self):
        assert derive_direction("192.168.1.10", "8.8.8.8", "", "", set()) == "in"


class TestBuildHostnameMap:
    def _fake_run_factory(self, dns_out: str, sni_out: str):
        def fake_run(args, **kwargs):
            class R:
                pass

            r = R()
            if "dns.flags.response==1" in args:
                r.stdout = dns_out
            else:
                r.stdout = sni_out
            return r

        return fake_run

    def test_dns_a_records(self, monkeypatch):
        fake = self._fake_run_factory("example.com\t93.184.216.34\t\n", "")
        monkeypatch.setattr("bw_meter.distiller.subprocess.run", fake)
        result = build_hostname_map(Path("dummy.pcapng"))
        assert result.get("93.184.216.34") == "example.com"

    def test_dns_multiple_a_records(self, monkeypatch):
        fake = self._fake_run_factory("multi.example.com\t1.2.3.4,5.6.7.8\t\n", "")
        monkeypatch.setattr("bw_meter.distiller.subprocess.run", fake)
        result = build_hostname_map(Path("dummy.pcapng"))
        assert result["1.2.3.4"] == "multi.example.com"
        assert result["5.6.7.8"] == "multi.example.com"

    def test_sni_used_when_no_dns(self, monkeypatch):
        fake = self._fake_run_factory("", "1.2.3.4\t\tsni.example.com\n")
        monkeypatch.setattr("bw_meter.distiller.subprocess.run", fake)
        result = build_hostname_map(Path("dummy.pcapng"))
        assert result["1.2.3.4"] == "sni.example.com"

    def test_dns_overwrites_sni(self, monkeypatch):
        # SNI and DNS both map the same IP; DNS wins.
        fake = self._fake_run_factory(
            "real.example.com\t1.2.3.4\t\n",
            "1.2.3.4\t\tsni.example.com\n",
        )
        monkeypatch.setattr("bw_meter.distiller.subprocess.run", fake)
        result = build_hostname_map(Path("dummy.pcapng"))
        assert result["1.2.3.4"] == "real.example.com"

    def test_empty_tshark_output(self, monkeypatch):
        fake = self._fake_run_factory("", "")
        monkeypatch.setattr("bw_meter.distiller.subprocess.run", fake)
        assert build_hostname_map(Path("dummy.pcapng")) == {}


class TestIterTsharkPackets:
    def test_single_packet_no_comment(self):
        lines = iter(
            [
                "1\t1711000000.0\t1500\t192.168.1.1\t8.8.8.8\t\t\tTCP\t\n",
            ]
        )
        pkts = list(iter_tshark_packets(Path("dummy"), _lines=lines))
        assert len(pkts) == 1
        assert pkts[0]["num"] == "1"
        assert pkts[0]["ts"] == "1711000000.0"
        assert pkts[0]["len"] == "1500"
        assert pkts[0]["src4"] == "192.168.1.1"
        assert pkts[0]["dst4"] == "8.8.8.8"
        assert pkts[0]["protocol"] == "TCP"
        assert pkts[0]["comment"] == ""

    def test_single_packet_with_comment(self):
        lines = iter(
            [
                "1\t1711000000.0\t100\t10.0.0.1\t8.8.8.8\t\t\tTCP\tPID: 42\n",
            ]
        )
        pkts = list(iter_tshark_packets(Path("dummy"), _lines=lines))
        assert pkts[0]["comment"] == "PID: 42"

    def test_multiline_comment_reassembled(self):
        lines = iter(
            [
                "1\t1711000000.0\t100\t10.0.0.1\t1.2.3.4\t\t\tTCP\tPID: 1\n",
                "Cmd: /usr/bin/foo\n",
                "Args: foo\n",
                "2\t1711000001.0\t200\t5.6.7.8\t10.0.0.1\t\t\tTCP\t\n",
            ]
        )
        pkts = list(iter_tshark_packets(Path("dummy"), _lines=lines))
        assert len(pkts) == 2
        assert pkts[0]["comment"] == "PID: 1\nCmd: /usr/bin/foo\nArgs: foo"
        assert pkts[1]["comment"] == ""

    def test_empty_output(self):
        pkts = list(iter_tshark_packets(Path("dummy"), _lines=iter([])))
        assert pkts == []

    def test_ipv6_fields(self):
        lines = iter(
            [
                "1\t1711000000.0\t80\t\t\t::1\t2001:db8::1\tTCP\t\n",
            ]
        )
        pkts = list(iter_tshark_packets(Path("dummy"), _lines=lines))
        assert pkts[0]["src6"] == "::1"
        assert pkts[0]["dst6"] == "2001:db8::1"
        assert pkts[0]["src4"] == ""


class TestAggregate:
    LOCAL = {"10.0.0.1"}

    def _pkt(self, ts, length, src4="10.0.0.1", dst4="8.8.8.8", src6="", dst6="", comment="", protocol="TCP"):
        return {
            "ts": str(ts),
            "len": str(length),
            "src4": src4,
            "dst4": dst4,
            "src6": src6,
            "dst6": dst6,
            "protocol": protocol,
            "comment": comment,
        }

    def test_single_outbound_packet(self):
        pkt = self._pkt(1711000000.0, 1500)
        result = _aggregate(iter([pkt]), {}, self.LOCAL, "wlan0", bucket_secs=60)
        assert len(result) == 1
        key = next(iter(result))
        _, iface, direction, remote_ip, protocol, _ = key
        assert direction == "out"
        assert remote_ip == "8.8.8.8"
        assert iface == "wlan0"
        assert result[key]["bytes"] == 1500
        assert result[key]["packets"] == 1

    def test_packets_merged_in_same_bucket(self):
        pkts = [
            self._pkt(1711000000.0, 100),
            self._pkt(1711000015.0, 200),  # same 60-sec bucket (offset 40 and 55 within bucket)
        ]
        result = _aggregate(iter(pkts), {}, self.LOCAL, "wlan0", bucket_secs=60)
        assert len(result) == 1
        assert next(iter(result.values()))["bytes"] == 300
        assert next(iter(result.values()))["packets"] == 2

    def test_packets_in_different_buckets_stay_separate(self):
        pkts = [
            self._pkt(1711000000.0, 100),
            self._pkt(1711000060.0, 200),  # next 60-sec bucket
        ]
        result = _aggregate(iter(pkts), {}, self.LOCAL, "wlan0", bucket_secs=60)
        assert len(result) == 2

    def test_non_ip_packet_skipped(self):
        pkt = {
            "ts": "1711000000.0",
            "len": "60",
            "src4": "",
            "dst4": "",
            "src6": "",
            "dst6": "",
            "protocol": "ARP",
            "comment": "",
        }
        result = _aggregate(iter([pkt]), {}, self.LOCAL, "wlan0")
        assert len(result) == 0

    def test_inbound_remote_ip_is_src(self):
        pkt = self._pkt(1711000000.0, 500, src4="8.8.8.8", dst4="10.0.0.1")
        result = _aggregate(iter([pkt]), {}, self.LOCAL, "wlan0", bucket_secs=60)
        key = next(iter(result))
        _, _, direction, remote_ip, _, _ = key
        assert direction == "in"
        assert remote_ip == "8.8.8.8"

    def test_different_processes_separate_buckets(self):
        comment_a = "PID: 1\nCmd: /bin/curl"
        comment_b = "PID: 2\nCmd: /bin/wget"
        pkts = [
            self._pkt(1711000000.0, 100, comment=comment_a),
            self._pkt(1711000000.0, 200, comment=comment_b),
        ]
        result = _aggregate(iter(pkts), {}, self.LOCAL, "wlan0", bucket_secs=60)
        assert len(result) == 2

    def test_invalid_ts_or_len_skipped(self):
        pkt = self._pkt(1711000000.0, 100)
        pkt["ts"] = "not-a-number"
        result = _aggregate(iter([pkt]), {}, self.LOCAL, "wlan0")
        assert len(result) == 0


class TestFindDistillableFiles:
    def test_empty_base_dir(self, tmp_path):
        assert find_distillable_files(tmp_path, set()) == []

    def test_nonexistent_base_dir(self, tmp_path):
        assert find_distillable_files(tmp_path / "nope", set()) == []

    def test_skips_newest_file_per_interface(self, tmp_path):
        iface_dir = tmp_path / "wlan0"
        iface_dir.mkdir()
        old = iface_dir / "capture-old.pcapng"
        new = iface_dir / "capture-new.pcapng"
        old.write_bytes(b"")
        new.write_bytes(b"")
        now = time.time()
        os.utime(old, (now - 100, now - 100))
        os.utime(new, (now, now))

        paths = [p for _, p in find_distillable_files(tmp_path, set())]
        assert old in paths
        assert new not in paths

    def test_skips_already_processed(self, tmp_path):
        iface_dir = tmp_path / "wlan0"
        iface_dir.mkdir()
        old = iface_dir / "capture-old.pcapng"
        new = iface_dir / "capture-new.pcapng"
        old.write_bytes(b"")
        new.write_bytes(b"")
        now = time.time()
        os.utime(old, (now - 100, now - 100))
        os.utime(new, (now, now))

        paths = [p for _, p in find_distillable_files(tmp_path, {str(old)})]
        assert old not in paths

    def test_returns_iface_name(self, tmp_path):
        iface_dir = tmp_path / "wg0"
        iface_dir.mkdir()
        old = iface_dir / "old.pcapng"
        new = iface_dir / "new.pcapng"
        old.write_bytes(b"")
        new.write_bytes(b"")
        now = time.time()
        os.utime(old, (now - 100, now - 100))
        os.utime(new, (now, now))

        result = find_distillable_files(tmp_path, set())
        assert result[0][0] == "wg0"

    def test_single_file_in_dir_is_skipped(self, tmp_path):
        """A directory with only one file means it's still open — skip it."""
        iface_dir = tmp_path / "wlan0"
        iface_dir.mkdir()
        (iface_dir / "capture-only.pcapng").write_bytes(b"")
        assert find_distillable_files(tmp_path, set()) == []
