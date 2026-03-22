"""Distiller: process pcapng captures into SQLite."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from .db import (
    get_processed_files,
    insert_traffic_batch,
    mark_file_processed,
    open_db,
    upsert_host,
    upsert_process,
)

BASE_DIR = Path("/var/lib/bw-meter")
BUCKET_SECS = 60

_DELETED_RE = re.compile(r"\s*\(deleted\)\s*$")
_FRAME_NUM_RE = re.compile(r"^\d+\t")

_COMMENT_KEYS = {
    "PID": "pid",
    "Cmd": "cmd",
    "Args": "args",
    "UserId": "uid",
    "ParentPID": "ppid",
    "ParentCmd": "parent_cmd",
    "ParentArgs": "parent_args",
}


def derive_process_name(cmd: str, args: str) -> str:
    """Derive a human-readable display name from ptcpdump's Cmd and Args fields.

    Preference order:
    1. basename of Args[0] when it is a bare name (not a full path)
    2. basename of Cmd
    """
    cmd_clean = _DELETED_RE.sub("", cmd).strip()
    args_stripped = (args or "").strip()

    if args_stripped:
        first = args_stripped.split()[0]
        if not first.startswith("/"):
            name = first
        else:
            name = os.path.basename(first) or os.path.basename(cmd_clean)
    else:
        name = os.path.basename(cmd_clean)

    name = _DELETED_RE.sub("", name).strip()
    return name or os.path.basename(cmd_clean) or cmd_clean


def parse_comment(raw: str) -> dict[str, str]:
    """Parse a ptcpdump pcapng comment block into a plain dict.

    Keys: pid, cmd, args, uid, ppid, parent_cmd, parent_args.
    Unknown keys are silently ignored.
    """
    if not raw:
        return {}
    result: dict[str, str] = {}
    for line in raw.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            mapped = _COMMENT_KEYS.get(key.strip())
            if mapped:
                result[mapped] = value.strip()
    return result


def build_hostname_map(pcapng_path: Path) -> dict[str, str]:
    """Return {ip: hostname} from DNS responses and TLS SNI in *pcapng_path*.

    DNS takes precedence over SNI for the same IP.
    """
    hostname_map: dict[str, str] = {}

    # SNI first (lower priority)
    sni = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcapng_path),
            "-Y",
            "tls.handshake.type==1",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tls.handshake.extensions_server_name",
        ],
        capture_output=True,
        text=True,
    )
    for line in sni.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        sni_name = parts[2].strip()
        if not sni_name:
            continue
        for ip in (parts[0].strip(), parts[1].strip()):
            if ip:
                hostname_map[ip] = sni_name

    # DNS responses (higher priority — overwrites SNI)
    dns = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcapng_path),
            "-Y",
            "dns.flags.response==1",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.a",
            "-e",
            "dns.aaaa",
        ],
        capture_output=True,
        text=True,
    )
    for line in dns.stdout.splitlines():
        parts = line.split("\t")
        name = parts[0].strip() if parts else ""
        if not name:
            continue
        ips_a = parts[1].strip().split(",") if len(parts) > 1 else []
        ips_aaaa = parts[2].strip().split(",") if len(parts) > 2 else []
        for ip in ips_a + ips_aaaa:
            ip = ip.strip()
            if ip:
                hostname_map[ip] = name

    return hostname_map


def _iter_tshark_lines(pcapng_path: Path) -> Iterator[str]:
    proc = subprocess.Popen(
        [
            "tshark",
            "-r",
            str(pcapng_path),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "frame.comment",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None
    try:
        yield from proc.stdout
    finally:
        proc.stdout.close()
        proc.wait()


def iter_tshark_packets(
    pcapng_path: Path,
    *,
    _lines: Iterator[str] | None = None,
) -> Iterator[dict[str, str]]:
    """Yield one dict per packet from *pcapng_path* via tshark.

    Each dict has keys: num, ts, len, src4, dst4, src6, dst6, protocol, comment.
    The *_lines* parameter is used in tests to inject mock tshark output.
    """
    lines = _lines if _lines is not None else _iter_tshark_lines(pcapng_path)
    current: dict[str, str] | None = None

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if _FRAME_NUM_RE.match(line):
            if current is not None:
                yield current
            parts = line.split("\t", 12)
            current = {
                "num": parts[0] if len(parts) > 0 else "",
                "ts": parts[1] if len(parts) > 1 else "",
                "len": parts[2] if len(parts) > 2 else "",
                "src4": parts[3] if len(parts) > 3 else "",
                "dst4": parts[4] if len(parts) > 4 else "",
                "src6": parts[5] if len(parts) > 5 else "",
                "dst6": parts[6] if len(parts) > 6 else "",
                "protocol": parts[7] if len(parts) > 7 else "",
                "tcp_src_port": parts[8] if len(parts) > 8 else "",
                "tcp_dst_port": parts[9] if len(parts) > 9 else "",
                "udp_src_port": parts[10] if len(parts) > 10 else "",
                "udp_dst_port": parts[11] if len(parts) > 11 else "",
                "comment": parts[12] if len(parts) > 12 else "",
            }
        elif current is not None:
            # Continuation line: belongs to multi-line frame.comment
            current["comment"] += "\n" + line

    if current is not None:
        yield current


def get_local_ips(iface: str) -> set[str]:
    """Return the IP addresses currently assigned to *iface*."""
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", iface],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        ips: set[str] = set()
        for entry in data:
            for addr_info in entry.get("addr_info", []):
                ips.add(addr_info["local"])
        return ips
    except Exception:
        return set()


def derive_direction(src4: str, dst4: str, src6: str, dst6: str, local_ips: set[str]) -> str:
    """Return 'out' if the packet source is a local IP, else 'in'."""
    src = src4 or src6
    return "out" if src in local_ips else "in"


def find_distillable_files(base_dir: Path, processed: set[str]) -> list[tuple[str, Path]]:
    """Return (iface, path) pairs for closed, unprocessed pcapng files.

    The newest file per interface directory is assumed still open (being written
    by ptcpdump) and is excluded.
    """
    result: list[tuple[str, Path]] = []
    if not base_dir.exists():
        return result
    for iface_dir in sorted(base_dir.iterdir()):
        if not iface_dir.is_dir():
            continue
        iface = iface_dir.name
        files = sorted(iface_dir.glob("*.pcapng"), key=lambda p: p.stat().st_mtime)
        # Skip the newest (currently open); need at least 2 files to have a closed one
        for f in files[:-1]:
            if str(f) not in processed:
                result.append((iface, f))
    return result


def _aggregate(
    packets: Iterator[dict[str, str]],
    hostname_map: dict[str, str],
    local_ips: set[str],
    iface: str,
    bucket_secs: int = BUCKET_SECS,
) -> dict[tuple, dict]:
    """Aggregate an iterator of packet dicts into time buckets.

    Returns a dict keyed by (bucket_ts, iface, direction, remote_ip, protocol, comment, remote_port).
    Each value is {"bytes": int, "packets": int}.
    """
    buckets: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})

    for pkt in packets:
        try:
            ts = float(pkt["ts"])
            length = int(pkt["len"])
        except (ValueError, KeyError):
            continue

        src4, dst4 = pkt.get("src4", ""), pkt.get("dst4", "")
        src6, dst6 = pkt.get("src6", ""), pkt.get("dst6", "")
        if not (src4 or src6 or dst4 or dst6):
            continue  # Non-IP (ARP, etc.)

        direction = derive_direction(src4, dst4, src6, dst6, local_ips)
        dst = dst4 or dst6
        src = src4 or src6
        remote_ip = dst if direction == "out" else src

        protocol = (pkt.get("protocol") or "").lower() or None
        comment = pkt.get("comment", "")
        bucket_ts = int(ts // bucket_secs) * bucket_secs

        if direction == "out":
            port_str = pkt.get("tcp_dst_port", "") or pkt.get("udp_dst_port", "")
        else:
            port_str = pkt.get("tcp_src_port", "") or pkt.get("udp_src_port", "")
        remote_port = int(port_str.strip()) if port_str.strip().isdigit() else None

        key = (bucket_ts, iface, direction, remote_ip, protocol, comment, remote_port)
        buckets[key]["bytes"] += length
        buckets[key]["packets"] += 1

    return dict(buckets)


def distill_file(
    pcapng_path: Path,
    iface: str,
    conn: sqlite3.Connection,
    bucket_secs: int = BUCKET_SECS,
) -> None:
    """Distill one pcapng file into *conn*, then mark it processed."""
    local_ips = get_local_ips(iface)
    hostname_map = build_hostname_map(pcapng_path)
    packets = iter_tshark_packets(pcapng_path)
    buckets = _aggregate(packets, hostname_map, local_ips, iface, bucket_secs)

    traffic_rows: list[dict] = []
    for (bucket_ts, iface_, direction, remote_ip, protocol, comment, remote_port), counts in buckets.items():
        host_id = upsert_host(conn, remote_ip, hostname_map.get(remote_ip)) if remote_ip else None

        process_id: int | None = None
        if comment:
            parsed = parse_comment(comment)
            if parsed.get("cmd"):
                name = derive_process_name(parsed["cmd"], parsed.get("args", ""))
                process_id = upsert_process(
                    conn,
                    cmd=parsed["cmd"],
                    name=name,
                    args=parsed.get("args"),
                    parent_cmd=parsed.get("parent_cmd"),
                    parent_args=parsed.get("parent_args"),
                    uid=int(parsed["uid"]) if parsed.get("uid") else None,
                )

        traffic_rows.append(
            {
                "ts": bucket_ts,
                "bucket_secs": bucket_secs,
                "interface": iface_,
                "process_id": process_id,
                "host_id": host_id,
                "direction": direction,
                "protocol": protocol,
                "bytes": counts["bytes"],
                "packets": counts["packets"],
                "remote_port": remote_port,
            }
        )

    insert_traffic_batch(conn, traffic_rows)
    mark_file_processed(conn, str(pcapng_path))


def run_distiller(
    base_dir: Path = BASE_DIR,
    db_path: Path | str | None = None,
    bucket_secs: int = BUCKET_SECS,
    delete_after: bool = True,
) -> None:
    """Process all closed pcapng files under *base_dir* into the database."""
    conn = open_db(db_path)
    try:
        processed = get_processed_files(conn)
        for iface, pcapng_path in find_distillable_files(base_dir, processed):
            distill_file(pcapng_path, iface, conn, bucket_secs)
            if delete_after:
                pcapng_path.unlink(missing_ok=True)
    finally:
        conn.close()
