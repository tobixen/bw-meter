"""bw-meter command-line interface."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sqlite3
import sys
from pathlib import Path

import argcomplete

from ._version import __version__
from .timeutil import parse_dt

_INTERVAL_RE = re.compile(r"^(\d+)([smhd])$")
_INTERVAL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _format_bytes(n: int) -> str:
    """Return *n* bytes as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


def _parse_interval(s: str) -> int:
    """Parse an interval string like '5m', '1h', '30s', '2d' into seconds."""
    m = _INTERVAL_RE.match(s.strip())
    if not m:
        raise ValueError(f"Invalid interval {s!r}: expected a number followed by s/m/h/d")
    return int(m.group(1)) * _INTERVAL_UNITS[m.group(2)]


def _print_table(headers: list[str], rows: list[list]) -> None:
    """Print a plain fixed-width text table to stdout."""
    str_rows = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "  "
    fmt = sep.join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(sep.join("-" * w for w in widths))
    for row in str_rows:
        print(fmt.format(*row))


def _time_range(args: argparse.Namespace) -> tuple[int, int]:
    """Return (since_ts, until_ts) as Unix epoch integers.

    Defaults: since = start of current calendar month, until = now.
    """
    now = datetime.datetime.now().astimezone()
    since_dt = parse_dt(args.since) if args.since else now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    until_dt = parse_dt(args.until) if args.until else now
    return int(since_dt.timestamp()), int(until_dt.timestamp())


def _iface_filter(args: argparse.Namespace) -> tuple[str, list]:
    """Return an optional SQL WHERE fragment and its parameters for interface filtering."""
    if getattr(args, "interface", None):
        return "AND t.interface = ?", [args.interface]
    return "", []


def _port_filter(args: argparse.Namespace) -> tuple[str, list]:
    """Return an optional SQL WHERE fragment and its parameters for port filtering."""
    if getattr(args, "port", None) is not None:
        return "AND t.remote_port = ?", [args.port]
    return "", []


def _open_conn(args: argparse.Namespace) -> sqlite3.Connection:
    from .db import open_db

    return open_db(args.db)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_distill(args: argparse.Namespace) -> int:
    from .distiller import run_distiller

    run_distiller(
        base_dir=args.base_dir,
        db_path=args.db,
        delete_after=not args.no_delete,
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Total bandwidth summary grouped by process."""
    since_ts, until_ts = _time_range(args)
    iface_sql, iface_params = _iface_filter(args)

    conn = _open_conn(args)
    try:
        rows = conn.execute(
            f"""
            SELECT
                COALESCE(p.name, '(kernel)') AS process,
                SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in,
                SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out,
                SUM(t.bytes) AS total_bytes,
                SUM(t.packets) AS total_packets
            FROM traffic t
            LEFT JOIN process p ON t.process_id = p.id
            WHERE t.ts >= ? AND t.ts < ?
            {iface_sql}
            GROUP BY COALESCE(p.name, '(kernel)')
            ORDER BY total_bytes DESC
            """,
            [since_ts, until_ts, *iface_params],
        ).fetchall()
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "process": r[0],
                        "bytes_in": r[1],
                        "bytes_out": r[2],
                        "total_bytes": r[3],
                        "total_packets": r[4],
                    }
                    for r in rows
                ]
            )
        )
    else:
        _print_table(
            ["Process", "In", "Out", "Total", "Packets"],
            [[r[0], _format_bytes(r[1]), _format_bytes(r[2]), _format_bytes(r[3]), r[4]] for r in rows],
        )
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    """Ranked table of top consumers by process, host, or process+host."""
    since_ts, until_ts = _time_range(args)
    iface_sql, iface_params = _iface_filter(args)
    limit = args.limit
    by = args.by

    conn = _open_conn(args)
    try:
        if by == "process":
            rows = conn.execute(
                f"""
                SELECT
                    COALESCE(p.name, '(kernel)') AS process,
                    SUM(t.bytes) AS total_bytes,
                    SUM(t.packets) AS total_packets
                FROM traffic t
                LEFT JOIN process p ON t.process_id = p.id
                WHERE t.ts >= ? AND t.ts < ?
                {iface_sql}
                GROUP BY COALESCE(p.name, '(kernel)')
                ORDER BY total_bytes DESC
                LIMIT ?
                """,
                [since_ts, until_ts, *iface_params, limit],
            ).fetchall()
            headers = ["#", "Process", "Total", "Packets"]
            data_rows = [[i + 1, r[0], _format_bytes(r[1]), r[2]] for i, r in enumerate(rows)]
            json_rows = [
                {"rank": i + 1, "process": r[0], "total_bytes": r[1], "total_packets": r[2]} for i, r in enumerate(rows)
            ]

        elif by == "host":
            rows = conn.execute(
                f"""
                SELECT
                    COALESCE(h.hostname, h.ip, '(unknown)') AS host,
                    SUM(t.bytes) AS total_bytes,
                    SUM(t.packets) AS total_packets
                FROM traffic t
                LEFT JOIN host h ON t.host_id = h.id
                WHERE t.ts >= ? AND t.ts < ?
                {iface_sql}
                GROUP BY COALESCE(h.hostname, h.ip, '(unknown)')
                ORDER BY total_bytes DESC
                LIMIT ?
                """,
                [since_ts, until_ts, *iface_params, limit],
            ).fetchall()
            headers = ["#", "Host", "Total", "Packets"]
            data_rows = [[i + 1, r[0], _format_bytes(r[1]), r[2]] for i, r in enumerate(rows)]
            json_rows = [
                {"rank": i + 1, "host": r[0], "total_bytes": r[1], "total_packets": r[2]} for i, r in enumerate(rows)
            ]

        else:  # process+host
            rows = conn.execute(
                f"""
                SELECT
                    COALESCE(p.name, '(kernel)') AS process,
                    COALESCE(h.hostname, h.ip, '(unknown)') AS host,
                    SUM(t.bytes) AS total_bytes,
                    SUM(t.packets) AS total_packets
                FROM traffic t
                LEFT JOIN process p ON t.process_id = p.id
                LEFT JOIN host h ON t.host_id = h.id
                WHERE t.ts >= ? AND t.ts < ?
                {iface_sql}
                GROUP BY COALESCE(p.name, '(kernel)'), COALESCE(h.hostname, h.ip, '(unknown)')
                ORDER BY total_bytes DESC
                LIMIT ?
                """,
                [since_ts, until_ts, *iface_params, limit],
            ).fetchall()
            headers = ["#", "Process", "Host", "Total", "Packets"]
            data_rows = [[i + 1, r[0], r[1], _format_bytes(r[2]), r[3]] for i, r in enumerate(rows)]
            json_rows = [
                {
                    "rank": i + 1,
                    "process": r[0],
                    "host": r[1],
                    "total_bytes": r[2],
                    "total_packets": r[3],
                }
                for i, r in enumerate(rows)
            ]
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(json.dumps(json_rows))
    else:
        _print_table(headers, data_rows)
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    """Time-series bandwidth view in fixed-width buckets."""
    since_ts, until_ts = _time_range(args)
    bucket_secs = _parse_interval(args.interval)
    iface_sql, iface_params = _iface_filter(args)

    extra_joins = ""
    extra_where = ""
    extra_params: list = []

    if getattr(args, "process", None):
        extra_joins += " LEFT JOIN process p ON t.process_id = p.id"
        extra_where += " AND p.name = ?"
        extra_params.append(args.process)
    if getattr(args, "host", None):
        extra_joins += " LEFT JOIN host h ON t.host_id = h.id"
        extra_where += " AND (h.hostname = ? OR h.ip = ?)"
        extra_params.extend([args.host, args.host])
    port_sql, port_params = _port_filter(args)
    extra_where += f" {port_sql}"
    extra_params.extend(port_params)

    conn = _open_conn(args)
    try:
        rows = conn.execute(
            f"""
            SELECT
                (t.ts / ?) * ? AS bucket,
                SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in,
                SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out,
                SUM(t.bytes) AS total_bytes,
                SUM(t.packets) AS total_packets
            FROM traffic t
            {extra_joins}
            WHERE t.ts >= ? AND t.ts < ?
            {iface_sql}
            {extra_where}
            GROUP BY bucket
            ORDER BY bucket
            """,
            [bucket_secs, bucket_secs, since_ts, until_ts, *iface_params, *extra_params],
        ).fetchall()
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "time": datetime.datetime.fromtimestamp(r[0]).isoformat(),
                        "bytes_in": r[1],
                        "bytes_out": r[2],
                        "total_bytes": r[3],
                        "total_packets": r[4],
                    }
                    for r in rows
                ]
            )
        )
    else:
        _print_table(
            ["Time", "In", "Out", "Total", "Packets"],
            [
                [
                    datetime.datetime.fromtimestamp(r[0]).strftime("%Y-%m-%d %H:%M"),
                    _format_bytes(r[1]),
                    _format_bytes(r[2]),
                    _format_bytes(r[3]),
                    r[4],
                ]
                for r in rows
            ],
        )
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    """List the hosts that a given process connected to."""
    since_ts, until_ts = _time_range(args)
    iface_sql, iface_params = _iface_filter(args)
    port_sql, port_params = _port_filter(args)

    if args.process is None:
        proc_join = ""
        proc_filter = ""
        proc_params: list = []
    elif args.process == "(kernel)":
        proc_join = ""
        proc_filter = "AND t.process_id IS NULL"
        proc_params = []
    else:
        proc_join = "LEFT JOIN process p ON t.process_id = p.id"
        proc_filter = "AND p.name = ?"
        proc_params = [args.process]

    conn = _open_conn(args)
    try:
        rows = conn.execute(
            f"""
            SELECT
                COALESCE(h.hostname, h.ip, '(unknown)') AS host,
                SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in,
                SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out,
                SUM(t.bytes) AS total_bytes,
                SUM(t.packets) AS total_packets
            FROM traffic t
            {proc_join}
            LEFT JOIN host h ON t.host_id = h.id
            WHERE t.ts >= ? AND t.ts < ?
              {proc_filter}
            {iface_sql}
            {port_sql}
            GROUP BY COALESCE(h.hostname, h.ip, '(unknown)')
            ORDER BY total_bytes DESC
            """,
            [since_ts, until_ts, *proc_params, *iface_params, *port_params],
        ).fetchall()
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "host": r[0],
                        "bytes_in": r[1],
                        "bytes_out": r[2],
                        "total_bytes": r[3],
                        "total_packets": r[4],
                    }
                    for r in rows
                ]
            )
        )
    else:
        _print_table(
            ["Host", "In", "Out", "Total", "Packets"],
            [[r[0], _format_bytes(r[1]), _format_bytes(r[2]), _format_bytes(r[3]), r[4]] for r in rows],
        )
    return 0


def cmd_processes(args: argparse.Namespace) -> int:
    """List the processes that connected to a given host."""
    since_ts, until_ts = _time_range(args)
    iface_sql, iface_params = _iface_filter(args)
    port_sql, port_params = _port_filter(args)

    conn = _open_conn(args)
    try:
        rows = conn.execute(
            f"""
            SELECT
                COALESCE(p.name, '(kernel)') AS process,
                SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in,
                SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out,
                SUM(t.bytes) AS total_bytes,
                SUM(t.packets) AS total_packets
            FROM traffic t
            LEFT JOIN process p ON t.process_id = p.id
            LEFT JOIN host h ON t.host_id = h.id
            WHERE t.ts >= ? AND t.ts < ?
              AND (h.hostname = ? OR h.ip = ?)
            {iface_sql}
            {port_sql}
            GROUP BY COALESCE(p.name, '(kernel)')
            ORDER BY total_bytes DESC
            """,
            [since_ts, until_ts, args.host, args.host, *iface_params, *port_params],
        ).fetchall()
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "process": r[0],
                        "bytes_in": r[1],
                        "bytes_out": r[2],
                        "total_bytes": r[3],
                        "total_packets": r[4],
                    }
                    for r in rows
                ]
            )
        )
    else:
        _print_table(
            ["Process", "In", "Out", "Total", "Packets"],
            [[r[0], _format_bytes(r[1]), _format_bytes(r[2]), _format_bytes(r[3]), r[4]] for r in rows],
        )
    return 0


def cmd_ports(args: argparse.Namespace) -> int:
    """List the remote ports used, optionally filtered by process and/or host."""
    since_ts, until_ts = _time_range(args)
    iface_sql, iface_params = _iface_filter(args)

    extra_joins = ""
    extra_where = ""
    extra_params: list = []

    process = getattr(args, "process", None)
    host = getattr(args, "host", None)

    if process is not None:
        if process == "(kernel)":
            extra_where += " AND t.process_id IS NULL"
        else:
            extra_joins += " LEFT JOIN process p ON t.process_id = p.id"
            extra_where += " AND p.name = ?"
            extra_params.append(process)
    if host is not None:
        extra_joins += " LEFT JOIN host h ON t.host_id = h.id"
        extra_where += " AND (h.hostname = ? OR h.ip = ?)"
        extra_params.extend([host, host])

    conn = _open_conn(args)
    try:
        rows = conn.execute(
            f"""
            SELECT
                t.remote_port AS port,
                SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in,
                SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out,
                SUM(t.bytes) AS total_bytes,
                SUM(t.packets) AS total_packets
            FROM traffic t
            {extra_joins}
            WHERE t.ts >= ? AND t.ts < ?
              AND t.remote_port IS NOT NULL
            {iface_sql}
            {extra_where}
            GROUP BY t.remote_port
            ORDER BY total_bytes DESC
            """,
            [since_ts, until_ts, *iface_params, *extra_params],
        ).fetchall()
    finally:
        conn.close()

    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "port": r[0],
                        "bytes_in": r[1],
                        "bytes_out": r[2],
                        "total_bytes": r[3],
                        "total_packets": r[4],
                    }
                    for r in rows
                ]
            )
        )
    else:
        _print_table(
            ["Port", "In", "Out", "Total", "Packets"],
            [[r[0], _format_bytes(r[1]), _format_bytes(r[2]), _format_bytes(r[3]), r[4]] for r in rows],
        )
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def add_time_args(parser: argparse.ArgumentParser) -> None:
    """Add --since / --until arguments (with all common aliases) to a subparser."""
    since_group = parser.add_mutually_exclusive_group()
    since_group.add_argument(
        "--since",
        "--from",
        "--after",
        "--begin",
        "--start",
        dest="since",
        metavar="DATE",
        help="Start of time range (ISO 8601, 'yesterday', '-2h', 'Friday', …)",
    )
    until_group = parser.add_mutually_exclusive_group()
    until_group.add_argument(
        "--until",
        "--to",
        "--before",
        "--end",
        dest="until",
        metavar="DATE",
        help="End of time range (default: now)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bw-meter",
        description="Bandwidth metering CLI — dig into accumulated traffic statistics.",
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="SQLite database path (default: ~/.local/share/bw-meter/bw-meter.db)",
    )
    parser.add_argument(
        "--interface",
        "-i",
        metavar="IFACE",
        help="Filter to a specific interface (default: all metered interfaces from config)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output in machine-readable JSON format",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # distill
    p_distill = sub.add_parser("distill", help="Process raw pcapng captures into SQLite")
    p_distill.add_argument(
        "--base-dir",
        type=Path,
        default=Path("/var/lib/bw-meter"),
        metavar="DIR",
        help="Root directory containing per-interface pcapng capture subdirectories",
    )
    p_distill.add_argument(
        "--no-delete",
        action="store_true",
        help="Keep raw pcapng files after processing (default: delete)",
    )
    p_distill.set_defaults(func=cmd_distill)

    # report
    p_report = sub.add_parser("report", help="Total bandwidth spending summary")
    add_time_args(p_report)
    p_report.set_defaults(func=cmd_report)

    # top
    p_top = sub.add_parser("top", help="Ranked table of top consumers")
    add_time_args(p_top)
    p_top.add_argument(
        "--by",
        choices=["process", "host", "process+host"],
        default="process",
        help="Grouping dimension (default: process)",
    )
    p_top.add_argument("--limit", "-n", type=int, default=20, metavar="N")
    p_top.set_defaults(func=cmd_top)

    # timeline
    p_tl = sub.add_parser("timeline", help="Time-series bandwidth view")
    add_time_args(p_tl)
    p_tl.add_argument(
        "--interval",
        default="5m",
        metavar="INTERVAL",
        help="Bucket size, e.g. 1m, 5m, 1h (default: 5m)",
    )
    p_tl.add_argument("--process", metavar="NAME", help="Filter to a specific process name")
    p_tl.add_argument("--host", metavar="HOSTNAME", help="Filter to a specific hostname or IP")
    p_tl.add_argument("--port", metavar="PORT", type=int, help="Filter to a specific remote port")
    p_tl.set_defaults(func=cmd_timeline)

    # hosts
    p_hosts = sub.add_parser("hosts", help="Hosts by bandwidth usage, optionally filtered by process")
    add_time_args(p_hosts)
    p_hosts.add_argument(
        "--process", metavar="NAME", help="Filter to a specific process name (use '(kernel)' for untagged traffic)"
    )
    p_hosts.add_argument("--port", metavar="PORT", type=int, help="Restrict to a specific remote port")
    p_hosts.set_defaults(func=cmd_hosts)

    # processes
    p_procs = sub.add_parser("processes", help="What processes connected to a given host?")
    add_time_args(p_procs)
    p_procs.add_argument("--host", metavar="HOSTNAME", required=True, help="Hostname or IP address")
    p_procs.add_argument("--port", metavar="PORT", type=int, help="Restrict to a specific remote port")
    p_procs.set_defaults(func=cmd_processes)

    # ports
    p_ports = sub.add_parser("ports", help="Port breakdown, optionally filtered by process and/or host")
    add_time_args(p_ports)
    p_ports.add_argument(
        "--process", metavar="NAME", help="Filter to a specific process name (use '(kernel)' for untagged traffic)"
    )
    p_ports.add_argument("--host", metavar="HOSTNAME", help="Filter to a specific hostname or IP")
    p_ports.set_defaults(func=cmd_ports)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
