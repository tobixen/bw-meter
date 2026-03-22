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

VALID_DIMENSIONS = ("process", "host", "ip", "port", "interface", "protocol", "direction", "time")
VALID_SHOW = ("in", "out", "total", "packets")

# SQL expression for each dimension (excluding "time", which is dynamic)
_DIM_SELECT = {
    "process": "COALESCE(p.name, '(kernel)')",
    "host": "COALESCE(h.hostname, h.ip, '(unknown)')",
    "ip": "COALESCE(h.ip, '(unknown)')",
    "port": "t.remote_port",
    "interface": "t.interface",
    "protocol": "t.protocol",
    "direction": "t.direction",
}

# JOIN needed for each dimension (None = no extra join required)
_DIM_JOIN = {
    "process": "LEFT JOIN process p ON t.process_id = p.id",
    "host": "LEFT JOIN host h ON t.host_id = h.id",
    "ip": "LEFT JOIN host h ON t.host_id = h.id",
    "port": None,
    "interface": None,
    "protocol": None,
    "direction": None,
    "time": None,
}

_DIM_HEADER = {
    "process": "Process",
    "host": "Host",
    "ip": "IP",
    "port": "Port",
    "interface": "Interface",
    "protocol": "Protocol",
    "direction": "Direction",
    "time": "Time",
}

# Measures are always computed in fixed order; indices are n_dims + {0,1,2,3}
_MEASURE_IDX = {"in": 0, "out": 1, "total": 2, "packets": 3}

_SHOW_HEADER = {"in": "In", "out": "Out", "total": "Total", "packets": "Packets"}

_SHOW_JSON_KEY = {
    "in": "bytes_in",
    "out": "bytes_out",
    "total": "total_bytes",
    "packets": "total_packets",
}

_SORT_TO_ALIAS = {
    "in": "bytes_in",
    "out": "bytes_out",
    "total": "total_bytes",
    "packets": "total_packets",
    "time": "time_bucket",
}


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
    """Unified reporting command: group, filter, and sort traffic data."""
    since_ts, until_ts = _time_range(args)

    # --- Validate --group-by ---
    group_by: list[str] = [d.strip().lower() for d in args.group_by.split(",")]
    for dim in group_by:
        if dim not in VALID_DIMENSIONS:
            print(f"error: unknown dimension {dim!r}; valid: {', '.join(VALID_DIMENSIONS)}", file=sys.stderr)
            return 1

    # --- Validate --show ---
    show_cols: list[str] = [c.strip().lower() for c in args.show.split(",")]
    for col in show_cols:
        if col not in VALID_SHOW:
            print(f"error: unknown show column {col!r}; valid: {', '.join(VALID_SHOW)}", file=sys.stderr)
            return 1

    # --- Interval for time bucketing ---
    bucket_secs: int | None = None
    if "time" in group_by:
        bucket_secs = _parse_interval(args.interval)

    # --- Sort column and direction ---
    sort = args.sort
    if sort is None:
        sort = "time" if "time" in group_by else "total"
    if sort == "time" and "time" not in group_by:
        print("error: --sort time requires 'time' in --group-by", file=sys.stderr)
        return 1
    order_col = _SORT_TO_ALIAS[sort]
    order_dir = "ASC" if sort == "time" else "DESC"

    # --- Build JOIN set (deduplicated) ---
    seen_joins: set[str] = set()
    joins: list[str] = []

    def _add_join(j: str | None) -> None:
        if j and j not in seen_joins:
            joins.append(j)
            seen_joins.add(j)

    # --- SELECT and GROUP BY expressions for dimensions ---
    dim_selects: list[str] = []
    dim_groups: list[str] = []

    for dim in group_by:
        if dim == "time":
            expr = f"(t.ts / {bucket_secs}) * {bucket_secs}"
            dim_selects.append(f"{expr} AS time_bucket")
            dim_groups.append(expr)
        else:
            sel = _DIM_SELECT[dim]
            dim_selects.append(f"{sel} AS {dim}")
            dim_groups.append(sel)
            _add_join(_DIM_JOIN[dim])

    # Always compute all four measures (needed for ORDER BY and future show options)
    measures_sql = [
        "SUM(CASE WHEN t.direction='in'  THEN t.bytes ELSE 0 END) AS bytes_in",
        "SUM(CASE WHEN t.direction='out' THEN t.bytes ELSE 0 END) AS bytes_out",
        "SUM(t.bytes) AS total_bytes",
        "SUM(t.packets) AS total_packets",
    ]

    # --- WHERE clauses ---
    where_clauses: list[str] = ["t.ts >= ?", "t.ts < ?"]
    params: list = [since_ts, until_ts]

    if getattr(args, "interface", None):
        where_clauses.append("t.interface = ?")
        params.append(args.interface)

    process = getattr(args, "process", None)
    if process is not None:
        if process == "(kernel)":
            where_clauses.append("t.process_id IS NULL")
        else:
            _add_join(_DIM_JOIN["process"])
            where_clauses.append("p.name = ?")
            params.append(process)

    host = getattr(args, "host", None)
    if host is not None:
        _add_join(_DIM_JOIN["host"])
        where_clauses.append("(h.hostname = ? OR h.ip = ?)")
        params.extend([host, host])

    port = getattr(args, "port", None)
    if port is not None:
        where_clauses.append("t.remote_port = ?")
        params.append(port)

    # When grouping by port, exclude NULL remote_port rows
    if "port" in group_by:
        where_clauses.append("t.remote_port IS NOT NULL")

    # --- LIMIT ---
    limit = getattr(args, "limit", None)
    limit_clause = f"LIMIT {limit}" if limit else ""

    # --- Assemble SQL ---
    all_selects = dim_selects + measures_sql
    joins_sql = "\n        ".join(joins)
    where_sql = "\n          AND ".join(where_clauses)
    groups_sql = ", ".join(dim_groups)

    sql = f"""
        SELECT {", ".join(all_selects)}
        FROM traffic t
        {joins_sql}
        WHERE {where_sql}
        GROUP BY {groups_sql}
        ORDER BY {order_col} {order_dir}
        {limit_clause}
    """

    conn = _open_conn(args)
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    n_dims = len(group_by)

    if getattr(args, "json", False):
        result = []
        for row in rows:
            obj: dict = {}
            for i, dim in enumerate(group_by):
                val = row[i]
                if dim == "time" and val is not None:
                    val = datetime.datetime.fromtimestamp(val).isoformat()
                obj[dim] = val
            for col in show_cols:
                obj[_SHOW_JSON_KEY[col]] = row[n_dims + _MEASURE_IDX[col]]
            result.append(obj)
        print(json.dumps(result))
    else:
        headers = [_DIM_HEADER[dim] for dim in group_by] + [_SHOW_HEADER[col] for col in show_cols]
        table_rows = []
        for row in rows:
            cells: list = []
            for i, dim in enumerate(group_by):
                val = row[i]
                if dim == "time":
                    val = (
                        datetime.datetime.fromtimestamp(val).strftime("%Y-%m-%d %H:%M")
                        if val is not None
                        else "(unknown)"
                    )
                elif val is None:
                    val = "(unknown)"
                cells.append(val)
            for col in show_cols:
                val = row[n_dims + _MEASURE_IDX[col]] or 0
                cells.append(_format_bytes(val) if col in ("in", "out", "total") else val)
            table_rows.append(cells)
        _print_table(headers, table_rows)

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
    p_report = sub.add_parser(
        "report",
        help="Query and report traffic data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Query traffic data with flexible grouping, filtering, and sorting.

Examples:
  bw-meter report                                  # by process, current month
  bw-meter report --group-by host                  # by remote host
  bw-meter report --group-by process,host          # cross-tabulate
  bw-meter report --group-by time --interval 1h    # hourly timeline
  bw-meter report --group-by host --process curl   # hosts used by curl
  bw-meter report --group-by process --host api.anthropic.com
  bw-meter report --group-by port --show total
  bw-meter report --group-by process --show in,out,total,packets
""",
    )
    add_time_args(p_report)
    p_report.add_argument(
        "--group-by",
        default="process",
        metavar="DIMS",
        help=("Comma-separated grouping dimensions: " + ", ".join(VALID_DIMENSIONS) + " (default: process)"),
    )
    p_report.add_argument(
        "--interval",
        default="1h",
        metavar="INTERVAL",
        help="Time bucket size when 'time' is in --group-by, e.g. 5m, 1h, 1d (default: 1h)",
    )
    p_report.add_argument(
        "--show",
        default="in,out,total",
        metavar="COLS",
        help="Comma-separated measure columns: in, out, total, packets (default: in,out,total)",
    )
    p_report.add_argument(
        "--sort",
        choices=["total", "in", "out", "packets", "time"],
        default=None,
        help="Sort order (default: 'time' when grouped by time, else 'total')",
    )
    p_report.add_argument(
        "--limit",
        "-n",
        type=int,
        metavar="N",
        help="Maximum number of rows to display",
    )
    p_report.add_argument(
        "--process",
        metavar="NAME",
        help="Filter to a specific process name (use '(kernel)' for untagged traffic)",
    )
    p_report.add_argument(
        "--host",
        metavar="HOSTNAME",
        help="Filter to a specific hostname or IP address",
    )
    p_report.add_argument(
        "--port",
        metavar="PORT",
        type=int,
        help="Filter to a specific remote port number",
    )
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
