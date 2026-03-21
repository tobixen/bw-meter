"""bw-meter command-line interface."""

import argparse
import sys
from pathlib import Path

import argcomplete

from ._version import __version__


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


def add_interface_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--interface",
        "-i",
        metavar="IFACE",
        help="Filter to a specific interface (default: all metered interfaces from config)",
    )


def cmd_distill(args: argparse.Namespace) -> int:
    from .distiller import run_distiller

    run_distiller(
        base_dir=args.base_dir,
        db_path=args.db,
        delete_after=not args.no_delete,
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    print("bw-meter report: not yet implemented")
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    print("bw-meter top: not yet implemented")
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    print("bw-meter timeline: not yet implemented")
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    print("bw-meter hosts: not yet implemented")
    return 0


def cmd_processes(args: argparse.Namespace) -> int:
    print("bw-meter processes: not yet implemented")
    return 0


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
    p_tl.add_argument("--interval", default="5m", metavar="INTERVAL", help="Bucket size, e.g. 1m, 5m, 1h (default: 5m)")
    p_tl.add_argument("--process", metavar="NAME", help="Filter to a specific process name")
    p_tl.add_argument("--host", metavar="HOSTNAME", help="Filter to a specific hostname")
    p_tl.set_defaults(func=cmd_timeline)

    # hosts
    p_hosts = sub.add_parser("hosts", help="What hosts did a given process connect to?")
    add_time_args(p_hosts)
    p_hosts.add_argument("--process", metavar="NAME", required=True)
    p_hosts.set_defaults(func=cmd_hosts)

    # processes
    p_procs = sub.add_parser("processes", help="What processes connected to a given host?")
    add_time_args(p_procs)
    p_procs.add_argument("--host", metavar="HOSTNAME", required=True)
    p_procs.set_defaults(func=cmd_processes)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
