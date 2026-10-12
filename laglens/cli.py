"""Command line interface (BUILD_PLAN §3.7).

``main()`` parses the arguments and dispatches to the ``cmd_*`` functions in
:mod:`laglens.app`. Commands whose implementation module does not exist yet
print ``not implemented yet`` and exit with status 2.
"""
import argparse
import sys
from typing import List, Optional

from laglens.version import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_IMPLEMENTED = 2
EXIT_INTERRUPTED = 130

PACKS = ("full", "comcast")


def build_parser() -> argparse.ArgumentParser:
    """The argument parser with every command/flag of BUILD_PLAN §3.7."""
    p = argparse.ArgumentParser(
        prog="start.sh",
        description="Lag Lens: watch your home network and find out where the lag comes from.",
        epilog=(
            "Default command: run (fast doctor, then monitor). "
            "One-shot commands: --doctor, --selftest, --report, --export, --index, --loadtest, "
            "--docsis-dump, --update, --stop, --version."
        ),
    )
    p.add_argument("--version", action="store_true", help="print the version and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--config", metavar="PATH", default=None, help="config file (default: config.json next to run.py)")

    cmds = p.add_argument_group("commands (default: run)")
    cmds.add_argument("--doctor", action="store_true", help="print the full doctor table and exit")
    cmds.add_argument("--no-net", action="store_true", help="with --doctor: skip checks that send packets")
    cmds.add_argument("--selftest", action="store_true", help="run the offline unit tests and loopback checks")
    cmds.add_argument("--report", metavar="DIR", default=None, help="rebuild report.html for a session directory")
    cmds.add_argument("--export", metavar="DIR", default=None, help="write the export ZIP for a session directory")
    cmds.add_argument("--pack", choices=PACKS, default="full", help="with --export: pack to build (default full)")
    cmds.add_argument("--index", action="store_true", help="rebuild sessions/index.html")
    cmds.add_argument("--loadtest", action="store_true", help="headless 95 s load test; prints the result")
    cmds.add_argument("--docsis-dump", action="store_true", help="save the raw XB7 pages and print recognised tables")
    cmds.add_argument("--update", action="store_true", help="download and install the latest release")
    cmds.add_argument("--check", action="store_true", help="with --update: only check for a newer version")
    cmds.add_argument("--stop", action="store_true", help="stop the running instance (via its pidfile)")

    run = p.add_argument_group("run options")
    run.add_argument("--port", type=int, default=None, metavar="N", help="dashboard port (default 8787)")
    run.add_argument("--no-browser", action="store_true", help="do not open the dashboard in a browser")
    run.add_argument("--label", default=None, metavar="TEXT", help="experiment label stored with the session")
    run.add_argument("--xbox", default=None, metavar="IP", help="Xbox LAN address (skips discovery)")
    run.add_argument("--no-docsis", action="store_true", help="disable the XB7 modem scraper")
    run.add_argument("--no-igd", action="store_true", help="disable the UPnP IGD collector")
    run.add_argument("--resume", metavar="DIR", default=None, help="append to an existing session directory")
    return p


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point used by ``run.py``; returns the process exit status."""
    args = parse_args(argv)
    if args.version:
        print(__version__)
        return EXIT_OK
    if args.port is not None and not (1 <= args.port <= 65535):
        print("error: --port must be 1-65535", file=sys.stderr)
        return EXIT_ERROR

    from laglens import app

    try:
        if args.doctor:
            return app.cmd_doctor(args)
        if args.selftest:
            return app.cmd_selftest(args)
        if args.report:
            return app.cmd_report(args)
        if args.export:
            return app.cmd_export(args)
        if args.index:
            return app.cmd_index(args)
        if args.loadtest:
            return app.cmd_loadtest(args)
        if args.docsis_dump:
            return app.cmd_docsis_dump(args)
        if args.update or args.check:
            return app.cmd_update(args)
        if args.stop:
            return app.cmd_stop(args)
        return app.cmd_run(args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


__all__ = ["build_parser", "parse_args", "main", "EXIT_OK", "EXIT_ERROR", "EXIT_NOT_IMPLEMENTED", "EXIT_INTERRUPTED"]
