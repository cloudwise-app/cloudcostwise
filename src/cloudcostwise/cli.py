"""`cloudcostwise` command line."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from cloudcostwise import __version__


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudcostwise",
        description="Find AWS waste locally with your own read-only credentials. Nothing is sent to CloudWise unless you choose to share a summary at the end.",
    )
    p.add_argument("--version", action="version", version=f"cloudcostwise {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan an AWS account for waste")
    s.add_argument("--profile", help="AWS profile (default: the standard credential chain)")
    s.add_argument("--regions", help="comma-separated regions, or 'all' (default: us-east-1 plus your profile's region)")
    s.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    s.add_argument("--no-cost-explorer", action="store_true",
                   help="make no Cost Explorer call ($0.01 per request): skips the RI/Savings Plans checks")
    s.add_argument("--parallel", type=int, default=4, metavar="N",
                   help="regions scanned at once, each in its own process (default 4; 1 = one at a time)")
    s.add_argument("--verbose", "-v", action="store_true", help="show data warnings and engine logs")
    sh = sub.add_parser("share", help="opt in or out of sharing a scan summary with CloudWise (off unless you say yes)")
    g = sh.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true", help="share a summary after each scan (needs an interactive terminal)")
    g.add_argument("--off", action="store_true", help="never share, never ask")
    g.add_argument("--status", action="store_true", help="show the current setting (default)")
    g.add_argument("--reset", action="store_true", help="forget the answer; ask once more in an interactive terminal")
    sub.add_parser("mcp", help="run as an MCP server (stdio) for Claude Code, Codex and other assistants")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    # stderr always: on `mcp`, stdout carries the protocol and must stay clean.
    logging.basicConfig(level=logging.INFO if getattr(args, "verbose", False) else logging.ERROR,
                        stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "share":
        from cloudcostwise import share

        return share.command(args)

    if args.command == "mcp":
        from cloudcostwise.mcp_server import serve

        serve()
        return 0

    from cloudcostwise import render
    from cloudcostwise.runtime import (
        COST_EXPLORER_PRICE_PER_REQUEST, CredentialsError, ReadOnlyViolation, configure_local_runtime,
        resolve_credentials, resolve_regions,
    )
    from cloudcostwise.scan import global_checks_warning, run_scan

    configure_local_runtime()
    try:
        creds = resolve_credentials(args.profile)
        regions = resolve_regions(args.regions, creds)
    except CredentialsError as e:
        print(f"cloudcostwise: {e}", file=sys.stderr)
        return 1

    # CLO-817: the account-level checks run only from us-east-1. Scanning it just
    # for them would also run its regional checks on a Region the user left
    # out, so say what is skipped, from the engine this scan really uses.
    skipped = global_checks_warning(regions, include_cost_explorer=not args.no_cost_explorer)
    if skipped:
        print(skipped, file=sys.stderr)

    if not args.no_cost_explorer and args.format == "table":
        print("note: the RI/Savings Plans checks call Cost Explorer, which AWS bills at "
              f"${COST_EXPLORER_PRICE_PER_REQUEST:.2f} per request (a few cents a scan). "
              "Add --no-cost-explorer to skip them.", file=sys.stderr)

    done = 0
    print(f"scanning {len(regions)} region(s), {min(max(args.parallel, 1), len(regions))} at a time ...",
          file=sys.stderr)

    from cloudcostwise import board as board_mod

    # CLO-858: a live board on an interactive stderr; anywhere else, today's plain lines. JSON keeps them too.
    live = None
    if args.format != "json" and board_mod.wants_board(sys.stderr):
        live = board_mod.RegionBoard(regions, args.parallel, sys.stderr)
        live.draw()

    def progress(res) -> None:
        nonlocal done
        done += 1
        if live is not None:
            live.region_done(res)
            return
        print(f"  [{done}/{len(regions)}] {res.region:<15} {len(res.findings):>3} finding(s)  {res.seconds:>5.1f}s",
              file=sys.stderr)

    try:
        report = run_scan(creds, regions, include_cost_explorer=not args.no_cost_explorer, on_region=progress,
                          parallel=args.parallel, with_spend=True)
    except ReadOnlyViolation as e:
        print(f"cloudcostwise: stopped, {e}. Please report this: it is a bug.", file=sys.stderr)
        return 3

    if args.format == "json":
        print(render.as_json(report))
    elif args.format == "markdown":
        print(render.as_markdown(report, emoji=sys.stdout.isatty()))
    else:
        print(render.as_table(report, verbose=args.verbose, emoji=sys.stdout.isatty()))
    # CLO-824: after the results are out. Asks only a human at a terminal, or sends only on a
    # setting a human wrote; never raises, never fails the scan.
    from cloudcostwise import share

    share.offer(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
