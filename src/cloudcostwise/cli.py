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
        description="Find AWS waste locally with your own read-only credentials. Nothing is sent to CloudWise.",
    )
    p.add_argument("--version", action="version", version=f"cloudcostwise {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan an AWS account for waste")
    s.add_argument("--profile", help="AWS profile (default: the standard credential chain)")
    s.add_argument("--regions", help="comma-separated regions, or 'all' (default: us-east-1 plus your profile's region)")
    s.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    s.add_argument("--no-cost-explorer", action="store_true",
                   help="make no Cost Explorer call ($0.01 per request): skips the RI/Savings Plans checks; "
                        "extended-support surcharges fall back to estimates")
    s.add_argument("--parallel", type=int, default=4, metavar="N",
                   help="regions scanned at once, each in its own process (default 4; 1 = one at a time)")
    s.add_argument("--verbose", "-v", action="store_true", help="show data warnings and engine logs")
    sub.add_parser("mcp", help="run as an MCP server (stdio) for Claude Code, Codex and other assistants")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    # stderr always: on `mcp`, stdout carries the protocol and must stay clean.
    logging.basicConfig(level=logging.INFO if getattr(args, "verbose", False) else logging.ERROR,
                        stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "mcp":
        from cloudcostwise.mcp_server import serve

        serve()
        return 0

    from cloudcostwise import render
    from cloudcostwise.runtime import (
        CredentialsError, ReadOnlyViolation, configure_local_runtime, resolve_credentials, resolve_regions,
    )
    from cloudcostwise.scan import run_scan

    configure_local_runtime()
    try:
        creds = resolve_credentials(args.profile)
        regions = resolve_regions(args.regions, creds)
    except CredentialsError as e:
        print(f"cloudcostwise: {e}", file=sys.stderr)
        return 1

    if not args.no_cost_explorer and args.format == "table":
        print("note: the RI/Savings Plans checks call Cost Explorer, which AWS bills at $0.01 per "
              "request (about $0.13 a scan). Add --no-cost-explorer to skip them.", file=sys.stderr)

    done = 0
    print(f"scanning {len(regions)} region(s), {min(max(args.parallel, 1), len(regions))} at a time ...",
          file=sys.stderr)

    def progress(res) -> None:
        nonlocal done
        done += 1
        print(f"  [{done}/{len(regions)}] {res.region:<15} {len(res.findings):>3} finding(s)  {res.seconds:>5.1f}s",
              file=sys.stderr)

    try:
        report = run_scan(creds, regions, include_cost_explorer=not args.no_cost_explorer, on_region=progress,
                          parallel=args.parallel)
    except ReadOnlyViolation as e:
        print(f"cloudcostwise: stopped, {e}. Please report this: it is a bug.", file=sys.stderr)
        return 3

    if args.format == "json":
        print(render.as_json(report))
    elif args.format == "markdown":
        print(render.as_markdown(report))
    else:
        print(render.as_table(report, verbose=args.verbose))
    return 0


if __name__ == "__main__":
    sys.exit(main())
