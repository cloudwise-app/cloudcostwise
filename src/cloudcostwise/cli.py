"""`cloudcostwise` command line."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from cloudcostwise import __version__


def _port(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        n = 0
    if not 1024 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"{value!r} is not a port from 1024 to 65535")
    return n


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudcostwise",
        description="Find AWS waste locally with your own read-only credentials. Nothing is sent to CloudWise unless you choose to share a summary at the end.",
    )
    p.add_argument("--version", action="version", version=f"cloudcostwise {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan an AWS account for waste")
    s.add_argument("--demo", action="store_true",
                   help="print a recorded scan of a CloudWise test account (sample data, every identifier a "
                        "placeholder) instead of scanning: no AWS call, no credentials, no network, never shared. "
                        "Works with every --format and --anonymize; --profile and --regions are refused with it; "
                        "--no-cost-explorer, --no-exclude and --parallel have nothing to change and are ignored")
    s.add_argument("--emulator", action="store_true",
                   help="run a live scan of a fake AWS account in AWS Emulator on your machine (needs Docker): "
                        "starts the emulator (127.0.0.1 only, telemetry off) or reuses it, creates fake wasteful "
                        "resources, and runs the normal scan against them. Never uses your AWS credentials; "
                        "--profile, --regions and --demo are refused with it; Cost Explorer is always off and "
                        "--no-exclude and --parallel are ignored. Works with every --format and --anonymize; "
                        "never shared")
    s.add_argument("--emulator-port", type=_port, default=None, metavar="PORT",
                   help="port for --emulator on 127.0.0.1 (default 9397, or $CW_DEMO_EMULATOR_PORT)")
    s.add_argument("--emulator-down", action="store_true",
                   help="stop the emulator that --emulator started (its fake resources are gone) and exit")
    s.add_argument("--profile", help="AWS profile (default: the standard credential chain)")
    s.add_argument("--regions", help="comma-separated regions, or 'all' (default: us-east-1 plus your profile's region)")
    s.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    s.add_argument("--anonymize", action="store_true",
                   help="replace the account ID and the resource IDs, names and ARNs it recognizes with stable "
                        "placeholders (account-1, resource-1, ...); works with every --format. Anonymizing is "
                        "not complete: review the report before you send it")
    s.add_argument("--no-exclude", action="store_true",
                   help="ignore your exclude list (cloudcostwise exclude list) for this run and show every finding")
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
    g.add_argument("--last", action="store_true",
                   help="show the summary of your last scan (CLI or MCP) and send it only if you type y; "
                        "runs only in a terminal where you can type")
    ex = sub.add_parser("exclude", help="keep resources out of every scan: a local list that is never sent to CloudWise",
                        description="A local exclude list (~/.config/cloudcostwise/exclude.json). Every scan leaves out "
                                    "findings for the resources on it and says how many; `scan --no-exclude` ignores "
                                    "it for one run. A resource ID and a full ARN match each other. The list is "
                                    "never sent to CloudWise.")
    exs = ex.add_subparsers(dest="exclude_action", required=True)
    ea = exs.add_parser("add", help="leave a resource out of future scans")
    ea.add_argument("resource_id", metavar="RESOURCE_ID_OR_ARN", help="a resource ID or a full ARN; either form matches both")
    ea.add_argument("--reason", help="a note to yourself, shown by `exclude list`")
    exs.add_parser("list", help="show the excluded resources")
    er = exs.add_parser("remove", help="bring a resource back into scans")
    er.add_argument("resource_id", metavar="RESOURCE_ID_OR_ARN")
    sub.add_parser("mcp", help="run as an MCP server (stdio) for Claude Code, Codex and other assistants")
    return p


def _demo(args, render) -> int:
    """CLO-1057: print the recording. No credentials, no AWS, no network, no exclude list, no share offer."""
    from cloudcostwise import demo

    report = demo.load_report()
    if args.anonymize:
        from cloudcostwise.anonymize import anonymize_report

        report = anonymize_report(report)
    if args.format == "json":
        print(render.as_json(report))
    elif args.format == "markdown":
        print(render.as_markdown(report, emoji=sys.stdout.isatty(), verbose=args.verbose))
    else:
        print(render.as_table(report, verbose=args.verbose, emoji=sys.stdout.isatty()))
    return 0  # never share.offer: a demo result is never offered for sharing


def _emulator(args, render) -> int:
    """CLO-1116: a live scan of a fake account in AWS Emulator. Never the person's credentials, no exclude
    list, no share offer, nothing saved for `share --last`."""
    from cloudcostwise import emulator_demo as em

    port = args.emulator_port or em.default_port()

    def say(line: str) -> None:
        print(line, file=sys.stderr)

    try:
        if args.emulator_down:
            em.stop(port)
            print(f"AWS Emulator on port {port} stopped; its fake resources are gone.")
            return 0
        report = em.run(port, say)
    except em.DockerMissing as e:
        print(em.DOCKER_NEEDED.format(why=e), file=sys.stderr)
        return 1
    except em.Unsafe as e:
        print(f"cloudcostwise: stopped, {e}. Nothing was changed outside the local emulator.", file=sys.stderr)
        return 1
    except em.EmulatorError as e:
        print(f"cloudcostwise: {e}", file=sys.stderr)
        return 1
    shown = report
    if args.anonymize:
        from cloudcostwise.anonymize import anonymize_report

        shown = anonymize_report(report)
    if args.format == "json":
        print(render.as_json(shown))
    elif args.format == "markdown":
        print(render.as_markdown(shown, emoji=sys.stdout.isatty(), verbose=args.verbose))
    else:
        print(render.as_table(shown, verbose=args.verbose, emoji=sys.stdout.isatty()))
        again = f" --emulator-port {port}" if port != em.DEFAULT_PORT else ""
        print(f"Stop the emulator with: cloudcostwise scan --emulator-down{again}", file=sys.stderr)
    return 0  # never share.offer or save_last_summary: a fake account is never shared


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    # stderr always: on `mcp`, stdout carries the protocol and must stay clean.
    logging.basicConfig(level=logging.INFO if getattr(args, "verbose", False) else logging.ERROR,
                        stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "share":
        from cloudcostwise import share

        return share.command(args)

    if args.command == "exclude":
        from cloudcostwise import exclude

        return exclude.command(args)

    if args.command == "mcp":
        from cloudcostwise.mcp_server import serve

        serve()
        return 0

    from cloudcostwise import render

    if args.emulator or args.emulator_down:
        if args.demo or args.profile or args.regions:
            print("cloudcostwise: --emulator scans a fake account on your machine and never uses your AWS "
                  "credentials, so --demo, --profile and --regions do not apply. Drop them, or drop --emulator "
                  "to scan your account.", file=sys.stderr)
            return 2
        return _emulator(args, render)

    if args.demo:
        if args.profile or args.regions:
            print("cloudcostwise: --demo shows a recording and scans nothing, so --profile and --regions do not "
                  "apply. Drop them, or drop --demo to scan your account.", file=sys.stderr)
            return 2
        return _demo(args, render)

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
        print("note: the RI/Savings Plans checks (and one KMS spend read, only if an S3 bucket-key finding appears) call Cost Explorer, which AWS bills at "
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

    # CLO-931: the exclude list is read from disk now, before anything is shown, totalled or shared.
    # The share offer below gets this reduced report too: it counts what the user saw.
    # --anonymize still learns the excluded IDs (to scrub them from warnings) but prints none.
    if not args.no_exclude:
        from cloudcostwise import exclude

        report = exclude.apply(report)

    # CLO-929: --anonymize changes the printed report only. The share offer below keeps the un-anonymized
    # report (it reads four numbers off it and never an identifier).
    shown = report
    if args.anonymize:
        from cloudcostwise.anonymize import anonymize_report

        shown = anonymize_report(report)
    if args.format == "json":
        print(render.as_json(shown))
    elif args.format == "markdown":
        print(render.as_markdown(shown, emoji=sys.stdout.isatty(), verbose=args.verbose))
    else:
        print(render.as_table(shown, verbose=args.verbose, emoji=sys.stdout.isatty()))
    # CLO-824: after the results are out. Asks only a human at a terminal, or sends only on a
    # setting a human wrote; never raises, never fails the scan.
    from cloudcostwise import share

    # CLO-1055: the summary numbers, kept locally for `share --last` (never sent by themselves). Saved
    # first, so a send below can mark it; the send marks this scan's record only (by saved_at), never a
    # later scan's. The same reduced, un-anonymized report as the offer.
    saved_at = share.save_last_summary(report, "cli")
    share.offer(report, saved_at=saved_at)  # CLO-931: what the user saw (excluded findings are not counted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
