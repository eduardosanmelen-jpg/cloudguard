"""Command-line entry point:  python -m cloudguard  (or the `cloudguard` command)."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .report import to_console, to_html, to_json


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cloudguard", description="Scan an AWS account for security misconfigurations.")
    p.add_argument("--demo", action="store_true", help="scan a simulated, deliberately vulnerable account (no AWS needed)")
    p.add_argument("--profile", help="AWS CLI profile to use")
    p.add_argument("--regions", default="us-east-1", help="comma-separated regions (default: us-east-1)")
    p.add_argument("--html", metavar="FILE", help="write an HTML dashboard report")
    p.add_argument("--json", metavar="FILE", help="write a JSON report")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="exit 1 if any finding is at or above this severity (for CI pipelines)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"cloudguard {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s")
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    if args.demo:
        from .demo import run_demo
        result = run_demo(regions[0])
    else:
        from .scanner import scan
        result = scan(regions, profile=args.profile)

    print(to_console(result, color=sys.stdout.isatty()))
    if args.html:
        Path(args.html).write_text(to_html(result), encoding="utf-8")
        print(f"  HTML report -> {args.html}")
    if args.json:
        Path(args.json).write_text(to_json(result), encoding="utf-8")
        print(f"  JSON report -> {args.json}")

    if args.fail_on:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        threshold = order.index(args.fail_on)
        if any(order.index(f.severity.value) <= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
