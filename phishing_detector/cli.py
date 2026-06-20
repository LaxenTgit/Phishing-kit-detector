"""
hii btw

Exit codes:
    0 — SAFE / LOW
    1 — MEDIUM
    2 — HIGH
    3 — CRITICAL
   10 — usage / argument error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from phishing_detector import __version__
from phishing_detector.core import PhishingDetector
from phishing_detector.models import AnalysisResult, RiskLevel

_RESET = "" if os.getenv("NO_COLOR") else "\033[0m"
_BOLD  = "" if os.getenv("NO_COLOR") else "\033[1m"
_DIM   = "" if os.getenv("NO_COLOR") else "\033[2m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Modular phishing page analysis toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  phishing-detector https://suspicious.example.com
  phishing-detector https://suspicious.example.com -v
  phishing-detector https://suspicious.example.com -o json -f report.json
  phishing-detector --batch urls.txt -o json
        """,
    )
    parser.add_argument("url", nargs="?", help="Target URL to analyse")
    parser.add_argument(
        "--batch", "-b",
        metavar="FILE",
        help="Analyse multiple URLs from a newline-separated file",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--file", "-f",
        metavar="PATH",
        help="Write output to file (JSON mode only)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-module flag breakdown during scan",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=12,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 12)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"phishing-detector {__version__}",
    )
    return parser


def render_terminal(result: AnalysisResult) -> None:
    colour = result.level.color_code if hasattr(result.level, "color_code") else ""
    width  = 54

    print(f"\n{'═'*width}")
    print(f"  RISK REPORT")
    print(f"{'─'*width}")
    print(f"  URL      {_DIM}{result.url}{_RESET}")
    print(f"  Score    {_BOLD}{result.total_score}/100{_RESET}")
    print(f"  Level    {colour}{_BOLD}{result.level.value}{_RESET}")
    print(f"{'─'*width}")

    # Score breakdown table
    print(f"  {'Module':<10}  {'Raw':>5}  {'Weight':>7}  {'Contrib':>8}")
    print(f"  {'─'*10}  {'─'*5}  {'─'*7}  {'─'*8}")
    for b in result.breakdown:
        print(f"  {b.module:<10}  {b.raw_score:>5}  {b.weight:>7.0%}  {b.contribution:>8.1f}")

    print(f"{'─'*width}")
    print(f"  Flags ({len(result.all_flags)}):")
    if result.all_flags:
        for flag in result.all_flags:
            print(f"    {_DIM}•{_RESET} {flag}")
    else:
        print(f"    {_DIM}No significant indicators found.{_RESET}")
    print(f"{'═'*width}\n")


def exit_code_for(level: RiskLevel) -> int:
    return {"SAFE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(level.value, 0)


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.url and not args.batch:
        parser.print_help()
        return 10

    detector = PhishingDetector(verbose=args.verbose, timeout=args.timeout)
    results  = []

    # Collect URLs
    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.batch:
        try:
            with open(args.batch) as fh:
                urls.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            print(f"[✗] Batch file not found: {args.batch}", file=sys.stderr)
            return 10

    # Analyse
    max_exit = 0
    for url in urls:
        result = detector.analyze(url)
        results.append(result)

        if args.output == "terminal":
            render_terminal(result)

        code = exit_code_for(result.level)
        max_exit = max(max_exit, code)

    # JSON output
    if args.output == "json":
        payload = [r.to_dict() for r in results] if len(results) > 1 else results[0].to_dict()
        if args.file:
            os.makedirs(os.path.dirname(os.path.abspath(args.file)), exist_ok=True)
            with open(args.file, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            print(f"[+] Report saved → {args.file}")
        else:
            print(json.dumps(payload, indent=2, default=str))

    return max_exit


if __name__ == "__main__":
    sys.exit(main())
