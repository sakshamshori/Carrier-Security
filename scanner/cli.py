from __future__ import annotations

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from .browser_scanner import scan_record
from .domain_discovery import load_domain_map, parse_name_lines, prepare_candidates, write_prepared_csv
from .input import load_records, parse_text_records
from .models import MGARecord
from .reporting import scan_root, slugify, write_portfolio_summary, write_scan_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description="Collect technical tracking evidence from MGA websites for legal/compliance review.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="Run a portfolio scan from CSV or text input")
    run.add_argument("--input", required=True, help="CSV file, or text file with 'MGA Name | https://example.com' lines")
    run.add_argument("--output", default="data/scans", help="Output root folder")
    run.add_argument("--headful", action="store_true", help="Run Chromium with a visible browser")
    run.add_argument("--timeout-ms", type=int, default=int(os.getenv("SCANNER_TIMEOUT_MS", "30000")))
    run.add_argument("--post-consent-wait-ms", type=int, default=int(os.getenv("POST_CONSENT_WAIT_MS", "4000")))

    run_one = subcommands.add_parser("run-one", help="Run a scan for a single MGA URL")
    run_one.add_argument("--name", required=True)
    run_one.add_argument("--url", required=True)
    run_one.add_argument("--output", default="data/scans", help="Output root folder")
    run_one.add_argument("--headful", action="store_true", help="Run Chromium with a visible browser")
    run_one.add_argument("--timeout-ms", type=int, default=int(os.getenv("SCANNER_TIMEOUT_MS", "30000")))
    run_one.add_argument("--post-consent-wait-ms", type=int, default=int(os.getenv("POST_CONSENT_WAIT_MS", "4000")))

    parse_text = subcommands.add_parser("parse-text", help="Parse pasted text input into scan records")
    parse_text.add_argument("--text", required=True)

    prepare = subcommands.add_parser("prepare-input", help="Prepare scanner CSV from names and optional domains")
    prepare.add_argument("--names", required=True, help="Text file with 'MGA Name' or 'MGA Name | https://domain.com' lines")
    prepare.add_argument("--carrier", default="", help="Carrier/fronting carrier name")
    prepare.add_argument("--domain-map", help="Optional CSV with mga_name,url,domain_source,domain_confidence")
    prepare.add_argument("--output", required=True, help="Prepared CSV output path")
    prepare.add_argument(
        "--include-guesses",
        action="store_true",
        help="Include low-confidence heuristic domain guesses for manual confirmation. Guesses are not marked ready.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "parse-text":
        records = parse_text_records(args.text)
        for record in records:
            print(f"{record.mga_name},{record.url or ''}")
        return

    if args.command == "prepare-input":
        names_text = Path(args.names).read_text(encoding="utf-8-sig")
        names = parse_name_lines(names_text)
        domain_map = load_domain_map(args.domain_map)
        candidates = prepare_candidates(
            names,
            carrier_name=args.carrier or None,
            domain_map=domain_map,
            include_guesses=args.include_guesses,
        )
        output_path = write_prepared_csv(candidates, args.output, carrier_name=args.carrier or None)
        ready = sum(1 for candidate in candidates if candidate.domain_status == "ready_to_scan")
        needs_review = len(candidates) - ready
        print(f"Wrote prepared input: {output_path}")
        print(f"Ready to scan: {ready}; needs confirmation/research: {needs_review}")
        return

    if args.command == "run-one":
        records = [MGARecord(mga_name=args.name, url=args.url)]
    else:
        records = load_records(args.input)

    output_root = Path(args.output)
    root = scan_root(output_root)
    results = []
    for record in records:
        mga_dir = root / slugify(record.mga_name)
        print(f"Scanning {record.mga_name}: {record.url or 'missing URL'}")
        result = scan_record(
            record,
            output_dir=mga_dir,
            timeout_ms=args.timeout_ms,
            post_consent_wait_ms=args.post_consent_wait_ms,
            headless=not args.headful,
        )
        write_scan_files(result, output_root)
        results.append(result)

    summary_path = write_portfolio_summary(results, output_root)
    print(f"Wrote portfolio summary: {summary_path}")
