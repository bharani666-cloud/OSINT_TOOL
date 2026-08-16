#!/usr/bin/env python3
"""
Authorized OSINT Tool - CLI entry point.

    AUTHORIZED OSINT TOOL
    Use only for lawful investigations and systems/data you are authorized to access.
    This tool does not bypass privacy controls or retrieve private information.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from config import BANNER, CASES_ROOT
from models import CollectionResult
from collectors.dns import DNSCollector
from collectors.email import EmailCollector
from collectors.phone import PhoneCollector
from collectors.username import UsernameCollector
from collectors.social import SocialCollector
from reporting.json_report import write_json_report
from reporting.csv_report import write_csv_report
from reporting.html_report import write_html_report
from utils.logging_utils import setup_logging
from utils.validation import sanitize_case_id, ValidationError, is_valid_public_url

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()
    _COLOR = True
except ImportError:  # pragma: no cover
    _COLOR = False

    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = Style = _NoColor()


def _status(msg: str, kind: str = "info") -> None:
    colors = {"info": Fore.CYAN, "ok": Fore.GREEN, "warn": Fore.YELLOW, "err": Fore.RED}
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}
    color = colors.get(kind, "")
    reset = Style.RESET_ALL if _COLOR else ""
    print(f"{color}{prefix.get(kind, '[*]')} {msg}{reset}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint.py",
        description="Authorized OSINT information-gathering tool for lawful investigations.",
    )
    parser.add_argument("--case", required=True, help="Case / reference ID for this investigation")
    parser.add_argument("--reference", default=None, help="Optional free-text reference / legal note for the case")

    parser.add_argument("--username", help="Username to search across allow-listed public sources")
    parser.add_argument("--profile", help="A public profile URL supplied by the investigator")
    parser.add_argument("--domain", help="Domain to run DNS/WHOIS recon on")
    parser.add_argument("--email", help="Publicly disclosed / investigator-supplied email address")
    parser.add_argument("--phone", help="Publicly disclosed / investigator-supplied phone number (E.164 preferred)")

    parser.add_argument("--json", action="store_true", help="Write a JSON report")
    parser.add_argument("--csv", action="store_true", help="Write a CSV report")
    parser.add_argument("--html", action="store_true", help="Write an HTML report")
    parser.add_argument("--verbose", action="store_true", help="Verbose console logging")
    return parser


def ensure_case_dirs(case_id: str) -> dict[str, Path]:
    case_dir = CASES_ROOT / case_id
    dirs = {
        "case": case_dir,
        "raw": case_dir / "raw",
        "reports": case_dir / "reports",
        "evidence": case_dir / "evidence",
        "logs": case_dir / "logs",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    print()

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        case_id = sanitize_case_id(args.case)
    except ValidationError as exc:
        _status(str(exc), "err")
        return 2

    if not any([args.username, args.profile, args.domain, args.email, args.phone]):
        _status("Provide at least one of --username, --profile, --domain, --email, --phone", "err")
        return 2

    if args.profile and not is_valid_public_url(args.profile):
        _status(f"'{args.profile}' is not a valid http(s) URL", "err")
        return 2

    dirs = ensure_case_dirs(case_id)
    logger = setup_logging(dirs["logs"], verbose=args.verbose)
    logger.info("Starting authorized OSINT collection for case '%s'", case_id)

    inputs: dict[str, str] = {}
    aggregate = CollectionResult()

    jobs = []
    if args.username:
        inputs["username"] = args.username
        jobs.append(("Username correlation search", UsernameCollector(case_id), args.username))
        jobs.append(("Social media (public API)", SocialCollector(case_id), args.username))
    if args.domain:
        inputs["domain"] = args.domain
        jobs.append(("Domain / DNS recon", DNSCollector(case_id), args.domain))
    if args.email:
        inputs["email"] = args.email
        jobs.append(("Email information", EmailCollector(case_id), args.email))
    if args.phone:
        inputs["phone"] = args.phone
        jobs.append(("Phone metadata", PhoneCollector(case_id), args.phone))
    if args.profile:
        inputs["profile_url"] = args.profile
        parsed = urlparse(args.profile)
        inputs["profile_domain"] = parsed.netloc
        jobs.append(("Domain recon for supplied profile host", DNSCollector(case_id), parsed.netloc))

    for label, collector, target in jobs:
        _status(f"Running: {label} ({target})", "info")
        try:
            outcome = collector.collect(target)
        except Exception as exc:  # collectors should not crash the whole run
            logger.exception("Collector %s failed", collector.name)
            _status(f"{label} failed: {exc}", "err")
            continue
        aggregate.extend(outcome)
        _status(f"{label}: {len(outcome.findings)} finding(s), {len(outcome.errors)} error(s)", "ok")

    # Always persist the raw combined result as JSON in raw/, regardless of --json flag.
    raw_path = dirs["raw"] / "collection_raw.json"
    write_json_report(raw_path, case_id, inputs, aggregate, args.reference)

    produced = []
    if args.json:
        p = write_json_report(dirs["reports"] / "report.json", case_id, inputs, aggregate, args.reference)
        produced.append(p)
    if args.csv:
        p = write_csv_report(dirs["reports"] / "report.csv", aggregate)
        produced.append(p)
    if args.html:
        p = write_html_report(dirs["reports"] / "report.html", case_id, inputs, aggregate, args.reference)
        produced.append(p)

    print()
    _status("Collection summary", "info")
    print(f"    Sources queried : {aggregate.sources_queried}")
    print(f"    Findings         : {len(aggregate.findings)}")
    print(f"    Errors            : {len(aggregate.errors)}")
    print(f"    Case directory     : {dirs['case']}")
    for p in produced:
        _status(f"Report written: {p}", "ok")
    if not produced:
        _status("No --json/--csv/--html flag given; raw data still saved to raw/collection_raw.json", "warn")

    logger.info("Collection complete for case '%s'", case_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
