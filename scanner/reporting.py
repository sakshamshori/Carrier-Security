from __future__ import annotations

import csv
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from .models import ScanResult

try:
    import pandas as pd
except ImportError:  # pragma: no cover - fallback for minimal environments
    pd = None


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "unknown-mga"


def scan_root(output_root: str | Path, scan_date: date | None = None) -> Path:
    day = scan_date or date.today()
    return Path(output_root) / day.isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_scan_files(result: ScanResult, output_root: str | Path, scan_date: date | None = None) -> ScanResult:
    root = scan_root(output_root, scan_date)
    mga_dir = root / slugify(result.mga_name)
    mga_dir.mkdir(parents=True, exist_ok=True)
    result.output_dir = str(mga_dir)

    if result.pre:
        write_json(mga_dir / "pre_consent_network.json", result.pre.network)
        write_json(mga_dir / "pre_consent_cookies.json", result.pre.cookies)
        write_json(mga_dir / "pre_consent_storage.json", result.pre.storage)
        write_json(mga_dir / "pre_consent_document_cookie.json", {"document_cookie": result.pre.document_cookie})
        write_json(
            mga_dir / "pre_consent_document_cookie_inventory.json",
            {"cookie_names": result.pre.document_cookie_inventory},
        )
        write_json(mga_dir / "pre_consent_cookie_name_matches.json", result.pre.cookie_name_matches)
        write_json(mga_dir / "pre_consent_network_signatures.json", result.pre.network_signature_matches)
        write_json(mga_dir / "pre_consent_har.json", result.pre.har)
    else:
        write_json(mga_dir / "pre_consent_network.json", [])
        write_json(mga_dir / "pre_consent_cookies.json", [])
        write_json(mga_dir / "pre_consent_storage.json", {})
        write_json(mga_dir / "pre_consent_document_cookie.json", {"document_cookie": ""})
        write_json(mga_dir / "pre_consent_document_cookie_inventory.json", {"cookie_names": []})
        write_json(mga_dir / "pre_consent_cookie_name_matches.json", [])
        write_json(mga_dir / "pre_consent_network_signatures.json", [])
        write_json(mga_dir / "pre_consent_har.json", {"log": {"version": "1.2-lite", "entries": []}})

    if result.post:
        write_json(mga_dir / "post_consent_network.json", result.post.network)
        write_json(mga_dir / "post_consent_cookies.json", result.post.cookies)
        write_json(mga_dir / "post_consent_storage.json", result.post.storage)
        write_json(mga_dir / "post_consent_document_cookie.json", {"document_cookie": result.post.document_cookie})
        write_json(
            mga_dir / "post_consent_document_cookie_inventory.json",
            {"cookie_names": result.post.document_cookie_inventory},
        )
        write_json(mga_dir / "post_consent_cookie_name_matches.json", result.post.cookie_name_matches)
        write_json(mga_dir / "post_consent_network_signatures.json", result.post.network_signature_matches)
        write_json(mga_dir / "post_consent_har.json", result.post.har)
        script_items = []
        if result.pre:
            script_items.extend(result.pre.scripts)
        script_items.extend(result.post.scripts)
        all_scripts = {script.get("url", ""): script for script in script_items}
        all_third_party = sorted(set((result.pre.third_party_domains if result.pre else []) + result.post.third_party_domains))
    else:
        write_json(mga_dir / "post_consent_network.json", [])
        write_json(mga_dir / "post_consent_cookies.json", [])
        write_json(mga_dir / "post_consent_storage.json", {})
        write_json(mga_dir / "post_consent_document_cookie.json", {"document_cookie": ""})
        write_json(mga_dir / "post_consent_document_cookie_inventory.json", {"cookie_names": []})
        write_json(mga_dir / "post_consent_cookie_name_matches.json", [])
        write_json(mga_dir / "post_consent_network_signatures.json", [])
        write_json(mga_dir / "post_consent_har.json", {"log": {"version": "1.2-lite", "entries": []}})
        all_scripts = {script.get("url", ""): script for script in (result.pre.scripts if result.pre else [])}
        all_third_party = result.pre.third_party_domains if result.pre else []

    write_json(mga_dir / "scripts.json", list(all_scripts.values()))
    write_json(mga_dir / "third_party_domains.json", all_third_party)
    write_json(mga_dir / "vendor_classification.json", result.vendor_classification)
    write_json(mga_dir / "audit_environment.json", result.audit_environment)
    write_json(mga_dir / "consent_detection.json", result.consent_detection)
    write_json(mga_dir / "request_level_pre_post_diff.json", result.request_level_diff)
    write_json(mga_dir / "manual_checklist_parity.json", result.manual_checklist_parity)
    write_json(mga_dir / "scan_summary.json", scan_summary(result))
    return result


def scan_summary(result: ScanResult) -> dict[str, Any]:
    return {
        "mga_name": result.mga_name,
        "url": result.url,
        "scan_status": result.scan_status,
        "consent_status": result.consent_status,
        "output_dir": result.output_dir,
        "error": result.error,
        "pre_consent_third_party_count": len(result.pre.third_party_domains) if result.pre else 0,
        "post_consent_third_party_count": len(result.post.third_party_domains) if result.post else 0,
        "pre_consent_cookie_count": len(result.pre.cookies) if result.pre else 0,
        "post_consent_cookie_count": len(result.post.cookies) if result.post else 0,
        "pre_consent_cookie_name_matches": result.pre.cookie_name_matches if result.pre else [],
        "post_consent_cookie_name_matches": result.post.cookie_name_matches if result.post else [],
        "pre_consent_document_cookie_inventory": result.pre.document_cookie_inventory if result.pre else [],
        "post_consent_document_cookie_inventory": result.post.document_cookie_inventory if result.post else [],
        "pre_consent_network_signature_matches": result.pre.network_signature_matches if result.pre else [],
        "post_consent_network_signature_matches": result.post.network_signature_matches if result.post else [],
        "audit_environment": result.audit_environment,
        "consent_detection": result.consent_detection,
        "request_level_pre_post_diff": result.request_level_diff,
        "manual_checklist_parity": result.manual_checklist_parity,
        "vendor_classification": result.vendor_classification,
        "critical_flags": result.critical_flags,
        "high_flags": result.high_flags,
        "medium_flags": result.medium_flags,
        "manual_review_flags": result.manual_review_flags,
        "technical_indicator_notice": "This scan produces technical indicators and evidence only. Legal/compliance review recommended.",
    }


def write_portfolio_summary(results: list[ScanResult], output_root: str | Path, scan_date: date | None = None) -> Path:
    root = scan_root(output_root, scan_date)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "portfolio_summary.csv"
    columns = [
        "mga_name",
        "url",
        "scan_status",
        "consent_status",
        "pre_consent_third_party_count",
        "post_consent_third_party_count",
        "pre_consent_cookie_count",
        "post_consent_cookie_count",
        "pre_consent_tracker_categories",
        "post_consent_tracker_categories",
        "critical_flags",
        "high_flags",
        "medium_flags",
        "manual_review_flags",
        "top_third_party_domains",
        "pre_consent_cookie_name_signals",
        "post_consent_cookie_name_signals",
        "pre_consent_network_url_signals",
        "post_consent_network_url_signals",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        rows = [portfolio_row(result) for result in results]
        if pd is not None:
            pd.DataFrame(rows, columns=columns).to_csv(handle, index=False)
        else:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    return path


def portfolio_row(result: ScanResult) -> dict[str, str | int | None]:
    pre_categories = sorted({item.get("category") for item in result.vendor_classification if "pre" in item.get("phases", []) and item.get("category") not in {None, "First party", "Infrastructure/necessary service"}})
    post_categories = sorted({item.get("category") for item in result.vendor_classification if "post" in item.get("phases", []) and item.get("category") not in {None, "First party", "Infrastructure/necessary service"}})
    all_domains = sorted(set((result.pre.third_party_domains if result.pre else []) + (result.post.third_party_domains if result.post else [])))
    pre_cookie_signals = sorted({item.get("signal") for item in (result.pre.cookie_name_matches if result.pre else []) if item.get("signal")})
    post_cookie_signals = sorted({item.get("signal") for item in (result.post.cookie_name_matches if result.post else []) if item.get("signal")})
    pre_network_signals = network_signals(result.pre.network_signature_matches if result.pre else [])
    post_network_signals = network_signals(result.post.network_signature_matches if result.post else [])
    return {
        "mga_name": result.mga_name,
        "url": result.url,
        "scan_status": result.scan_status,
        "consent_status": result.consent_status,
        "pre_consent_third_party_count": len(result.pre.third_party_domains) if result.pre else 0,
        "post_consent_third_party_count": len(result.post.third_party_domains) if result.post else 0,
        "pre_consent_cookie_count": len(result.pre.cookies) if result.pre else 0,
        "post_consent_cookie_count": len(result.post.cookies) if result.post else 0,
        "pre_consent_tracker_categories": "; ".join(pre_categories),
        "post_consent_tracker_categories": "; ".join(post_categories),
        "critical_flags": "; ".join(result.critical_flags),
        "high_flags": "; ".join(result.high_flags),
        "medium_flags": "; ".join(result.medium_flags),
        "manual_review_flags": "; ".join(result.manual_review_flags),
        "top_third_party_domains": "; ".join(all_domains[:10]),
        "pre_consent_cookie_name_signals": "; ".join(pre_cookie_signals),
        "post_consent_cookie_name_signals": "; ".join(post_cookie_signals),
        "pre_consent_network_url_signals": "; ".join(pre_network_signals),
        "post_consent_network_url_signals": "; ".join(post_network_signals),
    }


def network_signals(matches: list[dict[str, Any]]) -> list[str]:
    signals = set()
    for match in matches:
        for signature in match.get("signature_matches", []):
            if signature.get("signal"):
                signals.add(signature["signal"])
    return sorted(signals)
