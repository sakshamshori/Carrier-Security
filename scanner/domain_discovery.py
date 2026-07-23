from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


COMMON_COMPANY_SUFFIXES = (
    "insurance",
    "ins",
    "group",
    "services",
    "service",
    "holdings",
    "holding",
    "specialty",
    "specialties",
    "underwriters",
    "underwriter",
    "agency",
    "agencies",
    "partners",
    "partner",
    "capital",
    "risk",
    "management",
    "mga",
    "llc",
    "inc",
    "corp",
    "corporation",
    "company",
    "co",
)


@dataclass
class DomainCandidate:
    mga_name: str
    url: str | None
    domain_source: str
    domain_confidence: str
    domain_status: str
    notes: str = ""


def parse_name_lines(text: str) -> list[tuple[str, str | None]]:
    """Parse low-friction input: either `Name` or `Name | https://domain.com`."""
    rows: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.lower().startswith("carrier:"):
            continue
        if "|" in stripped:
            name, url = [part.strip() for part in stripped.split("|", 1)]
            rows.append((name, normalize_url(url) if url else None))
        else:
            rows.append((stripped, None))
    return rows


def load_domain_map(path: str | Path | None) -> dict[str, tuple[str, str, str]]:
    if not path:
        return {}
    mapping: dict[str, tuple[str, str, str]] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            name = (row.get("mga_name") or row.get("name") or "").strip()
            url = normalize_url((row.get("url") or "").strip())
            if not name or not url:
                continue
            source = (row.get("domain_source") or row.get("source") or "provided_domain_map").strip()
            confidence = (row.get("domain_confidence") or row.get("confidence") or "confirmed").strip()
            mapping[normalize_name_key(name)] = (url, source, confidence)
    return mapping


def prepare_candidates(
    names: list[tuple[str, str | None]],
    carrier_name: str | None = None,
    domain_map: dict[str, tuple[str, str, str]] | None = None,
    include_guesses: bool = False,
) -> list[DomainCandidate]:
    domain_map = domain_map or {}
    candidates: list[DomainCandidate] = []
    for name, provided_url in names:
        mapped = domain_map.get(normalize_name_key(name))
        if provided_url:
            candidates.append(
                DomainCandidate(
                    mga_name=name,
                    url=provided_url,
                    domain_source="provided_inline",
                    domain_confidence="confirmed_by_input",
                    domain_status="ready_to_scan",
                    notes=carrier_note(carrier_name),
                )
            )
        elif mapped:
            url, source, confidence = mapped
            candidates.append(
                DomainCandidate(
                    mga_name=name,
                    url=url,
                    domain_source=source,
                    domain_confidence=confidence,
                    domain_status="ready_to_scan" if confidence.lower() in {"high", "confirmed", "confirmed_by_input"} else "domain_needs_confirmation",
                    notes=carrier_note(carrier_name),
                )
            )
        elif include_guesses:
            guesses = candidate_domains_for_name(name)
            candidates.append(
                DomainCandidate(
                    mga_name=name,
                    url=guesses[0] if guesses else None,
                    domain_source="heuristic_guess_unverified",
                    domain_confidence="low",
                    domain_status="domain_needs_confirmation",
                    notes=f"{carrier_note(carrier_name)} Suggested candidates: {', '.join(guesses)}".strip(),
                )
            )
        else:
            candidates.append(
                DomainCandidate(
                    mga_name=name,
                    url=None,
                    domain_source="not_discovered",
                    domain_confidence="unknown",
                    domain_status="domain_needs_research",
                    notes=carrier_note(carrier_name),
                )
            )
    return candidates


def write_prepared_csv(candidates: list[DomainCandidate], output_path: str | Path, carrier_name: str | None = None) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "carrier_name",
        "mga_name",
        "url",
        "domain_status",
        "domain_source",
        "domain_confidence",
        "program_name",
        "carrier_of_record",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for candidate in candidates:
            writer.writerow(
                {
                    "carrier_name": carrier_name or "",
                    "mga_name": candidate.mga_name,
                    "url": candidate.url or "",
                    "domain_status": candidate.domain_status,
                    "domain_source": candidate.domain_source,
                    "domain_confidence": candidate.domain_confidence,
                    "program_name": "",
                    "carrier_of_record": carrier_name or "",
                    "notes": candidate.notes,
                }
            )
    return path


def candidate_domains_for_name(name: str) -> list[str]:
    slug = name_to_slug(name)
    if not slug:
        return []
    compact = slug.replace("-", "")
    candidates = [f"https://www.{compact}.com", f"https://{compact}.com"]
    if "-" in slug:
        candidates.extend([f"https://www.{slug}.com", f"https://{slug}.com"])
    candidates.extend([f"https://www.{compact}.insure", f"https://{compact}.net"])
    return list(dict.fromkeys(candidates))


def name_to_slug(name: str) -> str:
    cleaned = re.sub(r"\([^)]*\)", " ", name.lower())
    cleaned = cleaned.replace("&", " and ")
    tokens = re.findall(r"[a-z0-9]+", cleaned)
    trimmed = [token for token in tokens if token not in COMMON_COMPANY_SUFFIXES]
    return "-".join(trimmed or tokens)


def normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    value = url.strip()
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if not parsed.netloc:
        return None
    return parsed.geturl().rstrip("/")


def normalize_name_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def carrier_note(carrier_name: str | None) -> str:
    return f"Carrier: {carrier_name}." if carrier_name else ""
