from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


CONSENT_STATUSES = {
    "no_banner_found",
    "banner_found_click_failed",
    "accepted_clicked",
}


@dataclass
class MGARecord:
    mga_name: str
    url: str | None = None
    program_name: str | None = None
    carrier_of_record: str | None = None
    notes: str | None = None


@dataclass
class NetworkRequest:
    url: str
    domain: str
    method: str
    resource_type: str
    phase: str
    response_status: int | None = None
    initiator: str | None = None


@dataclass
class StorageSnapshot:
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)


@dataclass
class PhaseEvidence:
    network: list[dict[str, Any]]
    cookies: list[dict[str, Any]]
    storage: dict[str, Any]
    third_party_domains: list[str]
    scripts: list[dict[str, Any]]
    document_cookie: str = ""
    document_cookie_inventory: list[str] = field(default_factory=list)
    cookie_name_matches: list[dict[str, Any]] = field(default_factory=list)
    network_signature_matches: list[dict[str, Any]] = field(default_factory=list)
    har: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    mga_name: str
    url: str | None
    scan_status: str
    consent_status: str
    output_dir: str | None = None
    error: str | None = None
    pre: PhaseEvidence | None = None
    post: PhaseEvidence | None = None
    vendor_classification: list[dict[str, Any]] = field(default_factory=list)
    critical_flags: list[str] = field(default_factory=list)
    high_flags: list[str] = field(default_factory=list)
    medium_flags: list[str] = field(default_factory=list)
    manual_review_flags: list[str] = field(default_factory=list)
    audit_environment: dict[str, Any] = field(default_factory=dict)
    consent_detection: dict[str, Any] = field(default_factory=dict)
    manual_checklist_parity: dict[str, Any] = field(default_factory=dict)
    request_level_diff: dict[str, Any] = field(default_factory=dict)
