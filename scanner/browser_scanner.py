from __future__ import annotations

import json
import os
import re
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .domain import is_third_party, normalize_domain
from .manual_detectors import (
    cookie_name_matches,
    network_records_with_signatures,
    network_signature_matches,
    parse_document_cookie_names,
)
from .models import CONSENT_STATUSES, MGARecord, PhaseEvidence, ScanResult
from .risk_flags import assign_risk_flags, detect_block_status
from .vendor_classifier import classify_domain, classify_domains

try:
    from playwright.sync_api import BrowserContext, Page, TimeoutError as PlaywrightTimeoutError, sync_playwright
except ImportError:  # pragma: no cover - covered by runtime setup
    BrowserContext = Any
    Page = Any
    PlaywrightTimeoutError = Exception
    sync_playwright = None


ACCEPT_TEXT_RE = re.compile(
    r"^(accept|accept all|accept cookies|accept all cookies|i agree|agree|allow|allow all|"
    r"consent|i consent|agree to consenting data|continue|continue with recommended cookies|"
    r"got it|ok|okay|yes)$",
    re.I,
)
BANNER_TEXT_RE = re.compile(r"(cookie|cookies|privacy|consent|tracking|preferences)", re.I)


class NetworkRecorder:
    def __init__(self, site_url: str) -> None:
        self.site_url = site_url
        self.phase = "pre"
        self.records: list[dict[str, Any]] = []
        self._by_request: dict[Any, dict[str, Any]] = {}

    def attach(self, page: Page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_request_failed)

    def _on_request(self, request: Any) -> None:
        domain = normalize_domain(request.url)
        record = {
            "request_sequence": len(self.records) + 1,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "url": request.url,
            "domain": domain,
            "method": request.method,
            "response_status": None,
            "resource_type": request.resource_type,
            "initiator": _safe_frame_url(request),
            "initiator_type": "playwright_frame_url",
            "phase": self.phase,
            "third_party": is_third_party(request.url, self.site_url),
        }
        classification = classify_domain(domain, request.url, record["third_party"])
        record["vendor"] = classification["vendor"]
        record["category"] = classification["category"]
        record["signature_matches"] = network_signature_matches(request.url)
        self._by_request[request] = record
        self.records.append(record)

    def _on_response(self, response: Any) -> None:
        request = response.request
        if request in self._by_request:
            self._by_request[request]["response_status"] = response.status

    def _on_request_failed(self, request: Any) -> None:
        if request in self._by_request:
            self._by_request[request]["request_failed"] = True

    def records_for(self, phase: str) -> list[dict[str, Any]]:
        return [record for record in self.records if record["phase"] == phase]


def _safe_frame_url(request: Any) -> str | None:
    try:
        return request.frame.url
    except Exception:
        return None


def scan_record(
    record: MGARecord,
    output_dir: Path,
    timeout_ms: int = 30000,
    post_consent_wait_ms: int = 4000,
    headless: bool = True,
) -> ScanResult:
    if not record.url:
        result = ScanResult(
            mga_name=record.mga_name,
            url=record.url,
            scan_status="missing_url",
            consent_status="no_banner_found",
        )
        flags = assign_risk_flags([], [], [], [], None, result.scan_status, result.consent_status)
        _apply_flags(result, flags)
        return result

    if sync_playwright is None:
        raise RuntimeError("Playwright is not installed. Run: python3 -m pip install -r requirements.txt")

    result = ScanResult(record.mga_name, record.url, "success", "no_banner_found")
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless)
            context_options = {
                "viewport": {"width": 1440, "height": 1200},
                "ignore_https_errors": True,
                "user_agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
            }
            raw_har_enabled = os.getenv("SCANNER_RECORD_RAW_HAR", "1").lower() not in {"0", "false", "no"}
            if raw_har_enabled:
                context_options.update(
                    {
                        "record_har_path": str(output_dir / "raw_full_session.har"),
                        "record_har_content": "omit",
                        "record_har_mode": "minimal",
                    }
                )
            context = browser.new_context(**context_options)
            context.clear_cookies()
            page = context.new_page()
            cache_disabled = disable_cache(page)
            result.audit_environment = {
                "fresh_browser_context": True,
                "cookies_cleared_before_scan": True,
                "cache_disabled": cache_disabled,
                "raw_har_enabled": raw_har_enabled,
                "network_recording_attached_before_navigation": True,
                "playwright_context": "chromium",
                "manual_equivalent": "Incognito-style fresh session with network recording preserved by the script.",
            }
            recorder = NetworkRecorder(record.url)
            recorder.attach(page)
            page.goto(record.url, wait_until="domcontentloaded", timeout=timeout_ms)
            _quiet_wait(page, 2500)

            page.screenshot(path=str(output_dir / "screenshot_initial.png"), full_page=True)
            result.consent_detection = detect_consent_banner(page)
            banner_found = result.consent_detection["banner_found"]
            if banner_found:
                _capture_banner_screenshot(page, output_dir / "screenshot_banner.png")

            pre = collect_phase_evidence(page, context, recorder, "pre", record.url)

            if banner_found:
                recorder.phase = "post"
                click_result = click_accept(page)
                clicked = click_result["clicked"]
                result.consent_detection["click_attempt"] = click_result
                result.consent_status = "accepted_clicked" if clicked else "banner_found_click_failed"
                if clicked:
                    _quiet_wait(page, post_consent_wait_ms)
                    page.screenshot(path=str(output_dir / "screenshot_post_consent.png"), full_page=True)
                else:
                    page.screenshot(path=str(output_dir / "screenshot_post_consent.png"), full_page=True)
            else:
                result.consent_status = "no_banner_found"
                page.screenshot(path=str(output_dir / "screenshot_post_consent.png"), full_page=True)

            post = collect_phase_evidence(page, context, recorder, "post", record.url)
            title = _safe_page_title(page)
            body_text = _safe_body_text(page)
            block_status = detect_block_status(page.url, title, body_text)
            if block_status:
                result.scan_status = block_status

            context.close()
            browser.close()
            split_har = split_raw_har(output_dir / "raw_full_session.har", pre.network, post.network)
            if split_har:
                pre.har = split_har["pre"]
                post.har = split_har["post"]

            result.pre = pre
            result.post = post
            result.vendor_classification = build_vendor_classification(pre, post, record.url)
            result.request_level_diff = build_request_level_diff(pre.network, post.network)
            result.manual_checklist_parity = build_manual_checklist_parity(result)
            flags = assign_risk_flags(
                result.vendor_classification,
                pre.network,
                post.network,
                pre.cookies,
                record.url,
                result.scan_status,
                result.consent_status,
            )
            _apply_flags(result, flags)
            return result
    except PlaywrightTimeoutError as exc:
        result.scan_status = "site_unreachable"
        result.error = str(exc)
    except Exception as exc:
        result.scan_status = "site_unreachable"
        result.error = str(exc)

    flags = assign_risk_flags([], [], [], [], record.url, result.scan_status, result.consent_status)
    _apply_flags(result, flags)
    result.manual_checklist_parity = build_manual_checklist_parity(result)
    return result


def disable_cache(page: Page) -> bool:
    try:
        session = page.context.new_cdp_session(page)
        session.send("Network.enable")
        session.send("Network.setCacheDisabled", {"cacheDisabled": True})
        return True
    except Exception:
        return False


def _quiet_wait(page: Page, wait_ms: int) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=wait_ms)
    except Exception:
        page.wait_for_timeout(wait_ms)


def detect_banner(page: Page) -> bool:
    return detect_consent_banner(page)["banner_found"]


def detect_consent_banner(page: Page) -> dict[str, Any]:
    detection: dict[str, Any] = {
        "banner_found": False,
        "matched_frame_url": None,
        "matched_text_excerpt": None,
        "candidate_buttons": [],
        "accepted_phrases_checked": [
            "Accept",
            "Accept all",
            "Accept cookies",
            "Accept all cookies",
            "I agree",
            "Agree",
            "Allow",
            "Allow all",
            "Consent",
            "I consent",
            "Agree to consenting data",
            "Continue",
            "Got it",
            "OK",
            "Okay",
            "Yes",
        ],
    }
    for frame in page.frames:
        try:
            body = frame.locator("body")
            if body.count() and BANNER_TEXT_RE.search(body.inner_text(timeout=1000)):
                body_text = body.inner_text(timeout=1000)
                candidates = candidate_consent_controls(frame)
                detection.update(
                    {
                        "banner_found": bool(candidates),
                        "matched_frame_url": frame.url,
                        "matched_text_excerpt": body_text[:500],
                        "candidate_buttons": candidates,
                    }
                )
                accept_controls = frame.get_by_role("button", name=ACCEPT_TEXT_RE)
                if accept_controls.count():
                    detection["banner_found"] = True
                    return detection
                clickable_text = frame.locator("button, a, [role=button], input[type=button], input[type=submit]").filter(has_text=ACCEPT_TEXT_RE)
                if clickable_text.count():
                    detection["banner_found"] = True
                    return detection
        except Exception:
            continue
    return detection


def candidate_consent_controls(frame: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    try:
        controls = frame.locator("button, a, [role=button], input[type=button], input[type=submit]")
        for index in range(min(controls.count(), 20)):
            control = controls.nth(index)
            try:
                text = (control.inner_text(timeout=500) or control.get_attribute("value") or "").strip()
                if text and (ACCEPT_TEXT_RE.search(text) or BANNER_TEXT_RE.search(text)):
                    candidates.append({"text": text[:100], "tag": control.evaluate("el => el.tagName.toLowerCase()")})
            except Exception:
                continue
    except Exception:
        pass
    return candidates


def click_accept(page: Page) -> dict[str, Any]:
    for frame in page.frames:
        selectors = [
            ("role_button", lambda: frame.get_by_role("button", name=ACCEPT_TEXT_RE)),
            ("clickable_text", lambda: frame.locator("button, a, [role=button]").filter(has_text=ACCEPT_TEXT_RE)),
            lambda: frame.locator("input[type=button], input[type=submit]").filter(has_text=ACCEPT_TEXT_RE),
        ]
        for selector_entry in selectors:
            if isinstance(selector_entry, tuple):
                selector_name, selector = selector_entry
            else:
                selector_name, selector = "input_button", selector_entry
            try:
                locator = selector().first
                if locator.count():
                    text = ""
                    try:
                        text = (locator.inner_text(timeout=500) or locator.get_attribute("value") or "").strip()
                    except Exception:
                        pass
                    locator.click(timeout=2500)
                    return {"clicked": True, "frame_url": frame.url, "selector": selector_name, "button_text": text}
            except Exception:
                continue
    return {"clicked": False, "frame_url": None, "selector": None, "button_text": None}


def _capture_banner_screenshot(page: Page, path: Path) -> None:
    likely_selectors = [
        "[id*='cookie' i]",
        "[class*='cookie' i]",
        "[id*='consent' i]",
        "[class*='consent' i]",
        "[aria-label*='cookie' i]",
    ]
    for selector in likely_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible(timeout=1000):
                locator.screenshot(path=str(path))
                return
        except Exception:
            continue
    page.screenshot(path=str(path), full_page=True)


def collect_phase_evidence(page: Page, context: BrowserContext, recorder: NetworkRecorder, phase: str, site_url: str) -> PhaseEvidence:
    network = recorder.records_for(phase)
    document_cookie = collect_document_cookie(page)
    cookies = annotate_cookies(context.cookies(), site_url)
    scripts = collect_scripts(page, site_url, phase)
    third_party_domains = sorted(
        {
            record["domain"]
            for record in network
            if record.get("domain") and record.get("third_party")
        }
    )
    storage = collect_storage(page)
    cookie_matches = cookie_name_matches(cookies, document_cookie)
    network_matches = network_records_with_signatures(network)
    return PhaseEvidence(
        network=network,
        cookies=cookies,
        storage=storage,
        third_party_domains=third_party_domains,
        scripts=scripts,
        document_cookie=document_cookie,
        document_cookie_inventory=parse_document_cookie_names(document_cookie),
        cookie_name_matches=cookie_matches,
        network_signature_matches=network_matches,
        har=build_har_json(network),
    )


def annotate_cookies(cookies: list[dict[str, Any]], site_url: str) -> list[dict[str, Any]]:
    annotated = []
    for cookie in cookies:
        item = dict(cookie)
        item["third_party"] = is_third_party(cookie.get("domain", ""), site_url)
        item["cookie_name_match"] = cookie_name_matches([item])[0] if cookie_name_matches([item]) else None
        annotated.append(item)
    return annotated


def collect_document_cookie(page: Page) -> str:
    try:
        return page.evaluate("() => document.cookie || ''")
    except Exception:
        return ""


def collect_storage(page: Page) -> dict[str, Any]:
    try:
        return page.evaluate(
            """() => ({
                local_storage: Object.fromEntries(Object.entries(window.localStorage || {})),
                session_storage: Object.fromEntries(Object.entries(window.sessionStorage || {}))
            })"""
        )
    except Exception as exc:
        return {"error": str(exc), "local_storage": {}, "session_storage": {}}


def collect_scripts(page: Page, site_url: str, phase: str) -> list[dict[str, Any]]:
    try:
        script_urls = page.evaluate(
            """() => Array.from(document.scripts)
                .map((script) => script.src)
                .filter(Boolean)"""
        )
    except Exception:
        script_urls = []
    scripts = []
    for script_url in sorted(set(script_urls)):
        domain = normalize_domain(script_url)
        third_party = is_third_party(script_url, site_url)
        classification = classify_domain(domain, script_url, third_party)
        scripts.append(
            {
                "url": script_url,
                "domain": domain,
                "phase": phase,
                "third_party": third_party,
                "vendor": classification["vendor"],
                "category": classification["category"],
            }
        )
    return scripts


def build_vendor_classification(pre: PhaseEvidence, post: PhaseEvidence, site_url: str) -> list[dict[str, Any]]:
    pre_domains = set(pre.third_party_domains)
    post_domains = set(post.third_party_domains)
    all_scripts = [*pre.scripts, *post.scripts]
    classified = classify_domains(pre_domains | post_domains, all_scripts, site_url)
    by_domain = {item["domain"]: item for item in classified}
    for domain, item in by_domain.items():
        phases = []
        if domain in pre_domains:
            phases.append("pre")
        if domain in post_domains:
            phases.append("post")
        if phases == ["pre"]:
            timing = "pre-consent only"
        elif phases == ["post"]:
            timing = "post-consent only"
        else:
            timing = "both pre-consent and post-consent"
        item["phases"] = phases
        item["timing"] = timing
    return sorted(by_domain.values(), key=lambda item: (item.get("category", ""), item.get("domain", "")))


def build_har_json(network: list[dict[str, Any]]) -> dict[str, Any]:
    entries = []
    for record in network:
        entries.append(
            {
                "request": {
                    "method": record.get("method"),
                    "url": record.get("url"),
                },
                "startedDateTime": record.get("timestamp_utc"),
                "response": {
                    "status": record.get("response_status") or 0,
                },
                "resource_type": record.get("resource_type"),
                "domain": record.get("domain"),
                "third_party": record.get("third_party"),
                "vendor": record.get("vendor"),
                "category": record.get("category"),
                "signature_matches": record.get("signature_matches", []),
            }
        )
    return {
        "log": {
            "version": "1.2-lite",
            "creator": {"name": "mga-privacy-scanner", "version": "0.1.0"},
            "entries": entries,
        }
    }


def split_raw_har(raw_har_path: Path, pre_network: list[dict[str, Any]], post_network: list[dict[str, Any]]) -> dict[str, dict[str, Any]] | None:
    if not raw_har_path.exists():
        return None
    try:
        raw_har = json.loads(raw_har_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    phase_queue: dict[tuple[str, str], deque[str]] = defaultdict(deque)
    for record in [*pre_network, *post_network]:
        phase_queue[(record.get("method", "GET"), record.get("url", ""))].append(record.get("phase", "unknown"))

    pre_entries = []
    post_entries = []
    unknown_entries = []
    for entry in raw_har.get("log", {}).get("entries", []):
        request = entry.get("request", {})
        key = (request.get("method", "GET"), request.get("url", ""))
        phase = phase_queue[key].popleft() if phase_queue.get(key) else "unknown"
        enriched_entry = deepcopy(entry)
        enriched_entry["scanner_phase"] = phase
        if phase == "pre":
            pre_entries.append(enriched_entry)
        elif phase == "post":
            post_entries.append(enriched_entry)
        else:
            unknown_entries.append(enriched_entry)

    return {
        "pre": har_with_entries(raw_har, pre_entries, unknown_entries),
        "post": har_with_entries(raw_har, post_entries, unknown_entries),
    }


def har_with_entries(raw_har: dict[str, Any], entries: list[dict[str, Any]], unknown_entries: list[dict[str, Any]]) -> dict[str, Any]:
    har = deepcopy(raw_har)
    har.setdefault("log", {})
    har["log"]["entries"] = entries
    har["scanner_note"] = "Raw Playwright HAR split by scanner pre/post phase. Entries that could not be matched are summarized under unmatched_entry_count."
    har["unmatched_entry_count"] = len(unknown_entries)
    return har


def build_request_level_diff(pre_network: list[dict[str, Any]], post_network: list[dict[str, Any]]) -> dict[str, Any]:
    pre_by_key = group_requests(pre_network)
    post_by_key = group_requests(post_network)
    pre_keys = set(pre_by_key)
    post_keys = set(post_by_key)
    return {
        "pre_consent_only": [request_diff_entry(key, pre_by_key[key]) for key in sorted(pre_keys - post_keys)],
        "post_consent_only": [request_diff_entry(key, post_by_key[key]) for key in sorted(post_keys - pre_keys)],
        "both_pre_and_post": [
            {
                **request_diff_entry(key, [*pre_by_key[key], *post_by_key[key]]),
                "pre_count": len(pre_by_key[key]),
                "post_count": len(post_by_key[key]),
            }
            for key in sorted(pre_keys & post_keys)
        ],
    }


def group_requests(records: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(record.get("method", "GET"), record.get("url", ""))].append(record)
    return grouped


def request_diff_entry(key: tuple[str, str], records: list[dict[str, Any]]) -> dict[str, Any]:
    first = records[0] if records else {}
    return {
        "method": key[0],
        "url": key[1],
        "domain": first.get("domain"),
        "resource_type": first.get("resource_type"),
        "response_statuses": sorted({record.get("response_status") for record in records if record.get("response_status") is not None}),
        "request_count": len(records),
        "first_timestamp_utc": min((record.get("timestamp_utc") for record in records if record.get("timestamp_utc")), default=None),
        "initiators": sorted({record.get("initiator") for record in records if record.get("initiator")}),
        "third_party": first.get("third_party"),
        "vendor": first.get("vendor"),
        "category": first.get("category"),
        "signature_matches": first.get("signature_matches", []),
    }


def build_manual_checklist_parity(result: ScanResult) -> dict[str, Any]:
    pre = result.pre
    post = result.post
    return {
        "ordered_manual_checklist": [
            {
                "manual_step": "Incognito tab",
                "script_check": "Fresh Chromium browser context per site; cookies cleared before scan.",
                "status": bool(result.audit_environment.get("fresh_browser_context")),
            },
            {
                "manual_step": "Developer tools: preserve logging and disable cache",
                "script_check": "Network recorder attaches before navigation and keeps pre/post records; Chromium cache disable attempted through CDP.",
                "status": bool(result.audit_environment.get("network_recording_attached_before_navigation")),
                "cache_disabled": result.audit_environment.get("cache_disabled"),
            },
            {
                "manual_step": "Console: document.cookie",
                "script_check": "document.cookie captured for pre-consent and post-consent phases.",
                "pre_consent_document_cookie": pre.document_cookie if pre else "",
                "post_consent_document_cookie": post.document_cookie if post else "",
                "pre_consent_document_cookie_inventory": pre.document_cookie_inventory if pre else [],
                "post_consent_document_cookie_inventory": post.document_cookie_inventory if post else [],
            },
            {
                "manual_step": "Cookie-name detector",
                "script_check": "Checks _fbp, _fbc, _ga, _gid, _ga_*, _gcl_au, _clck, _clsk, _hjSession, _hjSessionUser, _uetmsclkid, _uetsid, and _uetvid.",
                "pre_consent_matches": pre.cookie_name_matches if pre else [],
                "post_consent_matches": post.cookie_name_matches if post else [],
            },
            {
                "manual_step": "Network URL signature checks",
                "script_check": "Checks URL evidence for facebook, connect.facebook.net, fbevents, /tr, google-analytics, googletagmanager, doubleclick, googleadservices, collect, linkedin, px.ads.linkedin, bing, bat.bing, clarity, hotjar, fullstory, mouseflow, crazyegg, and tiktok.",
                "pre_consent_matches": pre.network_signature_matches if pre else [],
                "post_consent_matches": post.network_signature_matches if post else [],
            },
            {
                "manual_step": "Download HAR file pre-consent",
                "script_check": "Writes HAR-like JSON evidence to pre_consent_har.json.",
                "status": bool(pre and pre.har),
            },
            {
                "manual_step": "Consent: Allow / agree / accept wording",
                "script_check": "Detects likely consent banner and attempts affirmative accept/allow/agree/consent/continue wording.",
                "consent_status": result.consent_status,
                "consent_detection": result.consent_detection,
            },
            {
                "manual_step": "Download HAR file post-consent and compare",
                "script_check": "Writes HAR-like JSON evidence to post_consent_har.json and compares pre/post domains, cookies, vendors, cookie names, and URL signatures.",
                "status": bool(post and post.har),
            },
            {
                "manual_step": "Request-level pre/post consent diff",
                "script_check": "Writes request_level_pre_post_diff.json with pre-only, post-only, and both-phase request URLs.",
                "status": bool(result.request_level_diff),
            },
            {
                "manual_step": "Pre-consent should not have listed trackers",
                "script_check": "Pre-consent tracker indicators are reflected in critical/high/medium technical flags and the pre_consent_* evidence files.",
                "critical_flags": result.critical_flags,
                "high_flags": result.high_flags,
                "medium_flags": result.medium_flags,
            },
        ],
        "pre_post_comparison": {
            "cookie_name_signals": compare_signal_sets(
                pre.cookie_name_matches if pre else [],
                post.cookie_name_matches if post else [],
                "signal",
            ),
            "network_url_signals": compare_signal_sets(
                flatten_network_signals(pre.network_signature_matches if pre else []),
                flatten_network_signals(post.network_signature_matches if post else []),
                "signal",
            ),
        },
    }


def flatten_network_signals(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened = []
    for match in matches:
        for signature in match.get("signature_matches", []):
            flattened.append({**signature, "url": match.get("url"), "domain": match.get("domain")})
    return flattened


def compare_signal_sets(pre_matches: list[dict[str, Any]], post_matches: list[dict[str, Any]], key: str) -> dict[str, list[str]]:
    pre = {item.get(key) for item in pre_matches if item.get(key)}
    post = {item.get(key) for item in post_matches if item.get(key)}
    return {
        "pre_consent_only": sorted(pre - post),
        "post_consent_only": sorted(post - pre),
        "both_pre_and_post": sorted(pre & post),
    }


def _safe_page_title(page: Page) -> str:
    try:
        return page.title()
    except Exception:
        return ""


def _safe_body_text(page: Page) -> str:
    try:
        return page.locator("body").inner_text(timeout=1000)[:5000]
    except Exception:
        return ""


def _apply_flags(result: ScanResult, flags: dict[str, list[str]]) -> None:
    result.critical_flags = flags["critical"]
    result.high_flags = flags["high"]
    result.medium_flags = flags["medium"]
    result.manual_review_flags = flags["manual_review"]


assert CONSENT_STATUSES == {"no_banner_found", "banner_found_click_failed", "accepted_clicked"}
