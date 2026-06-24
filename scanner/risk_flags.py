from __future__ import annotations

from urllib.parse import urlparse


SENSITIVE_KEYWORDS = (
    "quote",
    "get-a-quote",
    "apply",
    "application",
    "contact",
    "claim",
    "claims",
    "report-claim",
    "login",
    "payment",
)

SESSION_REPLAY_CATEGORIES = {"Session replay"}
FORM_ANALYTICS_CATEGORIES = {"Heatmap/form analytics"}
HIGH_PRE_CONSENT_CATEGORIES = {
    "Meta/Facebook Pixel",
    "TikTok Pixel",
    "Google Ads/DoubleClick",
    "LinkedIn Insight Tag",
    "X/Twitter Pixel",
}
MEDIUM_PRE_CONSENT_CATEGORIES = {
    "Google Analytics",
    "Google Tag Manager",
    "Tag manager",
}
TRACKER_CATEGORIES = (
    SESSION_REPLAY_CATEGORIES
    | FORM_ANALYTICS_CATEGORIES
    | HIGH_PRE_CONSENT_CATEGORIES
    | MEDIUM_PRE_CONSENT_CATEGORIES
    | {"Microsoft/Bing Ads", "CRM/lead-gen", "Identity resolution/data broker"}
)


def _urls_contain_sensitive_keyword(urls: list[str], page_url: str | None = None) -> bool:
    haystack = " ".join([page_url or "", *urls]).lower()
    return any(keyword in haystack for keyword in SENSITIVE_KEYWORDS)


def _categories(classifications: list[dict], phase: str | None = None) -> set[str]:
    categories = set()
    for item in classifications:
        if phase and phase not in set(item.get("phases", [])):
            continue
        category = item.get("category")
        if category:
            categories.add(category)
    return categories


def assign_risk_flags(
    classifications: list[dict],
    pre_network: list[dict],
    post_network: list[dict],
    pre_cookies: list[dict],
    page_url: str | None,
    scan_status: str,
    consent_status: str,
) -> dict[str, list[str]]:
    critical: list[str] = []
    high: list[str] = []
    medium: list[str] = []
    manual: list[str] = []

    pre_categories = _categories(classifications, "pre")
    post_categories = _categories(classifications, "post")
    post_only_categories = post_categories - pre_categories
    all_tracking_urls = [
        record.get("url", "")
        for record in [*pre_network, *post_network]
        if record.get("category") in TRACKER_CATEGORIES
    ]

    if SESSION_REPLAY_CATEGORIES & pre_categories:
        critical.append("Session replay fires pre-consent")
    if FORM_ANALYTICS_CATEGORIES & pre_categories:
        critical.append("Form analytics or keylogging-like script fires pre-consent")
    if all_tracking_urls and _urls_contain_sensitive_keyword(all_tracking_urls, page_url):
        critical.append("Known tracking vendor fires on URL containing sensitive insurance keyword")

    for category in sorted(HIGH_PRE_CONSENT_CATEGORIES & pre_categories):
        high.append(f"{category} fires pre-consent")
    if any(cookie for cookie in pre_cookies if cookie.get("third_party")):
        high.append("Third-party cookies are set pre-consent")

    for category in sorted(MEDIUM_PRE_CONSENT_CATEGORIES & pre_categories):
        medium.append(f"{category} fires pre-consent")
    if TRACKER_CATEGORIES & post_only_categories:
        medium.append("Trackers fire only after consent")

    if scan_status != "success":
        if scan_status == "missing_url":
            manual.append("no scannable web presence")
        elif scan_status == "site_unreachable":
            manual.append("site unreachable")
        elif scan_status == "blocked":
            manual.append("site blocks automation")
        elif scan_status == "captcha_or_login_block":
            manual.append("CAPTCHA/login blocks scan")
        else:
            manual.append(scan_status.replace("_", " "))
    if consent_status == "banner_found_click_failed":
        manual.append("consent banner found but click failed")
    if any(item.get("category") == "Unknown third party" for item in classifications):
        manual.append("unknown third-party domains detected")

    return {
        "critical": sorted(set(critical)),
        "high": sorted(set(high)),
        "medium": sorted(set(medium)),
        "manual_review": sorted(set(manual)),
    }


def detect_block_status(current_url: str, title: str, body_text: str) -> str | None:
    text = f"{current_url} {title} {body_text}".lower()
    captcha_or_login_terms = (
        "captcha",
        "verify you are human",
        "sign in to continue",
        "log in to continue",
        "login required",
    )
    blocked_terms = (
        "access denied",
        "bot detection",
        "blocked",
        "cloudflare ray id",
    )
    if any(term in text for term in captcha_or_login_terms):
        return "captcha_or_login_block"
    if any(term in text for term in blocked_terms):
        return "blocked"
    return None
