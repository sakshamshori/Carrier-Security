from __future__ import annotations

import re
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any


@dataclass(frozen=True)
class CookieNameRule:
    pattern: re.Pattern[str]
    signal: str
    vendor: str
    category: str


@dataclass(frozen=True)
class NetworkSignatureRule:
    pattern: re.Pattern[str]
    signal: str
    vendor: str
    category: str


COOKIE_NAME_RULES: tuple[CookieNameRule, ...] = (
    CookieNameRule(re.compile(r"^_fbp$", re.I), "_fbp", "Meta/Facebook", "Meta/Facebook Pixel"),
    CookieNameRule(re.compile(r"^_fbc$", re.I), "_fbc", "Meta/Facebook", "Meta click ID"),
    CookieNameRule(re.compile(r"^_ga(?:_.+)?$", re.I), "_ga / _ga_*", "Google Analytics", "Google Analytics"),
    CookieNameRule(re.compile(r"^_gid$", re.I), "_gid", "Google Analytics", "Google Analytics"),
    CookieNameRule(re.compile(r"^_gcl_au$", re.I), "_gcl_au", "Google Ads", "Google Ads / conversion linker"),
    CookieNameRule(re.compile(r"^_clck$", re.I), "_clck", "Microsoft Clarity", "Microsoft Clarity"),
    CookieNameRule(re.compile(r"^_clsk$", re.I), "_clsk", "Microsoft Clarity", "Microsoft Clarity"),
    CookieNameRule(re.compile(r"^_hjSession(?:User)?(?:_.+)?$", re.I), "_hjSession / _hjSessionUser", "Hotjar", "Hotjar"),
    CookieNameRule(re.compile(r"^_uetmsclkid$", re.I), "_uetmsclkid", "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
    CookieNameRule(re.compile(r"^_uetsid$", re.I), "_uetsid", "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
    CookieNameRule(re.compile(r"^_uetvid$", re.I), "_uetvid", "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
)

NETWORK_SIGNATURE_RULES: tuple[NetworkSignatureRule, ...] = (
    NetworkSignatureRule(re.compile(r"facebook", re.I), "facebook", "Meta/Facebook", "Meta/Facebook Pixel"),
    NetworkSignatureRule(re.compile(r"connect\.facebook\.net", re.I), "connect.facebook.net", "Meta/Facebook", "Meta/Facebook Pixel"),
    NetworkSignatureRule(re.compile(r"fbevents", re.I), "fbevents", "Meta/Facebook", "Meta/Facebook Pixel"),
    NetworkSignatureRule(re.compile(r"(^|/)tr(?:[/?#]|$)", re.I), "/tr", "Meta/Facebook", "Meta/Facebook Pixel"),
    NetworkSignatureRule(re.compile(r"google-analytics", re.I), "google-analytics", "Google Analytics", "Google Analytics"),
    NetworkSignatureRule(re.compile(r"googletagmanager", re.I), "googletagmanager", "Google Tag Manager", "Google Tag Manager"),
    NetworkSignatureRule(re.compile(r"doubleclick", re.I), "doubleclick", "Google Ads/DoubleClick", "Google Ads/DoubleClick"),
    NetworkSignatureRule(re.compile(r"googleadservices", re.I), "googleadservices", "Google Ads/DoubleClick", "Google Ads/DoubleClick"),
    NetworkSignatureRule(re.compile(r"collect", re.I), "collect", "Tracking collection endpoint", "Tracker collection endpoint"),
    NetworkSignatureRule(re.compile(r"px\.ads\.linkedin", re.I), "px.ads.linkedin", "LinkedIn", "LinkedIn Insight Tag"),
    NetworkSignatureRule(re.compile(r"linkedin", re.I), "linkedin", "LinkedIn", "LinkedIn Insight Tag"),
    NetworkSignatureRule(re.compile(r"bat\.bing", re.I), "bat.bing", "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
    NetworkSignatureRule(re.compile(r"bing", re.I), "bing", "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
    NetworkSignatureRule(re.compile(r"clarity", re.I), "clarity", "Microsoft Clarity", "Session replay"),
    NetworkSignatureRule(re.compile(r"hotjar", re.I), "hotjar", "Hotjar", "Session replay"),
    NetworkSignatureRule(re.compile(r"fullstory", re.I), "fullstory", "FullStory", "Session replay"),
    NetworkSignatureRule(re.compile(r"mouseflow", re.I), "mouseflow", "Mouseflow", "Session replay"),
    NetworkSignatureRule(re.compile(r"crazyegg", re.I), "crazyegg", "Crazy Egg", "Heatmap/form analytics"),
    NetworkSignatureRule(re.compile(r"tiktok", re.I), "tiktok", "TikTok", "TikTok Pixel"),
)


def classify_cookie_name(name: str) -> dict[str, str] | None:
    for rule in COOKIE_NAME_RULES:
        if rule.pattern.search(name):
            return {
                "cookie_name": name,
                "signal": rule.signal,
                "vendor": rule.vendor,
                "category": rule.category,
            }
    return None


def cookie_name_matches(cookies: list[dict[str, Any]], document_cookie: str = "") -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for cookie in cookies:
        name = cookie.get("name", "")
        match = classify_cookie_name(name)
        if not match:
            continue
        key = (name, cookie.get("domain", ""))
        seen.add(key)
        matches.append(
            {
                **match,
                "domain": cookie.get("domain"),
                "path": cookie.get("path"),
                "third_party": cookie.get("third_party"),
                "http_only": cookie.get("httpOnly"),
                "evidence_source": "browser_context_cookies",
            }
        )

    for name in parse_document_cookie_names(document_cookie):
        match = classify_cookie_name(name)
        if not match:
            continue
        key = (name, "document.cookie")
        if key in seen:
            continue
        matches.append(
            {
                **match,
                "domain": None,
                "path": None,
                "third_party": None,
                "http_only": False,
                "evidence_source": "document.cookie",
            }
        )
    return matches


def parse_document_cookie_names(document_cookie: str) -> list[str]:
    if not document_cookie:
        return []
    parsed = SimpleCookie()
    try:
        parsed.load(document_cookie)
        return list(parsed.keys())
    except Exception:
        names = []
        for chunk in document_cookie.split(";"):
            if "=" in chunk:
                names.append(chunk.split("=", 1)[0].strip())
        return [name for name in names if name]


def network_signature_matches(url: str) -> list[dict[str, str]]:
    matches = []
    for rule in NETWORK_SIGNATURE_RULES:
        if rule.pattern.search(url):
            matches.append(
                {
                    "signal": rule.signal,
                    "vendor": rule.vendor,
                    "category": rule.category,
                }
            )
    return matches


def network_records_with_signatures(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "url": record.get("url"),
            "domain": record.get("domain"),
            "method": record.get("method"),
            "resource_type": record.get("resource_type"),
            "response_status": record.get("response_status"),
            "third_party": record.get("third_party"),
            "signature_matches": record.get("signature_matches", []),
        }
        for record in records
        if record.get("signature_matches")
    ]
