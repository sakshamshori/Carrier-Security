from __future__ import annotations

from dataclasses import dataclass

from .domain import normalize_domain, registered_domain


@dataclass(frozen=True)
class VendorRule:
    domains: tuple[str, ...]
    vendor: str
    category: str


VENDOR_RULES: tuple[VendorRule, ...] = (
    VendorRule(("connect.facebook.net", "facebook.com"), "Meta/Facebook", "Meta/Facebook Pixel"),
    VendorRule(("google-analytics.com",), "Google Analytics", "Google Analytics"),
    VendorRule(("googletagmanager.com",), "Google Tag Manager", "Google Tag Manager"),
    VendorRule(("googleadservices.com", "doubleclick.net"), "Google Ads/DoubleClick", "Google Ads/DoubleClick"),
    VendorRule(("bat.bing.com",), "Microsoft/Bing Ads", "Microsoft/Bing Ads"),
    VendorRule(("linkedin.com", "ads.linkedin.com"), "LinkedIn", "LinkedIn Insight Tag"),
    VendorRule(("tiktok.com",), "TikTok", "TikTok Pixel"),
    VendorRule(("twitter.com", "x.com", "ads-twitter.com", "analytics.twitter.com"), "X/Twitter", "X/Twitter Pixel"),
    VendorRule(("hotjar.com", "fullstory.com", "clarity.ms", "mouseflow.com"), "Session replay", "Session replay"),
    VendorRule(("crazyegg.com",), "Crazy Egg", "Heatmap/form analytics"),
    VendorRule(("livechatinc.com", "intercom.io", "drift.com", "glia.com"), "Chat/live chat", "Chat/live chat"),
    VendorRule(("segment.io",), "Segment", "CRM/lead-gen"),
    VendorRule(("tealiumiq.com",), "Tealium", "Tag manager"),
    VendorRule(("adsrvr.org",), "The Trade Desk", "Identity resolution/data broker"),
    VendorRule(("liveramp.com", "lotame.com"), "Identity/data broker", "Identity resolution/data broker"),
)

INFRASTRUCTURE_REGISTERED_DOMAINS = {
    "cloudflare.com",
    "cloudfront.net",
    "akamaihd.net",
    "fastly.net",
    "jsdelivr.net",
    "unpkg.com",
    "jquery.com",
    "bootstrapcdn.com",
    "fontawesome.com",
    "gstatic.com",
    "googleapis.com",
}


def classify_domain(domain_or_url: str, script_url: str | None = None, is_third_party_domain: bool = True) -> dict[str, str | bool]:
    domain = normalize_domain(domain_or_url)
    script = (script_url or "").lower()

    for rule in VENDOR_RULES:
        for known_domain in rule.domains:
            if domain == known_domain or domain.endswith(f".{known_domain}") or known_domain in script:
                return {
                    "domain": domain,
                    "vendor": rule.vendor,
                    "category": rule.category,
                    "known_vendor": True,
                }

    if registered_domain(domain) in INFRASTRUCTURE_REGISTERED_DOMAINS:
        return {
            "domain": domain,
            "vendor": "Infrastructure/necessary service",
            "category": "Infrastructure/necessary service",
            "known_vendor": True,
        }

    if is_third_party_domain:
        return {
            "domain": domain,
            "vendor": "Unknown third party",
            "category": "Unknown third party",
            "known_vendor": False,
        }

    return {
        "domain": domain,
        "vendor": "First party",
        "category": "First party",
        "known_vendor": True,
    }


def classify_domains(domains: set[str], scripts: list[dict], site_url: str) -> list[dict]:
    from .domain import is_third_party

    classified: dict[str, dict] = {}
    script_by_domain: dict[str, str] = {}
    for script in scripts:
        script_url = script.get("url", "")
        script_domain = normalize_domain(script_url)
        if script_domain:
            script_by_domain.setdefault(script_domain, script_url)

    for domain in sorted(domains):
        classified[domain] = classify_domain(
            domain,
            script_by_domain.get(domain),
            is_third_party(domain, site_url),
        )
    return list(classified.values())
