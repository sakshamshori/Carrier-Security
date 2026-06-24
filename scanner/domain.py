from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:  # pragma: no cover - exercised only without optional deps
    tldextract = None

_TLD_CACHE_DIR = os.getenv("TLDEXTRACT_CACHE", str(Path(".scanner_cache/tldextract").resolve()))
_TLD_EXTRACTOR = (
    tldextract.TLDExtract(suffix_list_urls=(), cache_dir=_TLD_CACHE_DIR)
    if tldextract is not None
    else None
)


def normalize_domain(url_or_domain: str | None) -> str:
    if not url_or_domain:
        return ""
    value = url_or_domain.strip().lower()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or value
    return host.strip(".").lower()


@lru_cache(maxsize=4096)
def registered_domain(url_or_domain: str | None) -> str:
    host = normalize_domain(url_or_domain)
    if not host:
        return ""
    if _TLD_EXTRACTOR is not None:
        extracted = _TLD_EXTRACTOR(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return host

    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def is_third_party(request_url_or_domain: str, site_url_or_domain: str) -> bool:
    request_registered = registered_domain(request_url_or_domain)
    site_registered = registered_domain(site_url_or_domain)
    if not request_registered or not site_registered:
        return False
    return request_registered != site_registered
