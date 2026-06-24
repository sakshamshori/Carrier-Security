from scanner.browser_scanner import build_request_level_diff


def test_request_level_diff_splits_pre_post_and_both():
    pre = [
        {"method": "GET", "url": "https://example.com/a.js", "domain": "example.com", "timestamp_utc": "2026-01-01T00:00:00+00:00"},
        {"method": "GET", "url": "https://analytics.example/collect", "domain": "analytics.example", "timestamp_utc": "2026-01-01T00:00:01+00:00"},
    ]
    post = [
        {"method": "GET", "url": "https://example.com/a.js", "domain": "example.com", "timestamp_utc": "2026-01-01T00:00:02+00:00"},
        {"method": "POST", "url": "https://tracker.example/pixel", "domain": "tracker.example", "timestamp_utc": "2026-01-01T00:00:03+00:00"},
    ]
    diff = build_request_level_diff(pre, post)
    assert [entry["url"] for entry in diff["pre_consent_only"]] == ["https://analytics.example/collect"]
    assert [entry["url"] for entry in diff["post_consent_only"]] == ["https://tracker.example/pixel"]
    assert [entry["url"] for entry in diff["both_pre_and_post"]] == ["https://example.com/a.js"]
