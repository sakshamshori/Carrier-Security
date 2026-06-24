from scanner.risk_flags import assign_risk_flags


def test_meta_pixel_pre_consent_high_flag():
    classifications = [
        {"domain": "connect.facebook.net", "category": "Meta/Facebook Pixel", "phases": ["pre"]},
    ]
    flags = assign_risk_flags(classifications, [], [], [], "https://example.com", "success", "no_banner_found")
    assert "Meta/Facebook Pixel fires pre-consent" in flags["high"]


def test_session_replay_pre_consent_critical_flag():
    classifications = [
        {"domain": "fullstory.com", "category": "Session replay", "phases": ["pre"]},
    ]
    flags = assign_risk_flags(classifications, [], [], [], "https://example.com", "success", "no_banner_found")
    assert "Session replay fires pre-consent" in flags["critical"]


def test_third_party_cookie_pre_consent_high_flag():
    flags = assign_risk_flags([], [], [], [{"domain": ".facebook.com", "third_party": True}], "https://example.com", "success", "no_banner_found")
    assert "Third-party cookies are set pre-consent" in flags["high"]


def test_post_only_tracker_medium_flag():
    classifications = [
        {"domain": "google-analytics.com", "category": "Google Analytics", "phases": ["post"]},
    ]
    flags = assign_risk_flags(classifications, [], [], [], "https://example.com", "success", "accepted_clicked")
    assert "Trackers fire only after consent" in flags["medium"]


def test_sensitive_keyword_tracking_critical_indicator():
    classifications = [
        {"domain": "doubleclick.net", "category": "Google Ads/DoubleClick", "phases": ["pre"]},
    ]
    pre_network = [{"url": "https://stats.g.doubleclick.net/pagead/id", "category": "Google Ads/DoubleClick"}]
    flags = assign_risk_flags(
        classifications,
        pre_network,
        [],
        [],
        "https://example.com/get-a-quote",
        "success",
        "no_banner_found",
    )
    assert "Known tracking vendor fires on URL containing sensitive insurance keyword" in flags["critical"]


def test_manual_review_unknown_third_party_and_click_failed():
    classifications = [
        {"domain": "unknown.example", "category": "Unknown third party", "phases": ["pre"]},
    ]
    flags = assign_risk_flags(classifications, [], [], [], "https://example.com", "success", "banner_found_click_failed")
    assert "unknown third-party domains detected" in flags["manual_review"]
    assert "consent banner found but click failed" in flags["manual_review"]


def test_manual_review_captcha_or_login_block():
    flags = assign_risk_flags([], [], [], [], "https://example.com", "captcha_or_login_block", "no_banner_found")
    assert "CAPTCHA/login blocks scan" in flags["manual_review"]
