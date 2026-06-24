from scanner.vendor_classifier import classify_domain


def test_classifies_meta_pixel():
    result = classify_domain("connect.facebook.net", is_third_party_domain=True)
    assert result["category"] == "Meta/Facebook Pixel"
    assert result["vendor"] == "Meta/Facebook"


def test_classifies_google_ads_doubleclick():
    result = classify_domain("stats.g.doubleclick.net", is_third_party_domain=True)
    assert result["category"] == "Google Ads/DoubleClick"


def test_unknown_third_party():
    result = classify_domain("unknown-vendor.example", is_third_party_domain=True)
    assert result["category"] == "Unknown third party"
    assert result["known_vendor"] is False
