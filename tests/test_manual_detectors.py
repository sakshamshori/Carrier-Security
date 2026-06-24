from scanner.manual_detectors import cookie_name_matches, network_signature_matches, parse_document_cookie_names


def test_cookie_name_detector_classifies_manual_checklist_cookies():
    cookies = [
        {"name": "_fbp", "domain": ".example.com", "path": "/", "third_party": False, "httpOnly": False},
        {"name": "_ga_ABC123", "domain": ".example.com", "path": "/", "third_party": False, "httpOnly": False},
        {"name": "_gcl_au", "domain": ".example.com", "path": "/", "third_party": False, "httpOnly": False},
        {"name": "_uetvid", "domain": ".example.com", "path": "/", "third_party": False, "httpOnly": False},
    ]
    signals = {match["signal"] for match in cookie_name_matches(cookies)}
    assert "_fbp" in signals
    assert "_ga / _ga_*" in signals
    assert "_gcl_au" in signals
    assert "_uetvid" in signals


def test_document_cookie_parser_extracts_names():
    assert parse_document_cookie_names("_fbp=abc; _ga=GA1.1.123; other=x") == ["_fbp", "_ga", "other"]


def test_network_signature_detector_catches_manual_url_terms():
    matches = network_signature_matches("https://connect.facebook.net/en_US/fbevents.js")
    signals = {match["signal"] for match in matches}
    assert "connect.facebook.net" in signals
    assert "fbevents" in signals


def test_network_signature_detector_catches_pixel_paths_and_bing():
    pixel_signals = {match["signal"] for match in network_signature_matches("https://www.facebook.com/tr?id=123")}
    bing_signals = {match["signal"] for match in network_signature_matches("https://bat.bing.com/action/0?ti=123")}
    assert "/tr" in pixel_signals
    assert "bat.bing" in bing_signals
