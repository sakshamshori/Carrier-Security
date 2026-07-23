from scanner.domain_discovery import (
    candidate_domains_for_name,
    parse_name_lines,
    prepare_candidates,
)


def test_parse_name_lines_supports_names_and_inline_domains():
    rows = parse_name_lines(
        """
        Carrier: Example Carrier
        Openly
        QEO Insurance Group | https://qeo.com
        """
    )
    assert rows == [
        ("Openly", None),
        ("QEO Insurance Group", "https://qeo.com"),
    ]


def test_prepare_candidates_marks_inline_domains_ready():
    candidates = prepare_candidates([("Openly", "https://openly.com")], carrier_name="Clear Blue")
    assert candidates[0].url == "https://openly.com"
    assert candidates[0].domain_status == "ready_to_scan"
    assert candidates[0].domain_source == "provided_inline"


def test_prepare_candidates_marks_names_without_domains_for_research():
    candidates = prepare_candidates([("Some MGA", None)], carrier_name="Carrier")
    assert candidates[0].url is None
    assert candidates[0].domain_status == "domain_needs_research"


def test_candidate_domains_are_low_confidence_suggestions():
    guesses = candidate_domains_for_name("QEO Insurance Group")
    assert "https://www.qeo.com" in guesses
