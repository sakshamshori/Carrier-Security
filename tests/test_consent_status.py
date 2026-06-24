from scanner.models import CONSENT_STATUSES


def test_consent_status_values_are_phase_1_values():
    assert CONSENT_STATUSES == {
        "no_banner_found",
        "banner_found_click_failed",
        "accepted_clicked",
    }
