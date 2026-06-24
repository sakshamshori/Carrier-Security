from scanner.domain import is_third_party, registered_domain


def test_registered_domain_handles_subdomains():
    assert registered_domain("https://quote.example.co.uk/path") == "example.co.uk"


def test_first_party_subdomain_is_not_third_party():
    assert not is_third_party("https://cdn.example.com/app.js", "https://www.example.com")


def test_different_registered_domain_is_third_party():
    assert is_third_party("https://connect.facebook.net/en_US/fbevents.js", "https://www.example.com")
