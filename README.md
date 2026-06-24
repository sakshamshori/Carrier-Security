# MGA Privacy-Risk Evidence Scanner, Phase 1

This is a local Python scanner for insurance MGA and fronting-carrier partner-risk review. Phase 1 only collects technical evidence and risk indicators: pre-consent tracking, post-consent tracking, scripts, cookies, third-party domains, vendor classification, screenshots, and structured outputs.

It does not make legal determinations. Findings are technical indicators and potential exposure indicators for legal/compliance review.

## Setup

Use Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Install Playwright's browser binaries:

```bash
python3 -m playwright install chromium
```

Optional `.env` settings:

```bash
SCANNER_TIMEOUT_MS=30000
POST_CONSENT_WAIT_MS=4000
```

## Input Format

CSV input must include:

```csv
mga_name,url
Integrated Specialty Coverages (ISC),https://www.iscmga.com
Amwins Special Risk Underwriters (SRU),https://www.amwins.com
```

Optional columns are supported:

```csv
mga_name,url,program_name,carrier_of_record,notes
Example MGA,https://example.com,Program A,Carrier B,Review note
```

You can also provide a plain text file in this format:

```text
MGA Name | https://example.com
Another MGA | https://example.org
```

Phase 1 intentionally does not discover websites from MGA names. If a URL is missing, the scanner records `missing_url`, adds a manual review indicator, and skips browser scanning.

## Run One Scan

```bash
python -m scanner run-one --name "Example MGA" --url "https://example.com" --output data/scans
```

Use `--headful` if you want to watch the browser:

```bash
python -m scanner run-one --name "Example MGA" --url "https://example.com" --output data/scans --headful
```

## Run A Portfolio Scan

```bash
python -m scanner run --input examples/sample_mgas.csv --output data/scans
```

You can also point `--input` at a text file containing `MGA Name | URL` lines.

## Generated Files

Each scan writes to:

```text
data/scans/YYYY-MM-DD/mga_slug/
```

Per-MGA files:

```text
pre_consent_network.json
post_consent_network.json
pre_consent_har.json
post_consent_har.json
pre_consent_cookies.json
post_consent_cookies.json
pre_consent_document_cookie.json
post_consent_document_cookie.json
pre_consent_document_cookie_inventory.json
post_consent_document_cookie_inventory.json
pre_consent_cookie_name_matches.json
post_consent_cookie_name_matches.json
pre_consent_network_signatures.json
post_consent_network_signatures.json
pre_consent_storage.json
post_consent_storage.json
scripts.json
third_party_domains.json
vendor_classification.json
audit_environment.json
consent_detection.json
request_level_pre_post_diff.json
manual_checklist_parity.json
screenshot_initial.png
screenshot_banner.png
screenshot_post_consent.png
scan_summary.json
```

The banner screenshot is only created when a likely cookie/consent banner is detected.

The portfolio file is:

```text
data/scans/YYYY-MM-DD/portfolio_summary.csv
```

## What The Scanner Captures

For each URL, the scanner launches a fresh Chromium context, visits the homepage, and captures evidence before clicking any cookie banner. It records network requests, request domains, methods, response statuses where available, resource types, approximate initiator frame URLs, scripts, cookies, storage, third-party domains, and screenshots.

It then tries to detect a cookie/consent banner and click an affirmative button such as `Accept`, `Accept all`, `Accept cookies`, `Accept all cookies`, `I agree`, `Agree`, `Allow`, `Allow all`, `Consent`, `I consent`, `Agree to consenting data`, `Continue`, `Got it`, `OK`, `Okay`, or `Yes`. Consent status is one of:

```text
no_banner_found
banner_found_click_failed
accepted_clicked
```

If consent is clicked, the scanner waits briefly for tags to fire and captures post-consent evidence.

## Manual Checklist Parity

Phase 1 also writes checklist-oriented JSON files to mirror a manual DevTools workflow:

- Fresh incognito-style Chromium context per site
- Network recorder attached before navigation to preserve logging
- Chromium cache disable attempted through CDP
- `document.cookie` captured before and after consent
- Parsed `document.cookie` inventory captured before and after consent
- Cookie-name detector for `_fbp`, `_fbc`, `_ga`, `_gid`, `_ga_*`, `_gcl_au`, `_clck`, `_clsk`, `_hjSession`, `_hjSessionUser`, `_uetmsclkid`, `_uetsid`, and `_uetvid`
- Network URL signature detector for `facebook`, `connect.facebook.net`, `fbevents`, `/tr`, `google-analytics`, `googletagmanager`, `doubleclick`, `googleadservices`, `collect`, `linkedin`, `px.ads.linkedin`, `bing`, `bat.bing`, `clarity`, `hotjar`, `fullstory`, `mouseflow`, `crazyegg`, and `tiktok`
- Raw Playwright HAR is saved as `raw_full_session.har`, then split into pre-consent and post-consent HAR JSON files
- Request-level pre/post diff is saved as `request_level_pre_post_diff.json`
- `manual_checklist_parity.json` in the same rough order as the manual review steps

## Vendor And Platform Classification

The scanner compares each contacted domain's registered domain against the scanned site's registered domain using public suffix logic through `tldextract`. This avoids treating subdomains as third parties.

Known vendor mappings currently include:

- Meta/Facebook Pixel
- Google Analytics
- Google Tag Manager
- Google Ads/DoubleClick
- Microsoft/Bing Ads
- LinkedIn Insight Tag
- TikTok Pixel
- X/Twitter Pixel
- Session replay
- Heatmap/form analytics
- Chat/live chat
- CRM/lead-gen
- Identity resolution/data broker
- Tag manager
- Infrastructure/necessary service
- Unknown third party

Unknown third-party domains are preserved as manual review items so they can be classified later.

## Technical Risk Flags

The scanner creates explainable technical flags, not a legal score.

Critical technical indicators:

- Session replay fires pre-consent
- Form analytics or keylogging-like script fires pre-consent
- Known tracking vendor fires on a URL containing sensitive insurance keywords

High technical indicators:

- Meta Pixel fires pre-consent
- TikTok Pixel fires pre-consent
- Google Ads/DoubleClick fires pre-consent
- LinkedIn Insight Tag fires pre-consent
- X/Twitter Pixel fires pre-consent
- Third-party cookies are set pre-consent

Medium technical indicators:

- Google Analytics fires pre-consent
- Tag manager fires pre-consent
- Trackers fire only after consent

Manual review indicators:

- Site unreachable
- Site blocks automation
- CAPTCHA/login blocks scan
- Consent banner found but click failed
- No scannable web presence
- Unknown third-party domains detected

## Tests

```bash
pytest
```

Tests cover first-party versus third-party domain classification, vendor classification, consent status values, and technical risk flag assignment.

## Known Limitations

- Some websites block automation.
- Some cookie banners are inside iframes.
- Some banners use custom wording.
- Some sites behave differently by geography.
- Some trackers fire only after scrolling, clicking, or form interaction.
- Some trackers use first-party proxies.
- Some vendor domains may be unknown and require manual classification.
- A technical finding is not a legal conclusion.

## Legal Disclaimer

This tool produces technical evidence, technical indicators, and potential exposure indicators only. It does not determine whether any website violates CIPA, ECPA, wiretap laws, privacy statutes, consumer-protection rules, contractual requirements, or any other law or policy. Legal/compliance review is recommended for interpreting all findings.
