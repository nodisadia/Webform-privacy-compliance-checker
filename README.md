# WebForm Privacy Compliance Checker

![Python](https://img.shields.io/badge/Python-3.11-blue) ![License](https://img.shields.io/badge/License-MIT-green)

A **privacy & security scanner for web forms**. This tool checks web forms for HTTPS usage, form security, cookies, consent checkboxes, privacy policies, trackers, and security headers, and generates **JSON and Markdown reports** with a **5x5 risk calculation matrix**.

---

## Features

- Scan multiple URLs for webform privacy and security compliance.
- Detects issues such as:
  - Missing HTTPS
  - Insecure forms
  - Missing CSRF tokens
  - Missing consent checkboxes
  - Missing or insecure cookies
  - Trackers (Google Analytics, GTM, Facebook Pixel, TikTok, Hotjar, DoubleClick)
  - Missing security headers
- Calculates **risk level** using a 5x5 matrix (Likelihood × Impact).
- Generates:
  - Individual JSON reports per URL
  - Combined Markdown report for all scanned URLs
- Color-coded console output for easy reading.
- Simple user interaction:
  - Enter URLs one-by-one or load from a file
- Compliant with international and Bangladeshi privacy laws, e.g., GDPR, CCPA, PDPA, Bangladesh Data Protection Act 2023.

---

## Installation

1. Clone the repository via SSH:

```bash
git clone git@github.com:nodisadia/Webform-privacy-compliance-checker.git
cd Webform-privacy-compliance-checker
```
Install dependencies:

```bash
pip install -r requirements.txt
```
Usage
Run the main program:

```bash
python src/main.py
```
You will be prompted to enter URLs or a file containing URLs.

Scan results are displayed in the console with color-coded risk levels.

Reports are automatically saved as JSON and Markdown in the src/ folder.

Example Console Output
██████████████████████████████████████████████
     WEBFORM PRIVACY COMPLIANCE CHECKER      
██████████████████████████████████████████████
                     v1.0                     

Scanning https://example.com ...

Scan result for: https://example.com
HTTPS          : OK
Forms          : 2 forms detected — password fields: 1, csrf tokens: 0, insecure actions: 1
Privacy Policy : ⚠ Privacy policy link NOT found
Consent        : ⚠ Consent checkbox NOT found
Security Headers: Missing headers: CSP, HSTS
Cookies        : ⚠ 1 cookie(s) missing Secure/HttpOnly
Trackers       : Trackers detected: GoogleAnalytics, FacebookPixel

Risk Level: HIGH
Reports
JSON report per URL: compliance_summary_<safe_url>.json

Combined Markdown report: report.md

Both contain full scan details, issues detected, laws, recommendations, and risk breakdown.

Contributing
Contributions are welcome! Please fork the repo and create a pull request with your changes.

License
This project is licensed under the MIT License.

