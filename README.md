# Privacy-Focused Web Form Compliance Checker Tool

![Python Version](https://img.shields.io/badge/python-3.13-blue)
![Status](https://img.shields.io/badge/status-beta-yellowgreen)

---

## Project Overview

The **Privacy-Focused Web Form Compliance Checker** is an automated tool designed to help developers and organizations verify the privacy and security compliance of web forms. It analyzes HTML forms, scripts, cookies, and security headers to detect missing privacy policies, consent mechanisms, and other compliance gaps according to international and Bangladesh-specific data protection laws.

---

## Features

- **HTTPS Check:** Verifies that the site uses HTTPS.  
- **Form Analysis:** Checks form fields for proper security.  
- **Privacy Policy Check:** Detects presence of privacy policy links.  
- **Consent Checkbox Detection:** Checks for explicit consent mechanisms.  
- **Security Headers Validation:** Validates browser headers like CSP, HSTS, X-Frame-Options.  
- **Risk Scoring:** Calculates risk based on missing requirements with a risk matrix (Low, Medium, High).  
- **Report Generation:** Generates detailed `report.md` with issues found.  
- **GitHub Actions Compatible:** Can be set up to automatically scan HTML files on push.

---

## Compliance Coverage

### International Laws
- GDPR (EU)  
- CCPA (USA)  
- PDPA (Singapore/Thailand)  
- COPPA (USA)  
- ISO 27001  

### Bangladesh Laws
- Data Protection Act 2023  
- Digital Security Act (selected sections)  

---

## Installation

Clone the repository:

```bash
git clone git@github.com:nodisadia/Webform-privacy-compliance-checker.git
cd Webform-privacy-compliance-checker
```
Create a virtual environment and activate it:

```bash
python3 -m venv venv
source venv/bin/activate
```
Install dependencies:

```bash
pip install -r requirements.txt
```
Usage
Run the checker:

```bash
python3 src/main.py
```
Example:

=============================================
  Privacy-Focused Web Form Compliance Checker
                 v1.0
=============================================

Enter website URL: https://example.com

--- Running Privacy Compliance Check ---
[HTTPS CHECK]: Site uses HTTPS
[FORM CHECK]: Forms look secure
[PRIVACY POLICY]: ⚠ Privacy policy link NOT found
[CONSENT CHECKBOX]: ⚠ Consent checkbox NOT found

[RISK SCORE]: 6 (MEDIUM)
Issues detected: ['Privacy policy missing', 'Consent checkbox missing']
[✓] Report generated as report.md
Check the generated report:
```bash
cat report.md
```
License

This project is for educational purposes under the MIT License.
