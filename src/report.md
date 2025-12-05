# WebForm Privacy Compliance - Combined Report

## URL: https://ums.uftb.ac.bd/Dashboard/Index

### Checks
- **https**: OK — HTTPS enabled
- **forms**: OK — 2 form(s) detected — password fields: 1, csrf tokens: 0, insecure actions: 0
- **privacy_policy**: ⚠ NOT OK — ⚠ Privacy policy link NOT found
- **consent**: ⚠ NOT OK — ⚠ Consent checkbox NOT found
- **security_headers**: ⚠ NOT OK — Missing headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **cookies**: ⚠ NOT OK — 1 cookie(s) detected, 1 cookie(s) missing Secure/HttpOnly
- **trackers**: ⚠ NOT OK — No common trackers auto-detected

### Issues Detected
- Missing CSRF Token
- Privacy policy missing
- Consent checkbox missing
- Missing Security Header
- Insecure Cookies

### Risk Breakdown
- Raw total (sum of Likelihood×Impact per issue): 45
- Max possible for detected issues: 125
- Normalized (0-25): 9
- Risk Level: MEDIUM

#### Calculation details:
- Issue: Missing CSRF Token: Likelihood=4 × Impact=3 = 12
  - Laws: ISO 27001, GDPR
  - Recommendation: Implement anti-CSRF tokens for form submissions.
- Issue: Privacy policy missing: Likelihood=3 × Impact=3 = 9
  - Laws: GDPR, CCPA, PDPA, Bangladesh Data Protection Act 2023
  - Recommendation: Add a publicly accessible privacy policy detailing data collection and processing.
- Issue: Consent checkbox missing: Likelihood=3 × Impact=2 = 6
  - Laws: GDPR, CCPA, PDPA, COPPA
  - Recommendation: Add explicit consent checkbox for data collection with proper labeling.
- Issue: Missing Security Header: Likelihood=3 × Impact=3 = 9
  - Laws: ISO 27001, GDPR
  - Recommendation: Add recommended security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Issue: Insecure Cookies: Likelihood=3 × Impact=3 = 9
  - Laws: GDPR, PDPA
  - Recommendation: Set cookies with Secure, HttpOnly and SameSite attributes where appropriate.

### Recommendations (summary)
- Implement anti-CSRF tokens for form submissions.
- Add a publicly accessible privacy policy detailing data collection and processing.
- Add explicit consent checkbox for data collection with proper labeling.
- Add recommended security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Set cookies with Secure, HttpOnly and SameSite attributes where appropriate.

---

