# src/scanner.py
import requests
from bs4 import BeautifulSoup
import json
import re
from urllib.parse import urlparse

# -----------------------
# Colors / styling
# -----------------------
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"

# -----------------------
# Compliance mapping
# -----------------------
LAW_MAPPING = {
    "No HTTPS": {
        "laws": ["GDPR", "CCPA", "PDPA", "Bangladesh Data Protection Act 2023"],
        "recommendation": "Enable HTTPS/TLS to secure data in transit."
    },
    "Form not secure": {
        "laws": ["ISO 27001", "GDPR", "Bangladesh Digital Security Act"],
        "recommendation": "Validate and sanitize form inputs and enforce secure form handling (server-side)."
    },
    "Privacy policy missing": {
        "laws": ["GDPR", "CCPA", "PDPA", "Bangladesh Data Protection Act 2023"],
        "recommendation": "Add a publicly accessible privacy policy detailing data collection and processing."
    },
    "Consent checkbox missing": {
        "laws": ["GDPR", "CCPA", "PDPA", "COPPA"],
        "recommendation": "Add explicit consent checkbox for data collection with proper labeling."
    },
    "Missing Security Header": {
        "laws": ["ISO 27001", "GDPR"],
        "recommendation": "Add recommended security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)."
    },
    "Insecure Cookies": {
        "laws": ["GDPR", "PDPA"],
        "recommendation": "Set cookies with Secure, HttpOnly and SameSite attributes where appropriate."
    },
    "Trackers Detected": {
        "laws": ["GDPR", "CCPA"],
        "recommendation": "Disclose trackers and obtain consent where required; consider limiting third-party trackers."
    },
    "Missing CSRF Token": {
        "laws": ["ISO 27001", "GDPR"],
        "recommendation": "Implement anti-CSRF tokens for form submissions."
    }
}

# -----------------------
# Risk model defaults (per issue values)
# Each issue gets a default Likelihood (1-5) and Impact (1-5).
# You can tune these defaults to match your risk model.
# -----------------------
DEFAULT_ISSUE_RATINGS = {
    "No HTTPS":             {"likelihood": 5, "impact": 4},
    "Form not secure":      {"likelihood": 4, "impact": 3},
    "Privacy policy missing":{"likelihood": 3, "impact": 3},
    "Consent checkbox missing":{"likelihood": 3, "impact": 2},
    "Missing Security Header":{"likelihood": 3, "impact": 3},
    "Insecure Cookies":     {"likelihood": 3, "impact": 3},
    "Trackers Detected":    {"likelihood": 4, "impact": 2},
    "Missing CSRF Token":   {"likelihood": 4, "impact": 3}
}

# Helper: safe requests.get with headers and timeout
DEFAULT_HEADERS = {
    "User-Agent": "WebFormPrivacyScanner/1.0 (+https://example.com)"
}

def fetch_url(url, timeout=7):
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return r
    except Exception as e:
        return None

# -----------------------
# Scanning functions
# -----------------------

def check_https(url):
    ok = url.lower().startswith("https://")
    msg = "HTTPS enabled" if ok else "⚠ Site does NOT use HTTPS"
    return ok, msg

def check_form_security(soup, base_url=None):
    """
    Analyze forms: count forms, look for password fields, CSRF tokens, form action (http vs https)
    """
    forms = soup.find_all("form")
    if not forms:
        return False, "⚠ No forms detected", {}

    details = {"forms_count": len(forms), "password_fields": 0, "csrf_tokens": 0, "form_actions_insecure": 0}
    for f in forms:
        # count password fields
        pwd_fields = f.find_all("input", {"type": "password"})
        details["password_fields"] += len(pwd_fields)

        # detect anti-CSRF tokens: common name/id patterns: csrf, token, _csrf, authenticity_token
        inputs = f.find_all("input")
        for inp in inputs:
            name = inp.get("name", "") or ""
            id_ = inp.get("id", "") or ""
            if re.search(r"(csrf|token|authenticity_token|_csrf|csrfmiddlewaretoken)", name, re.I) or \
               re.search(r"(csrf|token|authenticity_token|_csrf|csrfmiddlewaretoken)", id_, re.I):
                details["csrf_tokens"] += 1

        # form action protocol check
        action = f.get("action", "") or ""
        if action:
            # if action is absolute url
            if action.startswith("http://"):
                details["form_actions_insecure"] += 1
            elif action.startswith("//"):
                # scheme-relative, may inherit http or https; can't be sure
                details["form_actions_insecure"] += 0
            else:
                # relative form actions are usually fine (server-side)
                pass

    summary_msg = f"{details['forms_count']} form(s) detected — password fields: {details['password_fields']}, csrf tokens: {details['csrf_tokens']}, insecure actions: {details['form_actions_insecure']}"
    return True, summary_msg, details

def check_privacy_policy(soup):
    links = soup.find_all("a")
    for link in links:
        href = (link.get("href") or "").lower()
        text = (link.get_text() or "").lower()
        if "privacy" in href or "privacy" in text:
            return True, "Privacy policy link found"
    return False, "⚠ Privacy policy link NOT found"

def check_consent_checkbox(soup):
    inputs = soup.find_all("input")
    for i in inputs:
        itype = (i.get("type") or "").lower()
        name = (i.get("name") or "").lower()
        id_ = (i.get("id") or "").lower()
        if itype == "checkbox" and ("consent" in name or "consent" in id_ or "agree" in name or "agree" in id_):
            return True, "Consent checkbox found"
    return False, "⚠ Consent checkbox NOT found"

def check_security_headers(response):
    if response is None:
        return False, "No HTTP response", {}

    headers = response.headers
    missing = []
    found = {}
    keys = {
        "Content-Security-Policy": "CSP",
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy"
    }
    for k in keys:
        if k in headers:
            found[keys[k]] = headers.get(k)
        else:
            missing.append(keys[k])
    if missing:
        msg = f"Missing headers: {', '.join(missing)}"
        return False, msg, {"found": found, "missing": missing}
    else:
        msg = "All recommended security headers present"
        return True, msg, {"found": found, "missing": []}

def check_cookies(response):
    """
    Look at Set-Cookie header(s) if any and check attributes.
    requests.Response.cookies gives CookieJar for client cookies; to inspect Set-Cookie attributes we need headers.
    """
    if response is None:
        return False, "No HTTP response", {}

    set_cookie_headers = response.headers.get("Set-Cookie")
    if not set_cookie_headers:
        return False, "No cookies set by server", {"cookies": []}

    # There might be multiple Set-Cookie headers concatenated; try to split by comma carefully.
    # A simple approach: use response.headers.get_all if available, otherwise split by ', ' may break on cookie values.
    raw = response.headers.get_all("Set-Cookie") if hasattr(response.headers, "get_all") else [set_cookie_headers]
    cookies_info = []
    insecure_count = 0
    for raw_cookie in raw:
        # raw_cookie ~ "name=value; Path=/; HttpOnly; Secure; SameSite=Lax"
        attrs = [p.strip() for p in raw_cookie.split(";")]
        name_val = attrs[0] if attrs else raw_cookie
        flags = { "HttpOnly": False, "Secure": False, "SameSite": None }
        for a in attrs[1:]:
            if a.lower() == "httponly":
                flags["HttpOnly"] = True
            elif a.lower() == "secure":
                flags["Secure"] = True
            elif a.lower().startswith("samesite"):
                parts = a.split("=")
                if len(parts) == 2:
                    flags["SameSite"] = parts[1]
        cookies_info.append({"cookie": name_val, "flags": flags})
        if not flags["Secure"] or not flags["HttpOnly"]:
            insecure_count += 1

    summary = f"{len(cookies_info)} cookie(s) detected, {insecure_count} cookie(s) missing Secure/HttpOnly"
    return (insecure_count == 0), summary, {"cookies": cookies_info, "insecure_count": insecure_count}

def detect_js_trackers(soup):
    """
    Simple heuristic: look for known tracker keywords in script src or inline scripts
    """
    tracker_patterns = {
        "GoogleAnalytics": [r"google-analytics", r"gtag\(", r"analytics.js", r"ga\("],
        "GoogleTagManager": [r"googletagmanager", r"gtm.js"],
        "FacebookPixel": [r"connect.facebook.net", r"fbq\("],
        "TikTok": [r"tiktok", r"analytics.tiktok"],
        "DoubleClick": [r"doubleclick", r"googlesyndication"],
        "Hotjar": [r"hotjar"],
    }
    found = []
    # search script src attributes
    for s in soup.find_all("script"):
        src = (s.get("src") or "").lower()
        text = (s.string or "") or ""
        combined = src + " " + text.lower()
        for name, pats in tracker_patterns.items():
            for pat in pats:
                if pat in combined:
                    if name not in found:
                        found.append(name)
    if found:
        return True, f"Trackers detected: {', '.join(found)}", {"trackers": found}
    return False, "No common trackers auto-detected", {"trackers": []}

# -----------------------
# Risk calculation & reporting
# -----------------------

def calculate_issue_score(issue_key, override_rating=None):
    """
    Returns (likelihood, impact, score)
    If override_rating provided, it should be dict {"likelihood":int, "impact":int}
    """
    base = DEFAULT_ISSUE_RATINGS.get(issue_key, {"likelihood": 3, "impact": 3})
    if override_rating:
        l = override_rating.get("likelihood", base["likelihood"])
        i = override_rating.get("impact", base["impact"])
    else:
        l = base["likelihood"]
        i = base["impact"]
    score = l * i  # 5x5 matrix product value
    return l, i, score

def compute_risk(issues_detected):
    """
    issues_detected: list of issue keys, e.g. ["No HTTPS", "Privacy policy missing", ...]
    Returns a dict with per-issue breakdown and aggregate totals and level.
    """
    breakdown = []
    total_score = 0
    max_possible = 0
    for issue in issues_detected:
        l, i, s = calculate_issue_score(issue)
        breakdown.append({
            "issue": issue,
            "likelihood": l,
            "impact": i,
            "score": s,
            "laws": LAW_MAPPING.get(issue, {}).get("laws", []),
            "recommendation": LAW_MAPPING.get(issue, {}).get("recommendation", "")
        })
        total_score += s
        max_possible += 5 * 5  # each issue max 25

    # Normalize to percentage of max and then map to a 0-25 like scale for human-friendly labels
    percent = (total_score / max_possible) if max_possible > 0 else 0
    normalized_0_25 = round(percent * 25)

    # Determine severity
    if percent >= 0.66:
        level = "HIGH"
        level_color = RED
    elif percent >= 0.33:
        level = "MEDIUM"
        level_color = YELLOW
    else:
        level = "LOW"
        level_color = GREEN

    return {
        "breakdown": breakdown,
        "raw_total": total_score,
        "max_total": max_possible,
        "percent": percent,
        "normalized_score": normalized_0_25,
        "level": level,
        "level_color": level_color
    }

def scan_webform(url):
    """
    Runs all checks for a single URL and returns a structured result dict.
    """
    response = fetch_url(url)
    soup = None
    if response and response.text:
        soup = BeautifulSoup(response.text, "html.parser")

    results = {
        "url": url,
        "checks": {},
        "issues": [],
        "recommendations": [],
        "laws": [],
        "details": {},
    }

    # HTTPS
    https_ok, https_msg = check_https(url)
    results["checks"]["https"] = {"ok": https_ok, "msg": https_msg}
    if not https_ok:
        results["issues"].append("No HTTPS")

    # Forms
    if soup:
        form_ok, form_msg, form_details = check_form_security(soup, base_url=url)
    else:
        form_ok, form_msg, form_details = False, "No response / cannot parse", {}
    results["checks"]["forms"] = {"ok": form_ok, "msg": form_msg, "meta": form_details}
    if not form_ok:
        results["issues"].append("Form not secure")
    else:
        # If forms exist but missing CSRF tokens, register issue
        if form_details.get("csrf_tokens", 0) == 0:
            results["issues"].append("Missing CSRF Token")
        # If password fields present but not HTTPS, flag as form not secure
        if form_details.get("password_fields", 0) > 0 and not https_ok:
            # but "No HTTPS" already added; this can be an additional detail
            pass

    # Privacy policy
    if soup:
        privacy_ok, privacy_msg = check_privacy_policy(soup)
    else:
        privacy_ok, privacy_msg = False, "No response / cannot parse"
    results["checks"]["privacy_policy"] = {"ok": privacy_ok, "msg": privacy_msg}
    if not privacy_ok:
        results["issues"].append("Privacy policy missing")

    # Consent checkbox
    if soup:
        consent_ok, consent_msg = check_consent_checkbox(soup)
    else:
        consent_ok, consent_msg = False, "No response / cannot parse"
    results["checks"]["consent"] = {"ok": consent_ok, "msg": consent_msg}
    if not consent_ok:
        results["issues"].append("Consent checkbox missing")

    # Security headers
    sec_ok, sec_msg, sec_meta = check_security_headers(response)
    results["checks"]["security_headers"] = {"ok": sec_ok, "msg": sec_msg, "meta": sec_meta}
    if not sec_ok:
        results["issues"].append("Missing Security Header")

    # Cookies
    cookie_ok, cookie_msg, cookie_meta = check_cookies(response)
    results["checks"]["cookies"] = {"ok": cookie_ok, "msg": cookie_msg, "meta": cookie_meta}
    if not cookie_ok and cookie_meta.get("insecure_count", 0) > 0:
        results["issues"].append("Insecure Cookies")

    # Trackers
    trackers_ok, trackers_msg, trackers_meta = (False, "No response", {"trackers": []})
    if soup:
        trackers_ok, trackers_msg, trackers_meta = detect_js_trackers(soup)
    results["checks"]["trackers"] = {"ok": trackers_ok, "msg": trackers_msg, "meta": trackers_meta}
    if trackers_meta and trackers_meta.get("trackers"):
        results["issues"].append("Trackers Detected")

    # Compose unique laws & recommendations
    law_set = set()
    recs = []
    for iss in results["issues"]:
        lm = LAW_MAPPING.get(iss, {})
        for law in lm.get("laws", []):
            law_set.add(law)
        rec = lm.get("recommendation")
        if rec:
            recs.append(rec)

    results["laws"] = list(law_set)
    results["recommendations"] = recs

    # Risk computation
    risk = compute_risk(results["issues"])
    results["risk"] = risk

    # Prepare JSON-friendly result and return
    return results

def generate_json_report(result, filename=None):
    if not filename:
        parsed = urlparse(result["url"])
        safe = parsed.netloc + parsed.path
        safe = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", safe).strip("_")
        filename = f"compliance_summary_{safe}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return filename

def generate_markdown_report(all_results, filename="report.md"):
    """
    all_results: list of result dicts
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write("# WebForm Privacy Compliance - Combined Report\n\n")
        for r in all_results:
            f.write(f"## URL: {r['url']}\n\n")
            f.write(f"### Checks\n")
            for k, v in r["checks"].items():
                status = "OK" if v.get("ok") else "⚠ NOT OK"
                f.write(f"- **{k}**: {status} — {v.get('msg')}\n")
            f.write("\n### Issues Detected\n")
            if r["issues"]:
                for iss in r["issues"]:
                    f.write(f"- {iss}\n")
            else:
                f.write("- None\n")

            f.write("\n### Risk Breakdown\n")
            f.write(f"- Raw total (sum of Likelihood×Impact per issue): {r['risk']['raw_total']}\n")
            f.write(f"- Max possible for detected issues: {r['risk']['max_total']}\n")
            f.write(f"- Normalized (0-25): {r['risk']['normalized_score']}\n")
            f.write(f"- Risk Level: {r['risk']['level']}\n\n")

            f.write("#### Calculation details:\n")
            for b in r['risk']['breakdown']:
                f.write(f"- Issue: {b['issue']}: Likelihood={b['likelihood']} × Impact={b['impact']} = {b['score']}\n")
                if b.get("laws"):
                    f.write(f"  - Laws: {', '.join(b.get('laws'))}\n")
                if b.get("recommendation"):
                    f.write(f"  - Recommendation: {b.get('recommendation')}\n")

            f.write("\n### Recommendations (summary)\n")
            if r['recommendations']:
                for rec in r['recommendations']:
                    f.write(f"- {rec}\n")
            else:
                f.write("- No recommendations (site looks good)\n")
            f.write("\n---\n\n")
    return filename
