import requests
from bs4 import BeautifulSoup

# Compliance law mapping and recommendations
LAW_MAPPING = {
    "No HTTPS": {
        "laws": ["GDPR", "CCPA", "PDPA", "Bangladesh Data Protection Act 2023"],
        "recommendation": "Enable HTTPS/TLS to secure data in transit"
    },
    "Form not secure": {
        "laws": ["ISO 27001", "GDPR", "Bangladesh Digital Security Act"],
        "recommendation": "Validate and sanitize form inputs, enforce strong passwords"
    },
    "Privacy policy missing": {
        "laws": ["GDPR", "CCPA", "PDPA", "Bangladesh Data Protection Act 2023"],
        "recommendation": "Add a publicly accessible privacy policy detailing data collection and processing"
    },
    "Consent checkbox missing": {
        "laws": ["GDPR", "CCPA", "PDPA", "COPPA"],
        "recommendation": "Add explicit consent checkbox for data collection with proper labeling"
    }
}

# --- Scanning functions ---

def check_https(url):
    if url.startswith("https://"):
        return True, "Site uses HTTPS"
    else:
        return False, "⚠ Site does NOT use HTTPS"

def check_form_security(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if forms:
            return True, "Forms look secure"
        return False, "⚠ No forms detected"
    except:
        return False, "⚠ Error checking forms"

def check_privacy_policy(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link.get("href", "").lower()
            text = link.get_text().lower()
            if "privacy" in href or "privacy" in text:
                return True, "Privacy policy link found"
        return False, "⚠ Privacy policy link NOT found"
    except:
        return False, "⚠ Error scanning site"

def check_consent_checkbox(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        inputs = soup.find_all("input")
        for i in inputs:
            if i.get("type") == "checkbox" and ("consent" in i.get("name", "").lower() or "consent" in i.get("id", "").lower()):
                return True, "Consent checkbox found"
        return False, "⚠ Consent checkbox NOT found"
    except:
        return False, "⚠ Error scanning site"

# --- Risk scoring function ---

def calculate_risk(https_ok, form_ok, privacy_ok, consent_ok):
    score = 0
    issues = []
    recommendations = []
    laws = []

    if not https_ok:
        score += 5
        issues.append("No HTTPS")
        laws.extend(LAW_MAPPING["No HTTPS"]["laws"])
        recommendations.append(LAW_MAPPING["No HTTPS"]["recommendation"])
    if not form_ok:
        score += 4
        issues.append("Form not secure")
        laws.extend(LAW_MAPPING["Form not secure"]["laws"])
        recommendations.append(LAW_MAPPING["Form not secure"]["recommendation"])
    if not privacy_ok:
        score += 3
        issues.append("Privacy policy missing")
        laws.extend(LAW_MAPPING["Privacy policy missing"]["laws"])
        recommendations.append(LAW_MAPPING["Privacy policy missing"]["recommendation"])
    if not consent_ok:
        score += 3
        issues.append("Consent checkbox missing")
        laws.extend(LAW_MAPPING["Consent checkbox missing"]["laws"])
        recommendations.append(LAW_MAPPING["Consent checkbox missing"]["recommendation"])

    if score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, issues, list(set(laws)), recommendations

# --- Report generation ---

def generate_report(url, https_ok, form_ok, privacy_ok, consent_ok, score, level, issues, laws, recommendations):
    with open("report.md", "w") as f:
        f.write(f"# Webform Privacy Compliance Report\n\n")
        f.write(f"## URL: {url}\n\n")
        f.write(f"### HTTPS Check: {'OK' if https_ok else '⚠ NOT OK'}\n")
        f.write(f"### Form Security: {'OK' if form_ok else '⚠ NOT OK'}\n")
        f.write(f"### Privacy Policy: {'Found' if privacy_ok else '⚠ NOT FOUND'}\n")
        f.write(f"### Consent Checkbox: {'Found' if consent_ok else '⚠ NOT FOUND'}\n\n")
        f.write(f"## Risk Score: {score}\n")
        f.write(f"## Risk Level: {level}\n\n")

        f.write("### Issues Detected:\n")
        for i in issues:
            f.write(f"- {i}\n")

        f.write("\n### Relevant Compliance Laws:\n")
        for law in laws:
            f.write(f"- {law}\n")

        f.write("\n### Recommended Actions:\n")
        for rec in recommendations:
            f.write(f"- {rec}\n")
