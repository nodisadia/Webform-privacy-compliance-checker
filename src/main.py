from scanner import check_https, check_form_security, check_privacy_policy, check_consent_checkbox, calculate_risk, generate_report
from colorama import Fore, Style

def print_banner():
    print("""
=============================================
  Privacy-Focused Web Form Compliance Checker
                 v1.0
=============================================
""")

def main():
    print_banner()
    url = input("Enter website URL: ")

    print("\n--- Running Privacy Compliance Check ---\n")

    https_ok, https_msg = check_https(url)
    print("[HTTPS CHECK]:", https_msg)

    form_ok, form_msg = check_form_security(url)
    print("[FORM CHECK]:", form_msg)

    privacy_ok, privacy_msg = check_privacy_policy(url)
    print("[PRIVACY POLICY]:", privacy_msg)

    consent_ok, consent_msg = check_consent_checkbox(url)
    print("[CONSENT CHECKBOX]:", consent_msg)

    # Risk Scoring & Compliance Mapping
    score, level, issues, laws, recommendations = calculate_risk(https_ok, form_ok, privacy_ok, consent_ok)

    # Terminal output
    if level == "HIGH":
        print(Fore.RED + f"\n[RISK SCORE]: {score} ({level})" + Style.RESET_ALL)
    elif level == "MEDIUM":
        print(Fore.YELLOW + f"\n[RISK SCORE]: {score} ({level})" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"\n[RISK SCORE]: {score} ({level})" + Style.RESET_ALL)

    print("\nIssues detected:", issues)
    print("Relevant compliance laws:", laws)
    print("Recommended actions:")
    for rec in recommendations:
        print("-", rec)

    # Generate Markdown Report
    generate_report(url, https_ok, form_ok, privacy_ok, consent_ok, score, level, issues, laws, recommendations)
    print("\n[✓] Report generated as report.md")

if __name__ == "__main__":
    main()
