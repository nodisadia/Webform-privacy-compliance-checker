# src/main.py
from scanner import (
    scan_webform, generate_json_report, generate_markdown_report,
    CYAN, GREEN, YELLOW, RED, MAGENTA, BLUE, WHITE, BOLD, RESET
)
import os

def print_header():
    print("""
\033[1;35m██████████████████████████████████████████████\033[0m
\033[1;92m     WEBFORM PRIVACY COMPLIANCE CHECKER     \033[0m
\033[1;35m██████████████████████████████████████████████\033[0m

\033[1;96mVersion : v1.0\033[0m
\033[1;96mAuthor  : Nodi Sadia\033[0m
\033[1;96mGitHub  : https://github.com/nodisadia/Webform-privacy-compliance-checker\033[0m
\033[1;96mLicense : MIT\033[0m
""")

def get_urls_from_user():
    print(WHITE + "Enter website URLs to scan (multiple allowed)." + RESET)
    print(YELLOW + "You can enter URLs one-by-one (type 'done' when finished) or type 'file' to read from a file." + RESET)
    urls = []
    while True:
        u = input(BOLD + "Enter URL / file / done: " + RESET).strip()
        if not u:
            continue
        if u.lower() == "done":
            break
        if u.lower() == "file":
            filename = input("Enter filename with URLs (one per line): ").strip()
            if not os.path.exists(filename):
                print(RED + "File not found." + RESET)
                continue
            with open(filename, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        urls.append(line)
            print(GREEN + f"{len(urls)} URL(s) loaded from file." + RESET)
            break
        if not u.startswith("http://") and not u.startswith("https://"):
            print(RED + "Please start URL with http:// or https://" + RESET)
            continue
        urls.append(u)
    return urls

def pretty_print_result(r):
    print()
    print(BLUE + ("="*70) + RESET)
    print(BOLD + f"Scan result for: {r['url']}" + RESET)
    print(BLUE + ("="*70) + RESET)

    for k, v in r["checks"].items():
        ok = v.get("ok")
        msg = v.get("msg")
        color = GREEN if ok else RED
        print(f"{BOLD}{k.upper():<18}{RESET}: {color}{msg}{RESET}")

    print()
    level_color = r["risk"]["level_color"]
    print(YELLOW + "--- Risk Calculation Breakdown (5x5 matrix style) ---" + RESET)
    for b in r["risk"]["breakdown"]:
        print(f"{WHITE}- {b['issue']}: {BOLD}L={b['likelihood']}{RESET}{WHITE} × {BOLD}I={b['impact']}{RESET}{WHITE} = {BOLD}{b['score']}{RESET}")

    print()
    print(f"{WHITE}Raw total:{RESET} {BOLD}{r['risk']['raw_total']}{RESET} / {r['risk']['max_total']}")
    print(f"{WHITE}Normalized (0-25):{RESET} {BOLD}{r['risk']['normalized_score']}{RESET}")
    print(f"{WHITE}Risk Level:{RESET} {level_color}{r['risk']['level']}{RESET}")

    if r['issues']:
        print()
        print(RED + "Issues Identified:" + RESET)
        for iss in r['issues']:
            print(f" - {iss}")
    else:
        print(GREEN + "No major issues detected." + RESET)

    if r['recommendations']:
        print()
        print(GREEN + "Recommended Actions:" + RESET)
        for rec in r['recommendations']:
            print(f" - {rec}")

    if r['laws']:
        print()
        print(MAGENTA + "Relevant Laws:" + RESET)
        for law in r['laws']:
            print(f" - {law}")

    print(BLUE + ("-"*70) + RESET)
    print()

def main():
    print_header()
    urls = get_urls_from_user()
    if not urls:
        print(RED + "No URLs provided. Exiting." + RESET)
        return

    all_results = []
    for url in urls:
        print(CYAN + f"\nScanning {url} ..." + RESET)
        r = scan_webform(url)
        all_results.append(r)
        pretty_print_result(r)
        json_file = generate_json_report(r)
        print(GREEN + f"[+] JSON summary saved to: {json_file}" + RESET)

    md_file = generate_markdown_report(all_results)
    print(GREEN + f"\n[+] Combined markdown report saved to: {md_file}" + RESET)
    print(GREEN + "\nAll scans complete." + RESET)

if __name__ == "__main__":
    main()
