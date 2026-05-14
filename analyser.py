import hashlib
import requests
import re
import os
import time
from datetime import datetime
from colorama import init, Fore, Style
from jinja2 import Template

init(autoreset=True)

NIST_MIN_LENGTH = 15
NIST_MAX_LENGTH = 64

COMMON_PASSWORDS = [
    "password", "password1", "123456", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football",
    "welcome", "admin", "login", "pass", "test",
    "welcome1", "admin123", "password123", "p@ssword",
    "p@ssw0rd", "summer2024", "winter2024", "spring2024"
]


def check_hibp(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "PasswordAnalyser-SecurityProject"},
            timeout=10
        )

        if response.status_code != 200:
            return False, 0

        for line in response.text.splitlines():
            returned_suffix, count = line.split(":")
            if returned_suffix == suffix:
                return True, int(count)

        return False, 0

    except requests.RequestException:
        print(Fore.YELLOW + "  Warning: Could not reach HaveIBeenPwned API")
        return False, 0


def analyse_password(password):
    findings = []
    passed = []
    score = 100

    if len(password) < 8:
        findings.append({
            "rule": "Minimum Length",
            "severity": "CRITICAL",
            "detail": f"Password is only {len(password)} characters. NIST SP 800-63B requires at least 8 characters minimum, with 15 strongly recommended.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 40
    elif len(password) < NIST_MIN_LENGTH:
        findings.append({
            "rule": "Recommended Length",
            "severity": "MEDIUM",
            "detail": f"Password is {len(password)} characters. NIST SP 800-63B Rev 4 recommends a minimum of {NIST_MIN_LENGTH} characters for single-factor authentication.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 20
    else:
        passed.append(f"Length is {len(password)} characters - meets NIST minimum of {NIST_MIN_LENGTH}")

    if len(password) > NIST_MAX_LENGTH:
        findings.append({
            "rule": "Maximum Length",
            "severity": "LOW",
            "detail": f"Password exceeds {NIST_MAX_LENGTH} characters. NIST recommends systems support up to 64 characters.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 5

    sequential_patterns = [
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "0123456789"
    ]

    found_sequential = False
    for pattern in sequential_patterns:
        for i in range(len(pattern) - 3):
            if pattern[i:i+4].lower() in password.lower():
                findings.append({
                    "rule": "Sequential Characters",
                    "severity": "HIGH",
                    "detail": f"Password contains sequential characters ('{pattern[i:i+4]}'). These patterns are easily guessed by automated attack tools.",
                    "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
                })
                score -= 25
                found_sequential = True
                break
        if found_sequential:
            break

    if not found_sequential:
        passed.append("No sequential character patterns detected")

    repetitive = re.search(r"(.)\1{3,}", password)
    if repetitive:
        findings.append({
            "rule": "Repetitive Characters",
            "severity": "HIGH",
            "detail": f"Password contains repetitive characters ('{repetitive.group()}'). Repetitive patterns significantly reduce password entropy.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 25
    else:
        passed.append("No repetitive character patterns detected")

    if password.lower() in COMMON_PASSWORDS:
        findings.append({
            "rule": "Common Password Blacklist",
            "severity": "CRITICAL",
            "detail": "Password appears on the common passwords blocklist. NIST SP 800-63B requires passwords be screened against lists of commonly used and previously breached values.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 50
    else:
        passed.append("Not found on common password blocklist")

    print(f"  Checking HaveIBeenPwned API...", end=" ", flush=True)
    is_pwned, pwned_count = check_hibp(password)

    if is_pwned:
        severity = "CRITICAL" if pwned_count > 10000 else "HIGH"
        findings.append({
            "rule": "HaveIBeenPwned Database",
            "severity": severity,
            "detail": f"Password has been found {pwned_count:,} times in known data breaches. NIST SP 800-63B requires passwords be checked against breach databases. This password must not be used.",
            "nist_ref": "NIST SP 800-63B Rev 4 Section 3.1.1"
        })
        score -= 60 if pwned_count > 10000 else 40
        print(Fore.RED + f"FOUND ({pwned_count:,} times)")
    else:
        passed.append("Not found in HaveIBeenPwned breach database")
        print(Fore.GREEN + "CLEAN")

    time.sleep(0.5)

    score = max(0, score)

    if score >= 80:
        risk_rating = "LOW"
        risk_colour = "green"
    elif score >= 50:
        risk_rating = "MEDIUM"
        risk_colour = "orange"
    elif score >= 20:
        risk_rating = "HIGH"
        risk_colour = "red"
    else:
        risk_rating = "CRITICAL"
        risk_colour = "darkred"

    return {
        "password": password,
        "masked": password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***",
        "length": len(password),
        "score": score,
        "risk_rating": risk_rating,
        "risk_colour": risk_colour,
        "findings": findings,
        "passed": passed,
        "is_pwned": is_pwned,
        "pwned_count": pwned_count,
        "findings_count": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "CRITICAL"]),
        "high_count": len([f for f in findings if f["severity"] == "HIGH"]),
        "medium_count": len([f for f in findings if f["severity"] == "MEDIUM"]),
    }


def load_passwords(filename):
    try:
        with open(filename, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
        return passwords
    except FileNotFoundError:
        print(Fore.RED + f"Error: File '{filename}' not found.")
        return []


def generate_report(results, output_path):
    try:
        with open("report_template.html", "r") as f:
            template_str = f.read()
    except FileNotFoundError:
        print(Fore.RED + "Error: report_template.html not found.")
        return

    template = Template(template_str)

    total = len(results)
    critical_count = len([r for r in results if r["risk_rating"] == "CRITICAL"])
    high_count = len([r for r in results if r["risk_rating"] == "HIGH"])
    medium_count = len([r for r in results if r["risk_rating"] == "MEDIUM"])
    low_count = len([r for r in results if r["risk_rating"] == "LOW"])
    pwned_count = len([r for r in results if r["is_pwned"]])
    avg_score = sum(r["score"] for r in results) // total if total > 0 else 0
    below_nist_length = len([r for r in results if r["length"] < NIST_MIN_LENGTH])

    html = template.render(
        results=results,
        total=total,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        pwned_count=pwned_count,
        avg_score=avg_score,
        below_nist_length=below_nist_length,
        nist_min_length=NIST_MIN_LENGTH,
        generated_at=datetime.now().strftime("%d %B %Y at %H:%M:%S"),
        nist_version="NIST SP 800-63B Revision 4 (August 2025)"
    )

    os.makedirs("output", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    print(Fore.GREEN + f"\nReport saved to: {output_path}")


def print_summary(results):
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "  ANALYSIS SUMMARY")
    print(Fore.CYAN + "=" * 60)

    for r in results:
        colour = (Fore.RED if r["risk_rating"] in ["CRITICAL", "HIGH"]
                  else Fore.YELLOW if r["risk_rating"] == "MEDIUM"
                  else Fore.GREEN)
        print(
            f"  {colour}{r['risk_rating']:<10}{Style.RESET_ALL} | "
            f"Score: {r['score']:<3} | "
            f"HIBP: {'YES' if r['is_pwned'] else 'NO':<4} | "
            f"{r['masked']}"
        )

    print(Fore.CYAN + "=" * 60)
    total = len(results)
    pwned = len([r for r in results if r["is_pwned"]])
    critical = len([r for r in results if r["risk_rating"] == "CRITICAL"])

    print(f"\n  Total analysed : {total}")
    print(f"  Found in HIBP  : {Fore.RED}{pwned}{Style.RESET_ALL}")
    print(f"  Critical risk  : {Fore.RED}{critical}{Style.RESET_ALL}")
    print(f"  Below NIST min : {Fore.YELLOW}{len([r for r in results if r['length'] < NIST_MIN_LENGTH])}{Style.RESET_ALL}")


def main():
    print(Fore.WHITE + "Loading passwords from passwords.txt...")
    passwords = load_passwords("passwords.txt")

    if not passwords:
        print(Fore.RED + "No passwords to analyse. Exiting.")
        return

    print(Fore.WHITE + f"Loaded {len(passwords)} passwords\n")
    print(Fore.WHITE + "Analysing passwords against NIST SP 800-63B Rev 4...\n")
    print("-" * 60)

    results = []
    for i, password in enumerate(passwords, 1):
        print(Fore.WHITE + f"[{i}/{len(passwords)}] Analysing: {password[0]}{'*' * (len(password)-2)}{password[-1] if len(password) > 1 else ''}")
        result = analyse_password(password)
        results.append(result)
        print()

    print_summary(results)

    print(Fore.WHITE + "\nGenerating HTML report...")
    generate_report(results, "output/report.html")
    print(Fore.GREEN + "Done. Open output/report.html in your browser.")


if __name__ == "__main__":
    main()