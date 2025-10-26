#!/usr/bin/env python3
import os
import re
import argparse

# Basic test patterns (regex) for A1-A10 OWASP
CHECK_PATTERNS = {
    "A1-Injection": [
        r"mysql_query\s*\(", r"mysqli_query\s*\(", r"\bexec\s*\(",
        r"shell_exec\s*\(", r"\bsystem\s*\(", r"\bpassthru\s*\(",
        r"\beval\s*\(", r"preg_replace\s*\(.*\/e.*\)"
    ],
    "A2-Broken_Auth_Session": [
        r"\bmd5\s*\(", r"\bsha1\s*\(", r"password\s*=\s*['\"]",
        r"session_id\s*\(", r"setcookie\s*\("
    ],
    "A3-XSS": [
        r"echo\s*\$_(GET|POST|REQUEST)\[", r"print\s*\$_(GET|POST|REQUEST)\[",
        r"\$_(GET|POST|REQUEST)\[.*\]\s*\."
    ],
    "A4-IDOR": [
        r"\$_(GET|POST|REQUEST)\[.*id.*\]", r"include\s*\(.*\$_", r"require\s*\(.*\$_"
    ],
    "A5-Security_Misconfig": [
        r"phpinfo\s*\(", r"ini_get_all\s*\(", r"display_errors\s*=\s*['\"]on['\"]"
    ],
    "A6-Sensitive_Data_Exposure": [
        r"setcookie\s*\(.*password", r"echo\s*.*password", r"base64_encode\s*\("
    ],
    "A7-Missing_Access_Control": [
        r"\bdelete\s*\(", r"\bunlink\s*\(", r"\bchmod\s*\("
    ],
    "A8-CSRF": [
        r"<form[^>]*method=['\"]post['\"][^>]*>"
    ],
    "A9-Components_with_Vuln": [
        r"require\s*['\"].*old.*['\"]", r"include\s*['\"].*old.*['\"]"
    ],
    "A10-Unvalidated_Redirects": [
        r"header\s*\(\s*['\"]Location:\s*.*\$_(GET|POST|REQUEST)"
    ],
}

# scan file or directory
def scan_php_file(file_path):
    issues = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return [{"error": f"Cannot read file: {e}"}]

    for vuln, patterns in CHECK_PATTERNS.items():
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_no = content[:match.start()].count("\n") + 1
                    lines = content.splitlines()
                    line_text = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else ""
                    start_ctx = max(0, match.start() - 60)
                    end_ctx = min(len(content), match.end() + 60)
                    context = content[start_ctx:end_ctx].replace("\n", " ").strip()
                    issues.append({
                        "vulnerability": vuln,
                        "line": line_no,
                        "line_text": line_text,
                        "context": context
                    })
            except re.error:
                continue
    return issues

def review_path(path):
    total = 0
    if os.path.isfile(path):
        if not path.lower().endswith(".php"):
            print(f"[!] File {path} is not a PHP file — still scanning but may not find anything.")
        print("="*80)
        print(f"Scanning file: {path}")
        print("-"*80)
        issues = scan_php_file(path)
        if not issues:
            print("No suspicious code found in this file.")
        else:
            for it in issues:
                if "error" in it:
                    print(f"[ERROR] {it['error']}")
                    continue
                total += 1
                print(f"[{it['vulnerability']}] (Line {it['line']}) ➜ {it['line_text']}")
                print(f"    context: {it['context']}")
        print("="*80)
    elif os.path.isdir(path):
        print("="*80)
        print(f"====STARTING DIRECTORY SCAN: {path}====")
        print("="*80)
        for root, _, files in os.walk(path):
            for f in files:
                if f.lower().endswith(".php"):
                    full = os.path.join(root, f)
                    issues = scan_php_file(full)
                    if issues:
                        print(f"\n * File: {full}")
                        print("-"*80)
                        for it in issues:
                            if "error" in it:
                                print(f"[ERROR] {it['error']}")
                                continue
                            total += 1
                            print(f"[{it['vulnerability']}] (Line {it['line']}) ➜ {it['line_text']}")
                            print(f"    context: {it['context']}")
        if total == 0:
            print("\n✅ No potential vulnerabilities found in the directory.")
        else:
            print(f"\n⚠ Total of {total} suspicious locations detected.")
        print("="*80)
    else:
        print(f"[!] Path does not exist: {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Code Review - scan file or directory")
    parser.add_argument("path", help="Path to PHP file or directory containing PHP code")
    args = parser.parse_args()
    review_path(args.path)
