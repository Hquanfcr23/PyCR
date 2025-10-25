#!/usr/bin/env python3
import os
import re
import argparse

# === Các mẫu kiểm tra cơ bản (regex) cho OWASP A1-A10 ===
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
        r"<form[^>]*method=['\"]post['\"][^>]*>"  # detect POST forms (may be false positives)
    ],
    "A9-Components_with_Vuln": [
        r"require\s*['\"].*old.*['\"]", r"include\s*['\"].*old.*['\"]"
    ],
    "A10-Unvalidated_Redirects": [
        r"header\s*\(\s*['\"]Location:\s*.*\$_(GET|POST|REQUEST)"
    ],
}

# === Quét một file PHP duy nhất ===
def scan_php_file(file_path):
    issues = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return [{"error": f"Không thể đọc file: {e}"}]

    for vuln, patterns in CHECK_PATTERNS.items():
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # số dòng chứa match
                    line_no = content[:match.start()].count("\n") + 1
                    # lấy một đoạn context (dòng hiện tại)
                    lines = content.splitlines()
                    line_text = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else ""
                    # thêm context ngắn xung quanh (tùy ý)
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
                # nếu pattern regex lỗi (không hợp lệ), bỏ qua pattern đó
                continue
    return issues

# === Quét đường dẫn: file hoặc thư mục ===
def review_path(path):
    total = 0
    if os.path.isfile(path):
        if not path.lower().endswith(".php"):
            print(f"[!] File {path} không phải file .php — vẫn cố quét nhưng có thể không tìm được gì.")
        print("="*80)
        print(f"📄 Quét file: {path}")
        print("-"*80)
        issues = scan_php_file(path)
        if not issues:
            print("✅ Không phát hiện vị trí nghi ngờ nào trong file này.")
        else:
            for it in issues:
                if "error" in it:
                    print(f"[ERROR] {it['error']}")
                    continue
                total += 1
                print(f"[{it['vulnerability']}] (Dòng {it['line']}) ➜ {it['line_text']}")
                # in context ngắn để dễ hiểu vị trí
                print(f"    context: {it['context']}")
        print("="*80)
    elif os.path.isdir(path):
        print("="*80)
        print(f"🔍 BẮT ĐẦU KIỂM DUYỆT THƯ MỤC: {path}")
        print("="*80)
        for root, _, files in os.walk(path):
            for f in files:
                if f.lower().endswith(".php"):
                    full = os.path.join(root, f)
                    issues = scan_php_file(full)
                    if issues:
                        print(f"\n📄 File: {full}")
                        print("-"*80)
                        for it in issues:
                            if "error" in it:
                                print(f"[ERROR] {it['error']}")
                                continue
                            total += 1
                            print(f"[{it['vulnerability']}] (Dòng {it['line']}) ➜ {it['line_text']}")
                            print(f"    context: {it['context']}")
        if total == 0:
            print("\n✅ Không phát hiện lỗ hổng đáng chú ý nào trong thư mục.")
        else:
            print(f"\n⚠ Tổng cộng phát hiện {total} vị trí nghi ngờ.")
        print("="*80)
    else:
        print(f"[!] Đường dẫn không tồn tại: {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHP Secure Code Review - file hoặc directory")
    parser.add_argument("path", help="Đường dẫn tới file .php hoặc thư mục chứa mã PHP")
    args = parser.parse_args()
    review_path(args.path)

