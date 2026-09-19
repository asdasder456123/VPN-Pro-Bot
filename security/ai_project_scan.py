import os
from pathlib import Path

from security.code_scanner import find_python_files, scan_project
from security.ai_analyzer import analyze_code


MAX_FILE_SIZE = 12000


def scan_with_ai(root="."):
    results = scan_project(root)

    for path in find_python_files(root):
        try:
            source = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        if not source.strip():
            continue

        if len(source) > MAX_FILE_SIZE:
            source = source[:MAX_FILE_SIZE]

        print(f"\n=== AI ANALYSIS: {path} ===")

        try:
            result = analyze_code(str(path), source)
            print(result)
        except Exception as exc:
            print(f"AI analysis failed: {exc}")

    return results


if __name__ == "__main__":
    scan_with_ai(".")
