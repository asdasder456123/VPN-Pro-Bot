import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from security.code_scanner import (
    check_file,
    find_python_files,
    scan_project,
)

load_dotenv()

MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/free")
BASE_URL = "https://openrouter.ai/api/v1"

AI_DELAY = 8
CHUNK_SIZE = 9000
MAX_ISSUES_PER_FILE = 5
MAX_TOTAL_ISSUES = 30

BACKUP_DIR = Path(".security_backups")

# هذه الملفات جزء من البنية الأمنية نفسها.
# يفحصها المدير، لكنه ممنوع من تعديلها تلقائياً.
PROTECTED_FILES = {
    Path("security/manager.py"),
    Path("security/ai_analyzer.py"),
    Path("security/auto_fixer.py"),
    Path("security/code_scanner.py"),
    Path("security/ai_project_scan.py"),
    Path("security/support.py"),
    Path("security/scanner.py"),
}


def normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def is_protected(path):
    try:
        return Path(path).resolve() == Path("security/manager.py").resolve() or (
            Path(path).resolve()
            in {p.resolve() for p in PROTECTED_FILES}
        )
    except OSError:
        return True


def extract_json_object(text):
    if not text:
        return None

    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None

    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def valid_issue(issue):
    if not isinstance(issue, dict):
        return False

    required = {"severity", "problem", "why", "fix"}

    if not required.issubset(issue):
        return False

    severity = str(issue["severity"]).upper()

    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return False

    problem = str(issue["problem"]).strip()
    why = str(issue["why"]).strip()
    fix = str(issue["fix"]).strip()

    if not problem or not why or not fix:
        return False

    # نرفض النتائج التي تبدو كاقتراحات تحسين وليست أخطاء مؤكدة.
    weak_markers = (
        "could improve",
        "can improve",
        "consider",
        "recommended",
        "recommend",
        "better to",
        "should consider",
        "might",
        "potentially",
        "would be better",
        "rate limiting",
        "retry logic",
        "refactor",
        "redesign",
        "optimization",
        "optimize",
    )

    combined = normalize_text(problem + " " + fix)

    if any(marker in combined for marker in weak_markers):
        return False

    return True


def chunk_source(source):
    if len(source) <= CHUNK_SIZE:
        return [source]

    chunks = []

    for start in range(0, len(source), CHUNK_SIZE):
        chunks.append(source[start:start + CHUNK_SIZE])

    return chunks


def ai_find_issues(filename, code):
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
    )

    prompt = (
        "You are a STRICT Python security auditor.\n"
        "Analyze ONLY the supplied code.\n\n"
        "Report ONLY a concrete existing bug or security vulnerability "
        "that is actually present in the supplied code.\n\n"
        "DO NOT report:\n"
        "- possible improvements\n"
        "- recommendations\n"
        "- missing optional features\n"
        "- refactoring ideas\n"
        "- redesign ideas\n"
        "- optimization ideas\n"
        "- hypothetical attacks without evidence\n"
        "- style issues\n"
        "- generic best practices\n"
        "- rate limiting unless the supplied code has a concrete exploitable "
        "rate-related bug\n"
        "- retry logic merely because it is absent\n\n"
        "If there is no confirmed issue, return exactly:\n"
        "{\"issues\":[]}\n\n"
        "Return ONLY valid JSON.\n"
        "No Markdown.\n"
        "No explanation.\n"
        "No reasoning.\n\n"
        "JSON format:\n"
        "{"
        "\"issues\":["
        "{"
        "\"severity\":\"LOW|MEDIUM|HIGH|CRITICAL\","
        "\"problem\":\"specific confirmed problem\","
        "\"why\":\"specific impact\","
        "\"fix\":\"minimal necessary fix\""
        "}"
        "]"
        "}\n\n"
        f"FILE: {filename}\n\n"
        f"CODE:\n{code}"
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a strict bug and security auditor. "
                    "Only confirmed existing problems are valid."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=1400,
        temperature=0,
    )

    raw = response.choices[0].message.content or ""
    data = extract_json_object(raw)

    if not isinstance(data, dict):
        return []

    issues = data.get("issues", [])

    if not isinstance(issues, list):
        return []

    return [
        issue
        for issue in issues[:MAX_ISSUES_PER_FILE]
        if valid_issue(issue)
    ]


def backup_file(path):
    BACKUP_DIR.mkdir(exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    backup = BACKUP_DIR / f"{path.name}.{stamp}.bak"

    shutil.copy2(path, backup)

    return backup


def restore_file(backup, path):
    shutil.copy2(backup, path)


def syntax_check(path):
    result = subprocess.run(
        ["python3", "-m", "py_compile", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def static_blocking_issues(path):
    results = check_file(path)

    return [
        issue
        for issue in results
        if str(issue.get("severity", "")).upper()
        in {"HIGH", "CRITICAL"}
    ]


def request_fixed_code(filename, source, issue):
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
    )

    prompt = (
        "You are a STRICT Python bug fixer.\n\n"
        "Fix ONLY the confirmed existing problem described below.\n\n"
        "RULES:\n"
        "- Do not add features.\n"
        "- Do not redesign.\n"
        "- Do not refactor unrelated code.\n"
        "- Do not optimize unrelated code.\n"
        "- Do not change unrelated behavior.\n"
        "- Do not invent additional fixes.\n"
        "- Keep the change as small as possible.\n"
        "- Return the complete corrected Python file.\n"
        "- Return ONLY JSON.\n"
        "- No Markdown.\n"
        "- No explanation.\n\n"
        "If you cannot safely make the exact fix, return:\n"
        "{\"action\":\"NO_FIX\"}\n\n"
        "Otherwise return:\n"
        "{\"action\":\"FIX\",\"code\":\"complete file here\"}\n\n"
        f"FILE: {filename}\n\n"
        f"CONFIRMED PROBLEM:\n{issue['problem']}\n\n"
        f"WHY:\n{issue['why']}\n\n"
        f"REQUIRED MINIMAL FIX:\n{issue['fix']}\n\n"
        f"CURRENT CODE:\n{source}"
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You repair only confirmed existing bugs. "
                    "Never develop new functionality."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=7000,
        temperature=0,
    )

    raw = response.choices[0].message.content or ""
    data = extract_json_object(raw)

    if not isinstance(data, dict):
        return None

    if data.get("action") != "FIX":
        return None

    code = data.get("code")

    if not isinstance(code, str) or not code.strip():
        return None

    if "```" in code:
        return None

    return code


def fix_issue(path, issue):
    path = Path(path)

    if is_protected(path):
        return False, "PROTECTED"

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"Cannot read file: {exc}"

    fixed_code = request_fixed_code(str(path), source, issue)

    if not fixed_code:
        return False, "AI could not produce a valid minimal fix."

    backup = backup_file(path)

    try:
        path.write_text(fixed_code, encoding="utf-8")

        if not syntax_check(path):
            restore_file(backup, path)
            return False, "Syntax check failed; original restored."

        blocking = static_blocking_issues(path)

        if blocking:
            restore_file(backup, path)
            return False, "Security check failed; original restored."

    except Exception as exc:
        restore_file(backup, path)
        return False, f"Fix failed; original restored: {exc}"

    return True, f"Fixed. Backup: {backup}"


def collect_ai_issues(root="."):
    files = find_python_files(root)

    print("=== AI SECURITY SCAN ===")
    print(f"Python files: {len(files)}")

    all_issues = []
    seen = set()

    for index, path in enumerate(files, 1):
        print(f"\n[{index}/{len(files)}] AI ANALYSIS: {path}")

        if is_protected(path):
            print("PROTECTED FILE - scan only, no automatic modification.")

        try:
            source = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"Read failed: {exc}")
            continue

        chunks = chunk_source(source)
        file_issues = []

        for chunk_index, chunk in enumerate(chunks, 1):
            try:
                issues = ai_find_issues(str(path), chunk)
            except Exception as exc:
                print(f"AI analysis failed: {exc}")
                continue

            for issue in issues:
                key = (
                    str(path),
                    normalize_text(issue["problem"]),
                )

                if key in seen:
                    continue

                seen.add(key)
                issue["file"] = str(path)
                issue["chunk"] = chunk_index

                file_issues.append(issue)

                if len(all_issues) >= MAX_TOTAL_ISSUES:
                    break

            if len(all_issues) >= MAX_TOTAL_ISSUES:
                break

            if chunk_index < len(chunks):
                time.sleep(AI_DELAY)

        if not file_issues:
            print("CLEAN")
        else:
            for issue in file_issues:
                print(
                    f"[{issue['severity']}] "
                    f"{issue['problem']}"
                )

            all_issues.extend(file_issues)

        if index < len(files):
            time.sleep(AI_DELAY)

    return all_issues


def run_security_manager(root="."):
    print("=== SECURITY MANAGER ===")

    print("=== STATIC SCAN ===")

    static_results = scan_project(root)

    if static_results:
        print(f"Static issues: {len(static_results)}")
        for issue in static_results:
            print(
                f"[{issue['severity']}] "
                f"{issue['file']}:{issue['line']} - "
                f"{issue['message']}"
            )
    else:
        print("Static scan: clean.")

    ai_issues = collect_ai_issues(root)

    combined = []

    seen = set()

    for issue in static_results:
        key = (
            issue.get("file"),
            normalize_text(issue.get("message")),
        )

        if key not in seen:
            seen.add(key)
            combined.append({
                "file": issue.get("file"),
                "severity": issue.get("severity"),
                "problem": issue.get("message"),
                "why": "Detected by static security scanner.",
                "fix": "Apply the minimal fix required for this confirmed issue.",
            })

    for issue in ai_issues:
        key = (
            issue.get("file"),
            normalize_text(issue.get("problem")),
        )

        if key not in seen:
            seen.add(key)
            combined.append(issue)

    print("\n=== CONFIRMED FIXES ONLY ===")

    applied = 0
    confirmed = len(combined)

    for index, issue in enumerate(combined, 1):
        path = Path(issue["file"])

        print(
            f"\n[{index}/{confirmed}] "
            f"{issue['severity']} - {path}"
        )
        print(f"Problem: {issue['problem']}")

        if is_protected(path):
            print(
                "Protected security infrastructure: "
                "reported only, automatic modification blocked."
            )
            continue

        changed, message = fix_issue(path, issue)

        print(message)

        if changed:
            applied += 1

    print("\n=== FINAL STATIC SCAN ===")

    final_results = scan_project(root)

    if final_results:
        print(f"Final static issues: {len(final_results)}")
    else:
        print("Final static scan: clean.")

    print("=== SECURITY MANAGER FINISHED ===")
    print(f"Confirmed issues: {confirmed}")
    print(f"Applied fixes: {applied}")


if __name__ == "__main__":
    run_security_manager(".")
