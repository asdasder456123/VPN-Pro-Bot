import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from openai import OpenAI

from security.ai_analyzer import MODEL


BACKUP_DIR = Path(".security_backups")


def backup_file(path: Path) -> Path:
    BACKUP_DIR.mkdir(exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = BACKUP_DIR / f"{path.name}.{stamp}.bak"

    shutil.copy2(path, backup)
    return backup


def syntax_check(path: Path) -> bool:
    result = subprocess.run(
        ["python3", "-m", "py_compile", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def fix_file(path: Path):
    source = path.read_text(encoding="utf-8")

    prompt = (
        "You are a STRICT Python security fixer.\n"
        "Fix ONLY a concrete existing security vulnerability, bug, or correctness "
        "problem that is clearly present in this file.\n\n"
        "STRICT RULES:\n"
        "- Do NOT add features.\n"
        "- Do NOT redesign the project.\n"
        "- Do NOT refactor working code without necessity.\n"
        "- Do NOT optimize code unnecessarily.\n"
        "- Do NOT change behavior unrelated to the confirmed problem.\n"
        "- Do NOT make speculative changes.\n"
        "- If there is no concrete issue, respond exactly: NO_FIX\n"
        "- If fixing, return ONLY the complete corrected Python file.\n"
        "- Never use Markdown fences.\n"
        "- Keep the change as small as safely possible.\n\n"
        f"FILE: {path}\n\n"
        "CODE:\n"
        f"{source}"
    )

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You repair only confirmed Python bugs. Never develop or redesign.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=6000,
        temperature=0,
    )

    fixed = response.choices[0].message.content or ""

    if fixed.strip() == "NO_FIX":
        return False, "No confirmed fix required."

    if "```" in fixed:
        return False, "AI returned Markdown instead of raw Python."

    backup = backup_file(path)

    path.write_text(fixed, encoding="utf-8")

    if not syntax_check(path):
        shutil.copy2(backup, path)
        return False, "Syntax check failed; original restored."

    return True, f"Fixed confirmed issue. Backup: {backup}"


def fix_project(root="."):
    from security.code_scanner import find_python_files

    for path in find_python_files(root):
        print(f"\n=== AUTO-FIX: {path} ===")

        try:
            changed, message = fix_file(path)
            print(message)
        except Exception as exc:
            print(f"Fix failed: {exc}")


if __name__ == "__main__":
    fix_project(".")
