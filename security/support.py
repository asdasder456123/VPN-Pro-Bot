import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/free")
BASE_URL = "https://openrouter.ai/api/v1"

BACKUP_DIR = Path(".security_backups")

PROTECTED_FILES = {
    Path("security/manager.py"),
    Path("security/ai_analyzer.py"),
    Path("security/auto_fixer.py"),
    Path("security/code_scanner.py"),
    Path("security/ai_project_scan.py"),
    Path("security/support.py"),
    Path("security/scanner.py"),
}


def extract_json(text):
    if not text:
        return None

    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")

        if start == -1 or end == -1:
            return None

        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None


def diagnose_error(error_text):
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
    )

    prompt = (
        "You are a strict technical support diagnostician for a Python Discord bot.\n"
        "Analyze the user's reported error.\n\n"
        "ONLY identify a concrete existing error supported by the report.\n"
        "Do not suggest features.\n"
        "Do not redesign.\n"
        "Do not refactor.\n"
        "Do not invent missing information.\n"
        "If the report does not contain enough evidence of an actual error, "
        "return CLEAN.\n\n"
        "Return ONLY valid JSON.\n"
        "No Markdown.\n"
        "No reasoning.\n\n"
        "For no confirmed error:\n"
        "{\"action\":\"CLEAN\",\"message\":\"لا يوجد أي شيء مريب\"}\n\n"
        "For a confirmed error:\n"
        "{\"action\":\"ERROR\",\"file\":\"path/to/file.py\","
        "\"problem\":\"confirmed error\","
        "\"fix\":\"minimal required fix\"}\n\n"
        "For a feature request:\n"
        "{\"action\":\"FEATURE_REQUEST\"}\n\n"
        f"USER REPORT:\n{error_text}"
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You diagnose only confirmed existing errors.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=1000,
        temperature=0,
    )

    return extract_json(response.choices[0].message.content or "")


def is_safe_target(path):
    path = Path(path)

    if path.is_absolute():
        return False

    if ".." in path.parts:
        return False

    try:
        resolved = path.resolve()
        root = Path(".").resolve()

        if root not in resolved.parents and resolved != root:
            return False

        for protected in PROTECTED_FILES:
            if resolved == protected.resolve():
                return False

    except OSError:
        return False

    return path.suffix == ".py" and path.exists()


def backup_file(path):
    BACKUP_DIR.mkdir(exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup = BACKUP_DIR / f"{path.name}.{stamp}.bak"

    shutil.copy2(path, backup)

    return backup


def syntax_check(path):
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def fix_confirmed_error(diagnosis):
    path = Path(diagnosis.get("file", ""))

    if not is_safe_target(path):
        return False, "لا يمكن تعديل الملف المحدد تلقائيًا."

    source = path.read_text(encoding="utf-8")

    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
    )

    prompt = (
        "You are a strict Python technical support fixer.\n"
        "Fix ONLY the confirmed error below.\n\n"
        "RULES:\n"
        "- No new features.\n"
        "- No redesign.\n"
        "- No unrelated refactoring.\n"
        "- No optimization.\n"
        "- No speculative changes.\n"
        "- Return ONLY JSON.\n"
        "- If you cannot safely fix it, return NO_FIX.\n\n"
        "Format:\n"
        "{\"action\":\"FIX\",\"code\":\"complete corrected file\"}\n\n"
        f"FILE: {path}\n"
        f"CONFIRMED ERROR: {diagnosis['problem']}\n"
        f"REQUIRED FIX: {diagnosis['fix']}\n\n"
        f"CURRENT CODE:\n{source}"
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "Fix only the confirmed error.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=7000,
        temperature=0,
    )

    result = extract_json(response.choices[0].message.content or "")

    if not isinstance(result, dict) or result.get("action") != "FIX":
        return False, "لم يتم إنشاء إصلاح آمن."

    code = result.get("code")

    if not isinstance(code, str) or not code.strip() or "```" in code:
        return False, "الإصلاح الناتج غير صالح."

    backup = backup_file(path)

    try:
        path.write_text(code, encoding="utf-8")

        if not syntax_check(path):
            shutil.copy2(backup, path)
            return False, "فشل فحص الكود وتمت استعادة النسخة الأصلية."

    except Exception as exc:
        shutil.copy2(backup, path)
        return False, f"فشل الإصلاح وتمت استعادة النسخة الأصلية: {exc}"

    return True, backup


def restart_bot():
    os.execv(sys.executable, [sys.executable] + sys.argv)


async def handle_support(error_text):
    diagnosis = diagnose_error(error_text)

    if not diagnosis:
        return "لا يوجد أي شيء مريب"

    action = diagnosis.get("action")

    if action == "CLEAN":
        return "لا يوجد أي شيء مريب"

    if action == "FEATURE_REQUEST":
        return "ده طلب إضافة أو Feature، ويحتاج تدخل دعم بشري."

    if action != "ERROR":
        return "لا يوجد أي شيء مريب"

    # لا نوقف البوت إلا بعد التأكد أن هناك خطأ حقيقي.
    changed, result = fix_confirmed_error(diagnosis)

    if not changed:
        return result

    # تم الإصلاح بنجاح؛ إعادة التشغيل تتم بعد إرسال الرد من bot/main.py.
    return "تم حل الخطأ وتنظيف التعديل", True
