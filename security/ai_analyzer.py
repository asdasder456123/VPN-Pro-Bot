import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/free")
BASE_URL = "https://openrouter.ai/api/v1"


def analyze_code(filename, code):
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
    )

    prompt = (
        "You are a strict Python security auditor.\n"
        "Your ONLY job is to identify concrete, existing security vulnerabilities, "
        "bugs, or correctness problems in the supplied code.\n\n"
        "IMPORTANT RULES:\n"
        "- Do NOT suggest new features.\n"
        "- Do NOT redesign or refactor working code.\n"
        "- Do NOT suggest improvements merely because they are possible.\n"
        "- Do NOT invent hypothetical problems without evidence in this file.\n"
        "- Do NOT repeat the same issue.\n"
        "- Do NOT analyze or propose improvements to the scanner itself unless "
        "the scanner code has an actual concrete bug that affects its operation.\n"
        "- Maximum 5 real issues.\n"
        "- If there are no concrete issues, respond exactly: CLEAN\n\n"
        f"FILE: {filename}\n\n"
        "CODE:\n"
        f"{code}\n\n"
        "For each confirmed issue use exactly this format:\n"
        "SEVERITY: LOW|MEDIUM|HIGH|CRITICAL\n"
        "PROBLEM: <specific existing problem>\n"
        "WHY: <short impact>\n"
        "FIX: <minimal fix>\n\n"
        "Be concise."
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are a precise security auditor. Report only confirmed issues.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        max_tokens=1200,
        temperature=0,
    )

    return response.choices[0].message.content or "CLEAN"
