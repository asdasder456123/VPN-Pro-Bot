import ast
import os
from pathlib import Path


SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
}


def find_python_files(root="."):
    root = Path(root)
    files = []

    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)

    return sorted(files)


def check_file(path):
    issues = []

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [{
            "file": str(path),
            "line": 0,
            "severity": "ERROR",
            "message": f"Cannot read file: {exc}",
        }]

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [{
            "file": str(path),
            "line": exc.lineno or 0,
            "severity": "CRITICAL",
            "message": f"Syntax error: {exc.msg}",
        }]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func

            if isinstance(func, ast.Name):
                if func.id == "eval":
                    issues.append({
                        "file": str(path),
                        "line": node.lineno,
                        "severity": "HIGH",
                        "message": "Use of eval() detected.",
                    })

                elif func.id == "exec":
                    issues.append({
                        "file": str(path),
                        "line": node.lineno,
                        "severity": "HIGH",
                        "message": "Use of exec() detected.",
                    })

        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name == "pickle":
                    issues.append({
                        "file": str(path),
                        "line": node.lineno,
                        "severity": "MEDIUM",
                        "message": "pickle import detected; unsafe deserialization can be dangerous with untrusted data.",
                    })

        if isinstance(node, ast.ImportFrom):
            if node.module == "pickle":
                issues.append({
                    "file": str(path),
                    "line": node.lineno,
                    "severity": "MEDIUM",
                    "message": "pickle import detected; unsafe deserialization can be dangerous with untrusted data.",
                })

    return issues


def scan_project(root="."):
    results = []

    for path in find_python_files(root):
        results.extend(check_file(path))

    return results


def format_report(results):
    if not results:
        return "No static security issues detected."

    lines = [
        "=== Python Security Scan ===",
        f"Issues found: {len(results)}",
        "",
    ]

    for issue in results:
        lines.append(
            f"[{issue['severity']}] "
            f"{issue['file']}:{issue['line']} - "
            f"{issue['message']}"
        )

    return "\n".join(lines)
