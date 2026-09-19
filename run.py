import subprocess
import sys


def main():
    print("=== SECURITY CHECK ===")

    result = subprocess.run(
        [sys.executable, "-m", "security.manager"],
        cwd=".",
    )

    if result.returncode != 0:
        print("Security check failed. Bot will not start.")
        sys.exit(result.returncode)

    print("\n=== STARTING BOT ===")

    result = subprocess.run(
        [sys.executable, "-m", "bot.main"],
        cwd=".",
    )

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
