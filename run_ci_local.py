#!/usr/bin/env python3
"""Run CI checks locally to verify fixes."""

import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], description: str, check: bool = True) -> bool:
    """Run a command and return success status."""
    separator = "=" * 60
    print(f"\n{separator}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{separator}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent)

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        if result.returncode == 0:
            print(f"\n✓ PASSED: {description}")
            return True
        else:
            print(f"\n✗ FAILED: {description} (exit code: {result.returncode})")
            if check:
                return False
            return True
    except FileNotFoundError as e:
        print(f"\n✗ ERROR: Command not found - {e}")
        print(f"   Make sure the required tools are installed.")
        if check:
            return False
        return True
    except Exception as e:
        print(f"\n✗ ERROR: {description}: {e}")
        if check:
            return False
        return True


def main():
    """Run CI checks locally."""
    print("=" * 60)
    print("sushCore Local CI Check")
    print("=" * 60)

    results = []

    # Step 1: Check merge conflicts
    results.append(
        run_command(
            ["python", "scripts/check_merge_conflicts.py"],
            "Check for merge conflicts",
            check=False,
        )
    )

    # Step 2: Ruff format check
    results.append(
        run_command(
            ["ruff", "format", "--check", "."],
            "Ruff format check",
            check=True,
        )
    )

    # Step 3: Ruff lint check
    results.append(
        run_command(
            ["ruff", "check", "."],
            "Ruff lint check",
            check=True,
        )
    )

    # Summary
    print("\n" + "=" * 60)
    print("CI Check Summary")
    print("=" * 60)

    passed = sum(results)
    total = len(results)

    checks = [
        "Merge conflicts check",
        "Ruff format check",
        "Ruff lint check",
    ]

    for i, (check, result) in enumerate(zip(checks, results), 1):
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{i}. {status}: {check}")

    print(f"\nOverall: {passed}/{total} checks passed")

    if passed == total:
        print("\n✓ All CI checks passed!")
        return 0
    else:
        print("\n✗ Some CI checks failed")
        print("\nTo fix issues:")
        print("  - make format      # or: ruff format .")
        print("  - make lint-fix    # or: ruff check --fix .")
        return 1


if __name__ == "__main__":
    sys.exit(main())
