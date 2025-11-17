#!/usr/bin/env python3
"""
Check for merge conflict markers in Python files.

This script detects actual merge conflict markers, not false positives
like print("==========") or other legitimate uses of equal signs.
"""

import os
import sys
from pathlib import Path


def has_merge_conflicts(file_path: Path) -> list[str]:
    """
    Check if a file contains merge conflict markers.

    Returns list of lines with conflicts, empty if none found.
    """
    conflicts = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Check for conflict start marker
            if stripped.startswith("<<<<<<<"):
                conflicts.append(f"{file_path}:{i}: {stripped}")

            # Check for conflict end marker
            if stripped.startswith(">>>>>>>"):
                conflicts.append(f"{file_path}:{i}: {stripped}")

            # Only check for separator if we're in a conflict context
            # We detect this by checking if there's a <<<<<<< before this line
            # and a >>>>>>> after this line (within reasonable distance)
            if stripped == "=======":
                # Check if this is part of a conflict block
                # Look backwards for <<<<<<<
                has_start = False
                has_end = False

                # Check 50 lines before
                for j in range(max(0, i - 50), i):
                    if lines[j].strip().startswith("<<<<<<<"):
                        has_start = True
                        break

                # Check 50 lines after
                for j in range(i, min(len(lines), i + 50)):
                    if lines[j].strip().startswith(">>>>>>>"):
                        has_end = True
                        break

                # Only flag if it's between conflict markers
                if has_start and has_end:
                    conflicts.append(f"{file_path}:{i}: {stripped}")

    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)

    return conflicts


def main():
    """Main function to check all Python files."""
    root = Path(".")
    all_conflicts = []

    # Find all Python files
    for py_file in root.rglob("*.py"):
        # Skip virtual environments and build directories
        if any(
            part in py_file.parts
            for part in [".venv", "venv", "__pycache__", ".git", "build", "dist"]
        ):
            continue

        conflicts = has_merge_conflicts(py_file)
        if conflicts:
            all_conflicts.extend(conflicts)

    if all_conflicts:
        print("Error: Merge conflict markers found in code:")
        for conflict in all_conflicts:
            print(conflict)
        sys.exit(1)
    else:
        print("No merge conflict markers found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
