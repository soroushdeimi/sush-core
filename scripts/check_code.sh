#!/bin/bash
set -e

echo "Checking for merge conflicts..."
if grep -r "<<<<<<< " . --include="*.py" || grep -r "=======" . --include="*.py" | grep -v "== " || grep -r ">>>>>>> " . --include="*.py"; then
    echo "Error: Merge conflict markers found in code"
    exit 1
fi

echo "Running ruff format check..."
ruff format --check .

echo "Running ruff lint check..."
ruff check .

echo "Running black check..."
black --check .

echo "All checks passed!"

