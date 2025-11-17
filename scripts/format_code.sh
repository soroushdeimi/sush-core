#!/bin/bash
set -e

echo "Formatting code with Ruff..."

ruff format .
ruff check --fix .

echo "✓ Code formatting complete!"

