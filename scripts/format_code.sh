#!/bin/bash
set -e

echo "Formatting code with ruff and black..."

ruff format .
ruff check --fix .
black .

echo "Code formatting complete!"

