#!/bin/bash
# Development environment setup script

set -e

echo "=========================================="
echo "sushCore Development Environment Setup"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
echo ""

# Setup pre-commit
echo "Setting up pre-commit hooks..."
pre-commit install
echo ""

# Verify tools
echo "Verifying tools..."
if command -v ruff &> /dev/null; then
    echo "✓ Ruff installed: $(ruff --version)"
else
    echo "❌ Ruff not found!"
    exit 1
fi

if command -v pre-commit &> /dev/null; then
    echo "✓ Pre-commit installed: $(pre-commit --version)"
else
    echo "❌ Pre-commit not found!"
    exit 1
fi
echo ""

# Run initial format check
echo "Running initial code format check..."
if make format 2>/dev/null || ruff format .; then
    echo "✓ Code formatted"
else
    echo "⚠ Formatting issues found (this is normal for first run)"
fi
echo ""

echo "=========================================="
echo "✓ Development environment setup complete!"
echo "=========================================="
echo ""
echo "Useful commands:"
echo "  make help          - Show all available commands"
echo "  make format        - Format code"
echo "  make lint          - Check code quality"
echo "  make lint-fix      - Auto-fix linting issues"
echo "  make ci-local      - Run all CI checks locally"
echo "  make test          - Run tests"
echo ""

