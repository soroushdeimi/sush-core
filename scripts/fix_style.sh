#!/bin/bash
# =============================================================================
# fix_style.sh - Automatic Code Style Fixer for sushCore
# =============================================================================
# This script fixes common linting issues:
#   - W293: Whitespace on blank lines
#   - F401: Unused imports
#   - I001: Unsorted imports
#   - E501: Line too long (where possible)
#
# Compatible with: Linux, macOS, Windows Git Bash
# =============================================================================

set -e

# Colors for output (compatible with Git Bash)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories to process
TARGET_DIRS="sush tests tools data examples"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   sushCore Code Style Fixer${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Check for required tools
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} $1 not found"
        return 1
    fi
}

echo -e "${BLUE}[Step 0] Checking for required tools...${NC}"
RUFF_AVAILABLE=false
AUTOPEP8_AVAILABLE=false
ISORT_AVAILABLE=false
AUTOFLAKE_AVAILABLE=false

check_tool "ruff" && RUFF_AVAILABLE=true
check_tool "autopep8" && AUTOPEP8_AVAILABLE=true
check_tool "isort" && ISORT_AVAILABLE=true
check_tool "autoflake" && AUTOFLAKE_AVAILABLE=true

echo ""

# Prefer ruff if available (fastest, most comprehensive)
if [ "$RUFF_AVAILABLE" = true ]; then
    echo -e "${BLUE}[Step 1] Using Ruff (preferred) to fix all issues...${NC}"
    
    # Fix formatting issues (W293 whitespace, line length, etc.)
    echo -e "  ${YELLOW}→ Fixing formatting issues...${NC}"
    ruff format . --quiet
    echo -e "  ${GREEN}✓ Formatting fixed${NC}"
    
    # Fix linting issues (F401 unused imports, I001 import sorting, etc.)
    echo -e "  ${YELLOW}→ Fixing linting issues (imports, unused code)...${NC}"
    ruff check --fix --unsafe-fixes . --quiet 2>/dev/null || true
    echo -e "  ${GREEN}✓ Linting issues fixed${NC}"
    
else
    echo -e "${YELLOW}Ruff not available. Using fallback tools...${NC}"
    
    # Step 1: Fix W293 (whitespace on blank lines)
    echo -e "${BLUE}[Step 1] Fixing W293: Whitespace on blank lines...${NC}"
    if [ "$AUTOPEP8_AVAILABLE" = true ]; then
        for dir in $TARGET_DIRS; do
            if [ -d "$dir" ]; then
                echo -e "  ${YELLOW}→ Processing $dir/${NC}"
                find "$dir" -name "*.py" -type f -exec autopep8 --in-place --select=W293,W291,W292 {} \;
            fi
        done
        # Also fix root-level Python files
        for file in *.py; do
            [ -f "$file" ] && autopep8 --in-place --select=W293,W291,W292 "$file"
        done
        echo -e "  ${GREEN}✓ Trailing whitespace fixed${NC}"
    else
        # Fallback to sed
        echo -e "  ${YELLOW}Using sed fallback...${NC}"
        for dir in $TARGET_DIRS; do
            if [ -d "$dir" ]; then
                find "$dir" -name "*.py" -type f -exec sed -i 's/[[:space:]]*$//' {} \;
            fi
        done
        for file in *.py; do
            [ -f "$file" ] && sed -i 's/[[:space:]]*$//' "$file"
        done
        echo -e "  ${GREEN}✓ Trailing whitespace fixed (sed)${NC}"
    fi
    
    # Step 2: Fix F401 (unused imports)
    echo -e "${BLUE}[Step 2] Fixing F401: Unused imports...${NC}"
    if [ "$AUTOFLAKE_AVAILABLE" = true ]; then
        for dir in $TARGET_DIRS; do
            if [ -d "$dir" ]; then
                echo -e "  ${YELLOW}→ Processing $dir/${NC}"
                autoflake --in-place --remove-all-unused-imports --recursive "$dir"
            fi
        done
        for file in *.py; do
            [ -f "$file" ] && autoflake --in-place --remove-all-unused-imports "$file"
        done
        echo -e "  ${GREEN}✓ Unused imports removed${NC}"
    else
        echo -e "  ${YELLOW}⚠ autoflake not available. Install with: pip install autoflake${NC}"
    fi
    
    # Step 3: Fix I001 (import sorting)
    echo -e "${BLUE}[Step 3] Fixing I001: Import sorting...${NC}"
    if [ "$ISORT_AVAILABLE" = true ]; then
        for dir in $TARGET_DIRS; do
            if [ -d "$dir" ]; then
                echo -e "  ${YELLOW}→ Processing $dir/${NC}"
                isort --quiet "$dir"
            fi
        done
        for file in *.py; do
            [ -f "$file" ] && isort --quiet "$file"
        done
        echo -e "  ${GREEN}✓ Imports sorted${NC}"
    else
        echo -e "  ${YELLOW}⚠ isort not available. Install with: pip install isort${NC}"
    fi
fi

echo ""
echo -e "${BLUE}[Step 4] Running final verification...${NC}"

# Final check
if [ "$RUFF_AVAILABLE" = true ]; then
    echo -e "  ${YELLOW}→ Checking with ruff...${NC}"
    if ruff check . --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✓ All ruff checks pass!${NC}"
    else
        echo -e "  ${YELLOW}⚠ Some issues remain. Run 'ruff check .' for details.${NC}"
    fi
    
    if ruff format --check . --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✓ All formatting checks pass!${NC}"
    else
        echo -e "  ${YELLOW}⚠ Formatting issues remain. Run 'ruff format --check .' for details.${NC}"
    fi
fi

echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${GREEN}   Code style fixing complete!${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Review changes: ${YELLOW}git diff${NC}"
echo -e "  2. Verify locally: ${YELLOW}ruff check . && ruff format --check .${NC}"
echo -e "  3. Commit:         ${YELLOW}git add -A && git commit -m 'style: fix linting issues'${NC}"
echo ""
