#!/bin/bash
# check-readme-sync.sh - Verify README.md and src/lib.rs documentation are in sync

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 Checking README and lib.rs synchronization..."
echo

# Check 1: Verify doc tests compile and pass
echo "📝 Step 1: Running doc tests..."
if cargo test --doc --quiet 2>&1 | grep -q "test result: ok"; then
    echo -e "${GREEN}✓${NC} Doc tests passed"
else
    echo -e "${RED}✗${NC} Doc tests failed"
    echo "   Run: cargo test --doc"
    exit 1
fi
echo

# Check 2: Verify section headers match
echo "📋 Step 2: Checking section headers..."

# Extract major section headers from lib.rs (lines starting with //! ##)
LIB_SECTIONS=$(grep -E "^//! ## " src/lib.rs | sed 's/^\/\/! ## //' | sort)

# Extract major section headers from README (lines starting with ##)
README_SECTIONS=$(grep -E "^## " README.md | sed 's/^## //' | sort)

# Compare sections
if [ "$LIB_SECTIONS" = "$README_SECTIONS" ]; then
    echo -e "${GREEN}✓${NC} Section headers match"
else
    echo -e "${YELLOW}⚠${NC}  Section headers differ between lib.rs and README.md"
    echo
    echo "  lib.rs sections:"
    echo "$LIB_SECTIONS" | sed 's/^/    - /'
    echo
    echo "  README sections:"
    echo "$README_SECTIONS" | sed 's/^/    - /'
    echo
    echo "  ${YELLOW}Note:${NC} This may be intentional if README has additional sections."
fi
echo

# Check 3: Look for common sync issues
echo "🔎 Step 3: Checking for common sync issues..."

ISSUES_FOUND=0

# Check if code block counts roughly match
LIB_CODE_BLOCKS=$(grep -c '^//! ```' src/lib.rs || true)
README_CODE_BLOCKS=$(grep -c '^```' README.md || true)

# Allow some variance since README may have additional examples
DIFF=$((README_CODE_BLOCKS - LIB_CODE_BLOCKS))
DIFF=${DIFF#-} # absolute value

if [ $DIFF -gt 5 ]; then
    echo -e "${YELLOW}⚠${NC}  Code block count differs significantly:"
    echo "   lib.rs: $LIB_CODE_BLOCKS blocks"
    echo "   README: $README_CODE_BLOCKS blocks"
    ISSUES_FOUND=1
fi

# Check for TODO or FIXME in lib.rs docs
if grep -q "//! .*TODO\|//! .*FIXME" src/lib.rs; then
    echo -e "${YELLOW}⚠${NC}  Found TODO/FIXME in lib.rs documentation"
    grep -n "//! .*TODO\|//! .*FIXME" src/lib.rs | sed 's/^/   /'
    ISSUES_FOUND=1
fi

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓${NC} No common issues found"
fi
echo

# Check 4: Verify Table of Contents exists in README
echo "📑 Step 4: Checking Table of Contents..."
if grep -q "## Table of Contents" README.md; then
    echo -e "${GREEN}✓${NC} Table of Contents found in README"
else
    echo -e "${RED}✗${NC} Table of Contents missing from README"
    exit 1
fi
echo

# Final summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ README sync check completed successfully!${NC}"
echo
echo "Reminder: When updating documentation:"
echo "  1. Edit doc comments in src/lib.rs"
echo "  2. Mirror changes to README.md"
echo "  3. Run: cargo test --doc"
echo "  4. Run: ./scripts/check-readme-sync.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
