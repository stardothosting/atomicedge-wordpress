#!/bin/bash
#
# Scan False-Positive Regression Test
#
# Replicates what hosting provider malware scanners (ClamAV, Imunify360, etc.)
# do when scanning our plugin. If this script finds any detections, the plugin
# will be flagged by hosting providers and cause user support tickets.
#
# Usage:
#   ./tests/scan-false-positive-check.sh
#
# Requirements:
#   - ClamAV installed (clamscan)
#   - Run from the plugin root directory
#
# Exit codes:
#   0 = Clean (no false positives)
#   1 = ClamAV not installed
#   2 = Malware signatures detected (false positive risk)
#

set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INCLUDES_DIR="${PLUGIN_DIR}/includes"

echo "=== AtomicEdge Plugin: False-Positive Regression Check ==="
echo ""
echo "Plugin dir: ${PLUGIN_DIR}"
echo "Scanning:   ${INCLUDES_DIR}"
echo ""

# --- Check prerequisites ---
if ! command -v clamscan &>/dev/null; then
    echo "ERROR: ClamAV (clamscan) is not installed."
    echo "Install: sudo apt install clamav clamav-daemon"
    exit 1
fi

echo "ClamAV version: $(clamscan --version)"
echo ""

# --- Test 1: ClamAV scan of includes/ ---
echo "--- Test 1: ClamAV scan (replicates hosting provider malware scan) ---"
echo ""

CLAM_OUTPUT=$(clamscan --recursive --infected includes/ 2>&1) || true
CLAM_FOUND=$(echo "$CLAM_OUTPUT" | grep -c "FOUND" || true)

if [ "$CLAM_FOUND" -gt 0 ]; then
    echo "FAIL: ClamAV detected ${CLAM_FOUND} file(s):"
    echo "$CLAM_OUTPUT" | grep "FOUND"
    echo ""
else
    echo "PASS: ClamAV found no detections."
    echo ""
fi

# --- Test 2: Grep-based signature string scan ---
# These are the specific string literals that trigger ClamAV's
# Txt.Backdoor.Webshell signature family.
echo "--- Test 2: Known webshell signature strings in source ---"
echo ""

WEBSHELL_STRINGS=(
    "c99shell"
    "r57shell"
    "b374k"
    "Weevely"
    "c999sh"
    "r57sh"
    "edoced_46esab"
    "FilesMan"
    "HACKED BY"
    "wp-vcd"
    "tmpcontentx"
    "wp_temp_setupx"
    "derna.top"
)

GREP_FAIL=0
for sig in "${WEBSHELL_STRINGS[@]}"; do
    MATCHES=$(grep -rn --include="*.php" "$sig" "$INCLUDES_DIR" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo "FAIL: Found '$sig' in source:"
        echo "$MATCHES" | head -5
        echo ""
        GREP_FAIL=1
    fi
done

if [ "$GREP_FAIL" -eq 0 ]; then
    echo "PASS: No webshell signature strings found in source."
    echo ""
fi

# --- Test 3: Dangerous function patterns that trigger heuristic scanners ---
echo "--- Test 3: Heuristic trigger patterns (eval+decode combos in strings) ---"
echo ""

HEURISTIC_PATTERNS=(
    'eval\s*(\s*gzinflate'
    'eval\s*(\s*gzuncompress'
    'eval\s*(\s*str_rot13'
    'eval\s*(\s*base64_decode'
    'assert\s*(\s*base64_decode'
    'create_function\s*([^)]*base64_decode'
)

HEUR_FAIL=0
for pattern in "${HEURISTIC_PATTERNS[@]}"; do
    MATCHES=$(grep -rPn --include="*.php" "$pattern" "$INCLUDES_DIR" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo "FAIL: Heuristic trigger pattern found: $pattern"
        echo "$MATCHES" | head -3
        echo ""
        HEUR_FAIL=1
    fi
done

if [ "$HEUR_FAIL" -eq 0 ]; then
    echo "PASS: No heuristic trigger patterns found."
    echo ""
fi

# --- Summary ---
echo "=== Summary ==="
TOTAL_FAIL=0
[ "$CLAM_FOUND" -gt 0 ] && TOTAL_FAIL=1
[ "$GREP_FAIL" -gt 0 ] && TOTAL_FAIL=1
[ "$HEUR_FAIL" -gt 0 ] && TOTAL_FAIL=1

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo ""
    echo "RESULT: FAIL — Plugin source contains patterns that will trigger"
    echo "hosting provider malware scanners (ClamAV, Imunify360, etc.)."
    echo ""
    echo "The get_refined_patterns_for_plugins() method in class-atomicedge-scanner.php"
    echo "contains hardcoded malware signature strings that must be served from the"
    echo "Malware Signature API instead."
    echo ""
    exit 2
else
    echo ""
    echo "RESULT: PASS — No false-positive triggers detected."
    echo ""
    exit 0
fi
