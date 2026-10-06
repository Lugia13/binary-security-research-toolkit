#!/bin/bash
# batch_checksec.sh
# Run checksec across all ELF binaries in a target directory
# Usage: ./batch_checksec.sh /path/to/bin64
#
# Author: Oussama Saddati

TARGET_DIR="${1:-.}"
OUTPUT_FILE="/tmp/checksec_results_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] Scanning ELF binaries in: $TARGET_DIR"
echo "[*] Output: $OUTPUT_FILE"
echo ""

# find all ELF files
ELF_FILES=$(find "$TARGET_DIR" -maxdepth 2 -type f -exec file {} \; \
    | grep ELF \
    | cut -d: -f1)

if [[ -z "$ELF_FILES" ]]; then
    COUNT=0
else
    COUNT=$(echo "$ELF_FILES" | wc -l)
fi
echo "[*] Found $COUNT ELF files"
echo ""

{
    echo "===== checksec batch scan ====="
    echo "Target: $TARGET_DIR"
    echo "Date: $(date -u)"
    echo "==============================="
    echo ""

    while IFS= read -r f; do
        echo "--- $f ---"
        checksec "$f" 2>/dev/null
        echo ""
    done <<< "$ELF_FILES"

} | tee "$OUTPUT_FILE"

echo ""
echo "[*] Done. Results saved to $OUTPUT_FILE"
echo ""
echo "[*] Binaries missing stack canary:"
# NOTE: match specifically on canary-related negatives, not a bare "No " --
# that also matches "No RPATH"/"No RUNPATH"/"No Symbols" and mislabels
# unrelated findings as canary issues.
grep -iB2 "no canary" "$OUTPUT_FILE" | grep -E "^---" || echo "    (none found)"

echo ""
echo "[*] Binaries with RPATH set:"
grep -B2 "RPATH" "$OUTPUT_FILE" | grep -E "^---" || echo "    (none found)"
