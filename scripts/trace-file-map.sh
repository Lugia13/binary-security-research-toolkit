#!/bin/bash
# trace_file_map.sh
# Map which files a binary actually reads at runtime using strace.
# Critical for confirming that a mutated file is actually being parsed,
# not bypassed by a pre-processed cache.
#
# Usage:
#   ./trace-file-map.sh "<binary> -report hotspots -r /tmp/testrun"
#   ./trace-file-map.sh "<binary> <args>" [filter_pattern]
#
# Author: Oussama Saddati

COMMAND="$1"
FILTER="${2:-}"
LOG_FILE="/tmp/file_access_$(date +%Y%m%d_%H%M%S).log"

if [ -z "$COMMAND" ]; then
    echo "Usage: $0 \"<command>\" [file_filter_pattern]"
    echo ""
    echo "Examples:"
    echo "  $0 \"<binary> -report hotspots -r /tmp/testrun\""
    echo "  $0 \"<binary> -report hotspots -r /tmp/testrun\" \".trace\""
    exit 1
fi

echo "[*] Tracing file access for: $COMMAND"
echo "[*] Log: $LOG_FILE"
echo "[*] Filter: ${FILTER:-(none — showing all)}"
echo ""

# run strace, capture all openat/open/read calls
strace -f -e trace=openat,open,read \
       -o "$LOG_FILE" \
       sh -c "$COMMAND" 2>&1

echo ""
echo "============================================"
echo " Files opened during execution"
echo "============================================"

if [ -n "$FILTER" ]; then
    echo "[*] Filtered to: $FILTER"
    # NOTE: extract the first quoted string on the line rather than
    # requiring the literal substring "openat" -- a plain open(...) trace
    # line (still possible depending on libc/syscall path) matched the
    # preceding grep but was silently dropped by a sed pattern anchored to
    # "openat" specifically.
    grep -i "openat\|^open" "$LOG_FILE" \
        | grep -i "$FILTER" \
        | grep -v "ENOENT" \
        | sed -E 's/^[^"]*"([^"]*)".*/\1/' \
        | sort -u
else
    grep -i "openat\|^open" "$LOG_FILE" \
        | grep -v "ENOENT" \
        | sed -E 's/^[^"]*"([^"]*)".*/\1/' \
        | sort -u
fi

echo ""
echo "============================================"
echo " Specific file types of interest"
echo "============================================"

echo ""
echo "[*] .trace files accessed:"
grep "openat" "$LOG_FILE" | grep -i "\.trace" | grep -v "ENOENT"

echo ""
echo "[*] .db / database files accessed:"
grep "openat" "$LOG_FILE" | grep -iE "\.(db|sqlite)" | grep -v "ENOENT"

echo ""
echo "[*] Shared libraries loaded (.so):"
grep "openat" "$LOG_FILE" | grep "\.so" | grep -v "ENOENT" \
    | sed 's/.*"\(.*\.so[^"]*\)".*/\1/' | sort -u

echo ""
echo "[*] Full log saved to: $LOG_FILE"
echo "[*] Tip: if your target file does NOT appear above, it was not read."
echo "    This usually means a cache database was used instead."
echo "    Delete the cache and re-run to force re-processing."
