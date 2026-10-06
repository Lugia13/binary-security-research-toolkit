#!/bin/bash
# import_hunter.sh
# Search for dangerous function imports across all ELF binaries and shared libs
# Usage: ./import_hunter.sh /path/to/directory
#
# Author: Oussama Saddati

TARGET_DIR="${1:-.}"

# functions to hunt — raw unsafe variants (high priority)
DANGEROUS_RAW="strcpy|strcat|sprintf|gets|scanf|memcpy|memmove|system|popen|execve|execl"

# functions to hunt — memory allocation (check size argument sources)
ALLOC_FUNCS="malloc|realloc|calloc|alloca|mmap"

# functions to hunt — I/O / loading
IO_FUNCS="read|recv|recvfrom|fread|dlopen|open|fopen"

echo "[*] Scanning: $TARGET_DIR"
echo "[*] Date: $(date -u)"
echo ""

echo "============================================"
echo " HIGH PRIORITY — Raw unsafe string/mem ops"
echo "============================================"
find "$TARGET_DIR" -type f | while read -r f; do
    result=$(file "$f" 2>/dev/null | grep -q ELF && \
        readelf --dyn-syms "$f" 2>/dev/null \
        | grep -iE "FUNC.*UND.*(${DANGEROUS_RAW})")
    if [ -n "$result" ]; then
        echo ""
        echo "--- $f ---"
        echo "$result"
    fi
done

echo ""
echo "============================================"
echo " MEDIUM — Allocation functions"
echo " (trace size argument to determine risk)"
echo "============================================"
find "$TARGET_DIR" -type f | while read -r f; do
    result=$(file "$f" 2>/dev/null | grep -q ELF && \
        readelf --dyn-syms "$f" 2>/dev/null \
        | grep -iE "FUNC.*UND.*(${ALLOC_FUNCS})")
    if [ -n "$result" ]; then
        echo ""
        echo "--- $f ---"
        echo "$result"
    fi
done

echo ""
echo "============================================"
echo " INFO — I/O and loading functions"
echo "============================================"
find "$TARGET_DIR" -type f | while read -r f; do
    result=$(file "$f" 2>/dev/null | grep -q ELF && \
        readelf --dyn-syms "$f" 2>/dev/null \
        | grep -iE "FUNC.*UND.*(${IO_FUNCS})")
    if [ -n "$result" ]; then
        echo ""
        echo "--- $f ---"
        echo "$result"
    fi
done

echo ""
echo "[*] Done."
echo "[!] Tip: for any 'Raw unsafe' hit, use r2 'axt sym.imp.<funcname>'"
echo "    to find all call sites, then trace the size/src arguments backward."
