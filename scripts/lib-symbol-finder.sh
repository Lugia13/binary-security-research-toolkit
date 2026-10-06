#!/bin/bash
# lib_symbol_finder.sh
# Find which .so file actually DEFINES a given symbol
# (as opposed to all the ones that just import/use it)
#
# Usage: ./lib_symbol_finder.sh /path/to/lib64 strcpy_safe
# Usage: ./lib_symbol_finder.sh /path/to/lib64 "strcpy_safe|sprintf_safe|memcpy_safe"
#
# Author: Oussama Saddati

LIB_DIR="${1:-/usr/lib}"
SYMBOL="${2:-strcpy}"

echo "[*] Searching for defined (non-UND) symbol matching: $SYMBOL"
echo "[*] Library directory: $LIB_DIR"
echo ""

FOUND=0

for lib in "$LIB_DIR"/*.so*; do
    [ -f "$lib" ] || continue
    file "$lib" 2>/dev/null | grep -q ELF || continue

    result=$(objdump -T "$lib" 2>/dev/null \
        | grep -Ev "^$lib|format|dynamic symbol" \
        | grep -v "UND" \
        | grep -iE "$SYMBOL")

    if [ -n "$result" ]; then
        echo "=== FOUND IN: $lib ==="
        echo "$result"
        echo ""
        FOUND=$((FOUND + 1))

        # also show the function size for context
        # NOTE: name uses $NF (last field), not a fixed column -- objdump -T
        # only emits a version field (e.g. GLIBC_2.2.5) for versioned symbols.
        # Custom/internal symbols (like the strcpy_safe example above) have
        # no version field, shifting the name from $7 to $6; a hardcoded $7
        # silently prints an empty name for exactly that case.
        echo "  [+] Function details:"
        objdump -T "$lib" 2>/dev/null \
            | grep -v "UND" \
            | grep -iE "$SYMBOL" \
            | awk '{printf "    name: %s | size: 0x%s bytes | offset: %s\n", $NF, $5, $1}'
        echo ""
    fi
done

if [ "$FOUND" -eq 0 ]; then
    echo "[-] Symbol '$SYMBOL' not found as a defined export in any .so in $LIB_DIR"
    echo ""
    echo "[*] It may be:"
    echo "    1. Statically compiled into a binary (check with: nm <binary> | grep $SYMBOL)"
    echo "    2. In a subdirectory (re-run with a broader path)"
    echo "    3. Inlined by the compiler (no symbol entry)"
else
    echo "[*] Found in $FOUND library/libraries"
fi
