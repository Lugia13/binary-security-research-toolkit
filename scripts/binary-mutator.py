#!/usr/bin/env python3
"""
binary_mutator.py
Generic binary field mutator for PoC development in bug bounty research.
Supports single-field mutations, batch mutations, and pattern-based fuzzing.

Usage:
    python3 binary_mutator.py --file input.bin --offset 0x0c --size 4 --value 0xFFFFFFFF
    python3 binary_mutator.py --file input.bin --offset 0x0c --size 4 --mode all
    python3 binary_mutator.py --file input.bin --map fields.json --mode all

Author: Oussama Saddati
"""

import argparse
import json
import os
import shutil
import struct
import sys
from pathlib import Path


# -------------------------------------------------------------------
# Mutation strategies
# -------------------------------------------------------------------

def mutation_values(size_bytes):
    """
    Return a list of interesting mutation values for a field of given byte size.
    These cover the most common vulnerability triggers:
    - Integer overflow boundaries
    - Zero / null
    - Maximum values
    - Off-by-one around common sizes
    """
    max_val = (1 << (size_bytes * 8)) - 1
    half_max = max_val // 2

    return [
        # overflow triggers
        (max_val,            "max_value (0x" + "FF" * size_bytes + ")"),
        (max_val - 1,        "max_value_minus_1"),
        (half_max + 1,       "signed_overflow_boundary"),

        # zero / null triggers
        (0,                  "zero"),
        (1,                  "one"),

        # common allocation size triggers
        (0xFFFF,             "64KB"),
        (0xFFFFFF,           "16MB"),
        (0x7FFFFFFF,         "INT_MAX (2GB)") if size_bytes >= 4 else None,

        # off-by-one around page size
        (0x1000 - 1,         "page_size_minus_1"),
        (0x1000,             "page_size"),
        (0x1000 + 1,         "page_size_plus_1"),

        # attacker pattern for register control visibility
        (0x41414141 & max_val, "AAAA_pattern"),
        (0xDEADBEEF & max_val, "DEADBEEF_pattern"),
        (0xCAFEBABE & max_val, "CAFEBABE_pattern"),
    ]


def pack_value(value, size, endian="little"):
    """Pack an integer value into bytes of the given size."""
    try:
        return value.to_bytes(size, endian)
    except (OverflowError, ValueError) as e:
        raise ValueError(f"Cannot pack value 0x{value:X} into {size} bytes: {e}")


def apply_mutation(data, offset, size, value, endian="little"):
    """Apply a single mutation to a bytearray. Returns modified copy."""
    if offset + size > len(data):
        raise ValueError(
            f"Offset 0x{offset:X} + size {size} exceeds file length {len(data)}"
        )
    result = bytearray(data)
    result[offset:offset + size] = pack_value(value, size, endian)
    return result


# -------------------------------------------------------------------
# Output helpers
# -------------------------------------------------------------------

def save_mutant(data, original_path, label):
    """Save a mutated variant next to the original with a descriptive suffix."""
    base = Path(original_path)
    out_path = base.parent / f"{base.stem}_mutant_{label}{base.suffix}"
    with open(out_path, "wb") as f:
        f.write(data)
    return str(out_path)


def hex_context(data, offset, size, context=8):
    """Print a hex view of bytes around the mutation offset."""
    start = max(0, offset - context)
    end = min(len(data), offset + size + context)
    print(f"\n  Hex context (offset 0x{start:X} to 0x{end:X}):")
    for i in range(start, end, 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        # mark the mutated field
        mark = ""
        if i <= offset < i + 16:
            mark = "  ← mutation here"
        print(f"  0x{i:08X}:  {hex_str:<47}  {mark}")


# -------------------------------------------------------------------
# Main logic
# -------------------------------------------------------------------

def single_mutation(args):
    """Apply a single specified mutation."""
    with open(args.file, "rb") as f:
        original = bytearray(f.read())

    offset = int(args.offset, 16) if args.offset.startswith("0x") else int(args.offset)
    size   = int(args.size)
    value  = int(args.value, 16) if args.value.startswith("0x") else int(args.value)
    endian = args.endian

    print(f"[*] File: {args.file} ({len(original)} bytes)")
    print(f"[*] Offset: 0x{offset:X} | Size: {size} bytes | Endian: {endian}")
    print(f"[*] Original field value: 0x{int.from_bytes(original[offset:offset+size], endian):X}")
    print(f"[*] Mutation value:       0x{value:X}")

    mutated = apply_mutation(original, offset, size, value, endian)
    hex_context(mutated, offset, size)

    if args.output:
        with open(args.output, "wb") as f:
            f.write(mutated)
        print(f"\n[+] Saved: {args.output}")
    else:
        label = f"0x{value:X}"
        out = save_mutant(mutated, args.file, label)
        print(f"\n[+] Saved: {out}")


def batch_mutations(args):
    """Generate all interesting mutation variants for a field."""
    with open(args.file, "rb") as f:
        original = bytearray(f.read())

    offset = int(args.offset, 16) if args.offset.startswith("0x") else int(args.offset)
    size   = int(args.size)
    endian = args.endian

    print(f"[*] Batch mutation: {args.file}")
    print(f"[*] Target field: offset=0x{offset:X}, size={size} bytes")
    print(f"[*] Original value: 0x{int.from_bytes(original[offset:offset+size], endian):X}")
    print("")

    generated = []
    for item in mutation_values(size):
        if item is None:
            continue
        value, label = item
        try:
            mutated = apply_mutation(original, offset, size, value, endian)
            out = save_mutant(mutated, args.file, label.replace(" ", "_"))
            generated.append((label, value, out))
            print(f"  [+] 0x{value:0{size*2}X}  ({label})")
            print(f"       → {out}")
        except ValueError as e:
            print(f"  [-] Skipped {label}: {e}")

    print(f"\n[*] Generated {len(generated)} mutant files")
    print(f"[*] Test each with:")
    print(f"    gdb --args <binary> <args-that-load-the-file>")
    print(f"    (gdb) set breakpoint pending on")
    print(f"    (gdb) b <target_function>")
    print(f"    (gdb) run")


def map_mutations(args):
    """Apply mutations from a JSON field map."""
    with open(args.file, "rb") as f:
        original = bytearray(f.read())

    with open(args.map, "r") as f:
        field_map = json.load(f)

    print(f"[*] Map-based mutation: {args.file}")
    print(f"[*] Fields: {args.map}")
    print("")

    for field in field_map.get("fields", []):
        name   = field.get("name", "unknown")
        offset = int(field.get("offset", "0x0"), 16)
        size   = field.get("size", 4)
        risk   = field.get("risk", "unknown")

        orig_val = int.from_bytes(original[offset:offset+size], args.endian)
        print(f"  Field: {name}")
        print(f"    offset=0x{offset:X}, size={size}, risk={risk}")
        print(f"    current value: 0x{orig_val:0{size*2}X}")

        if risk in ("high", "medium"):
            for item in mutation_values(size):
                if item is None:
                    continue
                value, label = item
                try:
                    mutated = apply_mutation(original, offset, size, value, args.endian)
                    tag = f"{name}_{label}".replace(" ", "_")
                    out = save_mutant(mutated, args.file, tag)
                    print(f"    [+] {label} → {out}")
                except ValueError as e:
                    print(f"    [-] Skipped {label}: {e}")
        else:
            print(f"    [~] Skipped (low risk)")
        print("")


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Binary field mutator for PoC development",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single mutation:
    %(prog)s --file trace.bin --offset 0x0c --size 4 --value 0xFFFFFFFF

  All interesting mutations for one field:
    %(prog)s --file trace.bin --offset 0x0c --size 4 --mode all

  Map-based mutations (JSON field map):
    %(prog)s --file trace.bin --map format_fields.json --mode map
        """
    )

    parser.add_argument("--file",    required=True, help="Input binary file")
    parser.add_argument("--offset",  default="0x0",  help="Field offset (hex: 0x0c or decimal)")
    parser.add_argument("--size",    default="4",    help="Field size in bytes")
    parser.add_argument("--value",   default="0x0",  help="Mutation value (single mode)")
    parser.add_argument("--endian",  default="little", choices=["little", "big"])
    parser.add_argument("--output",  default=None,   help="Output file path (single mode)")
    parser.add_argument("--map",     default=None,   help="JSON field map file (map mode)")
    parser.add_argument("--mode",    default="single",
                        choices=["single", "all", "map"],
                        help="single=one mutation, all=all interesting values, map=JSON field map")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    if args.mode == "single":
        single_mutation(args)
    elif args.mode == "all":
        batch_mutations(args)
    elif args.mode == "map":
        if not args.map:
            print("[-] --map required for map mode")
            sys.exit(1)
        map_mutations(args)


if __name__ == "__main__":
    main()
