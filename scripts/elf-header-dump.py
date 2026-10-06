#!/usr/bin/env python3
"""
elf_header_dump.py
Parse and display ELF header fields from a binary file.
Useful for understanding the structure of ELF-based targets
and identifying which fields are attacker-controllable.

Also includes a generic binary header scanner that identifies
known magic bytes at any offset — useful for discovering
embedded sub-formats (e.g. Zstd, zlib, ZIP inside a container).

Usage:
    python3 elf_header_dump.py --file binary.elf
    python3 elf_header_dump.py --file binary.elf --scan-magic
    python3 elf_header_dump.py --file custom.bin --scan-magic --no-elf

Author: Oussama Saddati
"""

import argparse
import struct
import sys
from pathlib import Path


# -------------------------------------------------------------------
# Known magic bytes for sub-format detection
# -------------------------------------------------------------------

KNOWN_MAGIC = {
    b'\x7fELF':           "ELF binary",
    b'\x28\xb5\x2f\xfd': "Zstandard (zstd) compressed data",
    b'\x1f\x8b':          "gzip compressed data",
    b'BZh':               "bzip2 compressed data",
    b'PK\x03\x04':        "ZIP archive",
    b'PK\x05\x06':        "ZIP archive (end of central directory)",
    b'\x89PNG':           "PNG image",
    b'%PDF':              "PDF document",
    b'MSCF':              "Microsoft Cabinet (.cab)",
    b'\xd0\xcf\x11\xe0': "Microsoft Compound Document",
    b'OggS':              "Ogg container",
    b'fLaC':              "FLAC audio",
    b'RIFF':              "RIFF container (WAV/AVI)",
    b'\x52\x61\x72\x21': "RAR archive",
    b'7z\xbc\xaf':        "7-zip archive",
    b'\xfd7zXZ':          "XZ compressed data",
    b'LZMA':              "LZMA compressed data",
    b'SQLite format 3':   "SQLite database",
    # Add any vendor/tool-specific proprietary container magic bytes you
    # discover during your own analysis here -- intentionally left generic
    # in this public methodology reference.
}


# -------------------------------------------------------------------
# ELF parsing
# -------------------------------------------------------------------

ELF_MAGIC = b'\x7fELF'

EI_CLASS   = {1: "32-bit", 2: "64-bit"}
EI_DATA    = {1: "Little-endian (LSB)", 2: "Big-endian (MSB)"}
EI_OSABI   = {0: "UNIX System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD"}
E_TYPE     = {0: "ET_NONE", 1: "ET_REL (relocatable)",
              2: "ET_EXEC (executable)", 3: "ET_DYN (shared object/PIE)",
              4: "ET_CORE"}
E_MACHINE  = {0x3e: "x86-64 (AMD64)", 0x28: "ARM", 0xb7: "AArch64",
              0x03: "x86 (i386)", 0x08: "MIPS"}


def parse_elf(data):
    """Parse ELF header and print key fields."""
    if data[:4] != ELF_MAGIC:
        print("[-] Not an ELF file (wrong magic)")
        return False

    ei_class = data[4]
    ei_data  = data[5]
    ei_osabi = data[7]

    is_64 = (ei_class == 2)
    is_le = (ei_data == 1)
    endian = "<" if is_le else ">"

    print("ELF Header:")
    print(f"  Magic:        {' '.join(f'{b:02x}' for b in data[:16])}")
    print(f"  Class:        {EI_CLASS.get(ei_class, f'unknown ({ei_class})')}")
    print(f"  Data:         {EI_DATA.get(ei_data, f'unknown ({ei_data})')}")
    print(f"  Version:      {data[6]}")
    print(f"  OS/ABI:       {EI_OSABI.get(ei_osabi, f'unknown ({ei_osabi})')}")

    if is_64:
        fmt = f"{endian}HHIQQQIHHHHHH"
        fields = struct.unpack_from(fmt, data, 16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields
    else:
        fmt = f"{endian}HHIIIIIHHHHHH"
        fields = struct.unpack_from(fmt, data, 16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields

    print(f"  Type:         {E_TYPE.get(e_type, f'unknown ({e_type})')} (0x{e_type:04X})")
    print(f"  Machine:      {E_MACHINE.get(e_machine, f'unknown ({e_machine})')} (0x{e_machine:04X})")
    print(f"  Entry point:  0x{e_entry:016X}" if is_64 else f"  Entry point:  0x{e_entry:08X}")
    print(f"  PHoff:        0x{e_phoff:X}  ({e_phnum} entries × {e_phentsize} bytes each)")
    print(f"  SHoff:        0x{e_shoff:X}  ({e_shnum} entries × {e_shentsize} bytes each)")
    print(f"  Flags:        0x{e_flags:X}")

    print(f"\n  PIE/Type note: ", end="")
    if e_type == 3:
        print("ET_DYN → PIE-capable (shared object or position-independent executable)")
    elif e_type == 2:
        print("ET_EXEC → NOT PIE (fixed load address)")
    else:
        print(f"ET={e_type}")

    print(f"\n  Program headers: {e_phnum} (sections to load into memory)")
    print(f"  Section headers: {e_shnum} (debug/relocation info)")

    return True


# -------------------------------------------------------------------
# Magic scanner
# -------------------------------------------------------------------

def scan_magic(data, filename):
    """Scan entire file for known sub-format magic bytes."""
    print(f"\nMagic byte scan: {filename} ({len(data)} bytes)")
    print("-" * 50)

    found = []
    for magic, description in KNOWN_MAGIC.items():
        offset = 0
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            found.append((idx, magic, description))
            offset = idx + 1

    if not found:
        print("  No known magic bytes found.")
    else:
        found.sort(key=lambda x: x[0])
        for offset, magic, desc in found:
            hex_magic = " ".join(f"{b:02x}" for b in magic)
            print(f"  0x{offset:08X}: [{hex_magic}] → {desc}")

    return found


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ELF header parser and binary magic scanner for security research"
    )
    parser.add_argument("--file", required=True, help="Binary file to analyze")
    parser.add_argument("--scan-magic", action="store_true",
                        help="Also scan entire file for known sub-format magic bytes")
    parser.add_argument("--no-elf", action="store_true",
                        help="Skip ELF parsing (useful for non-ELF files with --scan-magic)")

    args = parser.parse_args()

    path = Path(args.file)
    if not path.is_file():
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    with open(path, "rb") as f:
        data = f.read()

    print(f"[*] File: {args.file}")
    print(f"[*] Size: {len(data)} bytes (0x{len(data):X})")
    print(f"[*] First bytes: {' '.join(f'{b:02x}' for b in data[:16])}")
    print("")

    if not args.no_elf:
        parse_elf(data)

    if args.scan_magic:
        scan_magic(data, args.file)


if __name__ == "__main__":
    main()
