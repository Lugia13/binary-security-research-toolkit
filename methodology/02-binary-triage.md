# 02 — Binary Triage

## Goal
In one pass, answer: which binaries are worth analyzing, and in what order?

---

## Step 1 — Inventory All ELF Binaries

```bash
INSTALL_DIR="/opt/vendor/product/latest"  # adjust to the real install path

# find every ELF in the install tree
find "$INSTALL_DIR" -type f -exec file {} \; | grep ELF | tee /tmp/elf_inventory.txt

# count them
wc -l /tmp/elf_inventory.txt
```

### What to note:
- **Stripped vs not stripped** — unstripped binaries have real symbol names → much faster to analyze
- **Shared objects (.so) vs executables** — `.so` files often hold the actual logic; executables are thin wrappers
- **File sizes** — very large binaries (>50MB) are often bundled third-party (Electron/Chromium) → skip
- **ELF type** — `LSB pie executable` (ASLR-enabled) vs `LSB executable` (fixed base)

---

## Step 2 — Mitigation Audit

```bash
# batch checksec across target binaries
for f in <binary1> <binary2> <binary3>; do
  echo "=== $f ==="
  checksec "$f" 2>/dev/null
done
```

### Mitigation flags to record:

| Flag | Good value | Bad value | Impact if bad |
|---|---|---|---|
| NX | Yes | No | Stack/heap shellcode execution |
| PIE | Yes | No | Fixed addresses aid exploitation |
| Canary | Yes | No | Stack overflow easier to exploit |
| RELRO | Full | Partial/No | GOT overwrite possible |
| RPATH | No | Yes | Library hijack if path is relative/writable |
| RUNPATH | No | Yes | Same as RPATH, lower precedence |
| FORTIFY | Yes | No | Some buffer overflows caught at runtime |
| Symbols | No | Yes | Reversed more easily (lower barrier, not a vuln) |

### RPATH check:
```bash
readelf -d <binary> | grep -iE 'rpath|runpath'
# flag: $ORIGIN/../lib64 is relative — check if that dir is writable
ls -la $(dirname <binary>)/../lib64
```

---

## Step 3 — Dependency Chain

```bash
# full runtime dependency resolution
ldd <binary>

# check for missing libraries (=> not found)
ldd <binary> | grep "not found"

# check NEEDED entries directly
readelf -d <binary> | grep NEEDED
```

### What to look for:
- **Vendor-authored `.so` files** → these are your analysis targets (same scope as the binary)
- **Third-party `.so` files** (libxml2, libssl, libstdc++) → skip unless bug is in how they're called
- **`not found` entries** → potential library injection point if the RPATH is attacker-influenceable

---

## Step 4 — Prioritization Matrix

Score each binary on these axes, pick the highest total:

```
Attack surface reachability:
  4 = File/network input processed without authentication
  3 = Local file input from user-specified path
  2 = CLI arguments only
  1 = Internal IPC only

Symbol availability:
  2 = Not stripped (real function names)
  1 = Stripped (address-only, harder)

Binary size (tractability):
  3 = < 500KB
  2 = 500KB–5MB
  1 = > 5MB

Mitigation gaps:
  +1 per missing mitigation (no canary, no PIE, etc.)
```

Highest score = analyze first.
