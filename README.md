# Binary Security Research Toolkit

> Binary-level security research methodology for auditing first-party
> vendor software shipped as Linux ELF binaries, developed for authorized
> bug bounty research.

---

## Overview

This repository documents the methodology, tooling, and scripts used during
structured, CLI-only binary security research against vendor-shipped
software on Linux. The workflow is designed for resource-constrained
environments (8GB RAM, no GUI tools required) and is vendor-agnostic —
every script takes the target binary/library as an argument.

**This repository documents methodology and tooling only.** No
vulnerability details, target names, or specific findings from any
engagement are included — those remain subject to each program's
responsible disclosure process.

Portfolio: [oussamasaddati.vercel.app](https://oussamasaddati.vercel.app)

---

## Environment

| Component | Details |
|---|---|
| OS | Linux x86-64 (Debian-based) |
| RAM | 8GB |
| Workflow | CLI-only — no GUI reversing tools |
| Architecture | x86-64 ELF binaries + shared libraries |

**Toolchain:**
```
radare2       — disassembly, cross-reference analysis, function mapping
gdb           — dynamic analysis, breakpoints, crash inspection
readelf       — ELF structure, dynamic symbols, section headers
objdump       — disassembly, export tables, batch symbol search
checksec      — binary mitigation audit (NX, PIE, RELRO, canary, FORTIFY)
nm            — symbol table enumeration (stripped vs unstripped)
strings       — passive surface scan for embedded artifacts
strace        — syscall tracing to map runtime file access patterns
ldd           — shared library dependency chain resolution
xxd           — hex dump for binary format reverse engineering
python3       — binary file mutation scripting
bash          — automation loops across multiple targets
```

---

## Repository Structure

```
binary-security-research-toolkit/
├── README.md                          ← this file
├── methodology/
│   ├── 01-target-selection.md         ← how to pick an in-scope target
│   ├── 02-binary-triage.md            ← initial mitigation + surface audit
│   ├── 03-static-analysis.md          ← radare2 + readelf workflow
│   ├── 04-attack-surface-mapping.md   ← trust boundary classification
│   └── 05-dynamic-testing.md          ← gdb + strace workflow
├── scripts/
│   ├── batch-checksec.sh              ← run checksec across all ELF binaries
│   ├── import-hunter.sh               ← grep dangerous imports across libs
│   ├── lib-symbol-finder.sh           ← find which .so defines a given symbol
│   ├── binary-mutator.py              ← generic binary field mutator for PoC
│   ├── trace-file-map.sh              ← map runtime file access via strace
│   └── elf-header-dump.py             ← parse and display ELF header fields
├── templates/
│   └── bounty-report-template.md      ← generic, fill-in-the-blank report template
└── .gitignore
```

---

## Methodology Summary

### 1. Target Selection
- Verify the product is first-party, currently supported, not end-of-life
- Confirm the download source is the vendor's official site or package repository
- Check the vendor's discontinued-products page before investing time
- Prefer: native Linux ELF binaries, actively maintained, complex parsers

### 2. Binary Triage
- Run `file` on all executables to filter ELF vs scripts vs blobs
- Run `checksec` batch across all binaries — flag any missing mitigations
- Check RPATH/RUNPATH for relative paths → potential library hijack surface
- Separate stripped from unstripped binaries — unstripped are faster to start on

### 3. Static Analysis
- `readelf --dyn-syms` → full import table, look for raw unsafe functions
- `nm` → local symbol table (unstripped only) → real function names
- `r2 -A` → auto-analysis, `afl` for function list, `axt` for cross-references
- Trace data flow from attacker-controlled inputs to dangerous call sites
- Audit safe-wrapper implementations before assuming they are correct

### 4. Attack Surface Classification

| Surface | Trust Boundary | Priority |
|---|---|---|
| CLI argument parsing | Weak (self-exploitation) | Low |
| Config file parsing | Medium (local file) | Medium |
| Result/trace file parsing | Strong (shared file, cross-user) | **High** |
| Network protocol parsing | Strong (remote) | **High** |
| Loaded plugin/library parsing | Strong (supplied binary) | **High** |

### 5. Dynamic Testing
- Always work on a **copy** of the target file — never mutate originals
- Use `strace -e trace=openat` to confirm which files are actually read at runtime
- Use `gdb` with `set breakpoint pending on` for shared library functions
- Watch memory usage in a second terminal during large-input tests
- Capture: `bt full`, `info registers`, `x/32xb` at any crash point

### 6. PoC Development
- Identify the exact byte offset controlling the vulnerable field
- Use a De Bruijn / cyclic pattern to determine which offset controls which register
- Build minimal reproducer — smallest possible input that triggers the crash
- Document exact command, file, and environment for reproduction

---

## Report Format

Most bounty programs require, at minimum:

```
1. Product name + exact version + build number
2. CWE identification
3. CVSS score + vector string + field-by-field justification
4. Overview / impact statement
5. Detailed technical explanation
6. Likelihood of exploitation
7. PoC — step-by-step reproduction instructions
8. Development environment: OS, compiler (if applicable), tool versions
9. Proof of successful exploitation (crash output, gdb bt, register state)
```

See [`templates/bounty-report-template.md`](templates/bounty-report-template.md)
for a generic, fill-in-the-blank version — adapt the CVSS section and
submission details to the specific program's current requirements.

---

## Key Lessons

- **Confirm the actual code path** before mutating inputs — use `strace` first
- **Rule out safe wrappers before assuming they're broken** — audit the implementation
- **Stripped binaries still reveal structure** via import tables and `axt` xrefs
- **Trust boundary determines impact** — local CLI bugs rarely earn bounties
- **Silent failure ≠ safe** — unchecked return values from "safe" functions are still bugs
- **File-parsing bugs cross user trust boundaries** — highest value for bounty programs

---

## Responsible Disclosure

No vulnerability details are published here. Any research conducted using
this methodology follows the responsible disclosure timeline of the
specific program it was reported to.

---

## License

MIT — see [LICENSE](./LICENSE). Provided for educational and authorized
security testing purposes only.
