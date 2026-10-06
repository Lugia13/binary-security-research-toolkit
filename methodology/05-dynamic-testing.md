# 05 — Dynamic Testing

## Goal
Confirm a statically-identified hypothesis with a real crash or behavioral anomaly.
Dynamic proof is required for most bug bounty programs' eligibility criteria -- check the specific program's rules.

---

## Pre-Test Checklist

```
[ ] Working on a COPY of the target file — original untouched
[ ] Know exactly which phase reads the file (confirmed via strace)
[ ] Know the exact byte offset of the field to mutate
[ ] Have a second terminal open to monitor memory usage
[ ] gdb installed and confirmed working
[ ] Know the expected crash type (segfault, assert, OOM)
```

---

## Setting Up gdb for Shared Library Targets

Most interesting functions live in shared libraries, not the main binary.
By default, gdb won't find them until the library is loaded.

```bash
gdb --args <binary> <arguments>

# inside gdb:
(gdb) set breakpoint pending on      # ← critical: allow pending breakpoints

# set breakpoints BEFORE run
(gdb) b example_parse_function          # C function name
(gdb) b _ZN13example_class22example_parse_functionEj   # C++ mangled name

# run
(gdb) run
```

### Finding the right symbol names:
```bash
# C functions (not mangled)
nm <lib.so> | grep -iE 'parse|read|load' | grep ' T '

# C++ functions (mangled) — set the breakpoint using the mangled form
nm <lib.so> | grep -iE 'parse|read|load' | grep ' T '
# example: _ZN13example_class22example_parse_functionEj

# demangle to read, but break on mangled form
nm <lib.so> | grep ' T ' | c++filt | grep -i read
```

---

## When a Breakpoint Hits

```
(gdb) bt full            # full backtrace with local variables
(gdb) info registers     # all register values at this point
(gdb) x/32xb $rdi        # 32 bytes at address in rdi (first argument)
(gdb) x/32xb $rsi        # second argument
(gdb) x/8xg $rsp         # 8 quadwords from stack pointer
(gdb) p/x $rax           # print register as hex
(gdb) info locals        # local variables (if symbols available)
```

Save everything to a file:
```bash
gdb --args <binary> <arguments> 2>&1 | tee /tmp/gdb_session.log
```

---

## When It Crashes (Segfault)

This is what you want. Capture immediately:

```
(gdb) bt full            # where did it crash?
(gdb) info registers     # what was in every register?
(gdb) x/32xb <faulting_address>   # what's at the address that was accessed?
(gdb) disas              # what instruction caused the fault?
```

Key questions to answer:
1. **What address was being accessed when it crashed?** (`$rip`, `$rdi`, `$rsi`)
2. **Is that address attacker-controlled?** (Does it contain bytes from your mutated file?)
3. **What was the call stack?** (Which library function → which function → which function)
4. **Can you make it crash reproducibly?** (Run the same mutated file 3 times)

---

## Input Mutation Strategy

### Level 1: Oversized fields
```python
# claim the data is much larger than it actually is
data[offset:offset+4] = (0xFFFFFFFF).to_bytes(4, "little")
```
Tests: does the parser validate the length against actual file size?

### Level 2: Undersized fields
```python
# claim the data is much smaller than it actually is
data[offset:offset+4] = (0x00000001).to_bytes(4, "little")
```
Tests: does the parser read past the claimed end?

### Level 3: Zero fields
```python
data[offset:offset+4] = (0x00000000).to_bytes(4, "little")
```
Tests: division-by-zero, null deref after zero-size malloc

### Level 4: Maximum value
```python
data[offset:offset+4] = (0xFFFFFFFF).to_bytes(4, "little")
```
Tests: integer overflow when value is used in arithmetic before malloc

### Level 5: Boundary values
```python
# off-by-one around actual file size
actual_remaining = len(data) - offset - 4
data[offset:offset+4] = (actual_remaining + 1).to_bytes(4, "little")
data[offset:offset+4] = (actual_remaining - 1).to_bytes(4, "little")
```

---

## Memory Monitoring During Tests

Run in a separate terminal while gdb executes:

```bash
# watch process memory usage
watch -n 0.5 'ps aux | grep <binary_name> | grep -v grep | awk "{print \$6, \"KB\"}"'

# or use top filtered
top -p $(pgrep -f <binary_name>)
```

On an 8GB system:
- If RSS climbs above 4GB → kill the process (`Ctrl-C` in gdb)
- This indicates an unchecked allocation size — a DoS finding even if no crash

---

## Documenting a Crash for the Report

Minimum required capture:

```bash
# 1. the mutated file (keep a copy)
cp /tmp/mutated_input /tmp/poc_input_final

# 2. the exact command that triggers it
echo "Command: gdb --args <full command here>" >> /tmp/poc_notes.txt

# 3. gdb output
gdb --args <binary> <args> < /tmp/gdb_commands.txt 2>&1 | tee /tmp/crash_output.txt

# 4. environment
uname -r >> /tmp/poc_notes.txt
lsb_release -a >> /tmp/poc_notes.txt
<binary> --version >> /tmp/poc_notes.txt
gdb --version | head -1 >> /tmp/poc_notes.txt
```

The report must include all of the above — exact command, exact input, exact output.
