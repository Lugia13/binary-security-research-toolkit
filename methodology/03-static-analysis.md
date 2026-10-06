# 03 — Static Analysis

## Goal
Map the binary's attack surface without running it.
Find functions where attacker-controlled data reaches dangerous operations.

---

## Phase A — Import Table Analysis

The import table tells you which dangerous operations the binary CAN perform.

```bash
# full import table — all undefined (imported) functions
readelf --dyn-syms <binary> | grep -iE 'FUNC.*UND'

# targeted search — dangerous memory operations
readelf --dyn-syms <binary> | grep -iE \
  'memcpy|memmove|memset|strcpy|strcat|sprintf|snprintf|printf|scanf|gets|read|recv|malloc|realloc|calloc|alloca|system|popen|exec|dlopen'
```

### Interpretation:

| Import present | What to look for |
|---|---|
| `strcpy`, `strcat` (raw) | Any use is suspicious — no bounds parameter |
| `sprintf` (raw) | Format string + size-unaware |
| `memcpy` | Who provides the size argument? |
| `malloc` / `calloc` | Where does the size come from? Attacker-influenced? |
| `dlopen` | What provides the path? Attacker-influenced? |
| `system` / `popen` | Any attacker-controlled string reaching this? Critical |
| Custom `*_safe` wrappers | Audit the wrapper itself before trusting it |

### If only safe wrappers are present:
Do NOT assume they are bug-free.
Locate the library that **defines** them (not just imports):

```bash
for lib in /path/to/lib64/*.so*; do
  result=$(objdump -T "$lib" 2>/dev/null | grep 'strcpy_safe\|sprintf_safe\|memcpy_safe' | grep -v UND)
  [ -n "$result" ] && echo "=== $lib ===" && echo "$result"
done
```

Then audit the wrapper's implementation directly in r2.

---

## Phase B — Symbol Table (Unstripped Binaries)

```bash
# all local defined functions
nm <binary> | grep ' T '   # .text section (functions)

# filter for interesting names
nm <binary> | grep -iE 'parse|load|read|import|open|map|alloc|copy|inject|elf|segment|section|image'

# C++ class names
nm <binary> | grep '_ZN' | c++filt | head -40
```

---

## Phase C — radare2 Analysis

```bash
r2 -A <binary>
# -A runs aaa (auto-analysis): finds functions, xrefs, strings, vtables
```

### Core commands:

```
afl                    → list all functions found
afl | wc -l            → count (sanity check — too many = soft-float noise)
afl | grep -i parse    → filter by name
afl | grep -i read

pdf @ <address>        → disassemble a function
pdf @ sym.main
pdf @ sym.strcpy_safe  → read the wrapper implementation

axt sym.imp.memcpy     → find ALL callers of memcpy
axt sym.imp.strcpy_safe
axt sym.imp.malloc
axt sym.imp.dlopen

iz                     → strings embedded in the binary
izz                    → strings including non-default sections
```

### Noise filtering:
Large binaries often include statically linked math/float libraries.
If `afl` shows hundreds of `sym.__addq`, `sym.__mulq`, `sym.__divq` entries,
these are soft-float emulation routines — irrelevant, skip them.

Filter the real application functions:
```
afl | grep -v '__addq\|__mulq\|__divq\|__subq\|__geq\|__leq\|__qtof\|__dtoq'
```

---

## Phase D — Call Site Analysis

For each dangerous import identified, inspect every call site:

```
[0x...]> axt sym.imp.memcpy
```

For each result, navigate to that address and read the surrounding code:

```
[0x...]> pdf @ <caller_address>
```

**What to trace for each call site:**

1. **`rdi` (arg1 = dest)** → where is this buffer? stack or heap? how big is it?
2. **`rsi` (arg2 = src)** → where does the source data come from? attacker-controlled?
3. **`rdx` (arg3 = size)** → where does the size come from?
   - Hardcoded constant → likely safe
   - From a struct field read from a file → **attacker-controlled**
   - Computed from `strlen(src)` → depends on who controls `src`
   - Multiplied or shifted → watch for integer overflow

### Data flow tracing pattern:
```
call memcpy
  ↑
mov rdx, [rax + 0x10]   ← size from struct at offset 0x10
  ↑
mov rax, [rbp - 0x28]   ← struct pointer from stack
  ↑
call read_from_file      ← struct was populated by file parser
  ↑
attacker controls the file → attacker controls rdx → attacker controls copy size
```

---

## Phase E — Shared Library Analysis

Key difference: shared libraries export their functions for others to call.

```bash
# what a .so exports (its public API)
objdump -T <lib.so> | grep -v UND | grep ' DF '

# what a .so imports (its dependencies — may reveal internal bug patterns)
objdump -T <lib.so> | grep UND
```

Apply the same r2 analysis to `.so` files — `r2 -A <lib.so>` works identically.
