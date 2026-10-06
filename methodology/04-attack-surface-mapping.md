# 04 — Attack Surface Mapping

## Goal
Identify which inputs cross a real trust boundary.
Bugs in code that processes attacker-controlled data are bounty-worthy.
Bugs only reachable by an already-privileged local attacker are usually not.

---

## Trust Boundary Classification

### Tier 1 — Highest value (remote/cross-user attacker)
- **Network-parsed data** — anything received over a socket before authentication
- **Shared result/data files** — a file produced by user A and opened by user B
  (e.g. profiling result files shared with a colleague, opened with a viewer tool)
- **Plugin/extension loading** — a tool that loads externally-supplied `.so`/library files
  where the file content drives parsing code before the plugin actually executes

### Tier 2 — Medium value (local attacker, different privilege)
- **Config files in shared directories** — if readable/writable by a different user
- **Files read by a SUID/privileged binary** — even if local, privilege escalation is the impact
- **IPC messages** — if the receiving process runs at higher privilege

### Tier 3 — Lower value (same-user, self-exploitation)
- **CLI arguments to non-privileged tools** — attacker = user = victim, no privilege gain
- **Environment variables** — same issue, typically self-exploitation only
- **Files in the user's own home directory** — no cross-user trust boundary

---

## Confirming the Actual Code Path

Before spending time mutating inputs, confirm what code actually runs.
Never assume — verify with `strace`:

```bash
# what files does the tool actually open during this operation?
strace -f -e trace=openat,open -o /tmp/trace.log \
  <binary> <arguments>

# which of those files is it actually reading?
strace -f -e trace=openat,read -o /tmp/trace.log \
  <binary> <arguments>

# did it open any interesting library at runtime (dlopen)?
grep -i 'interesting_lib_name' /tmp/trace.log
```

### Common trap: pre-processed caches
Many tools pre-process raw input during an initial "import/finalize" phase,
storing results in a database or cache. Subsequent "report/view" operations
read the cache, never touching the raw input again.

**To identify this:**
```bash
# run the import/finalize phase under strace
strace -f -e trace=openat -o /tmp/import.log <tool> <import-command>
grep 'raw_input_file' /tmp/import.log

# run the report phase under strace  
strace -f -e trace=openat -o /tmp/report.log <tool> <report-command>
grep 'raw_input_file' /tmp/report.log

# if raw file appears in import.log but NOT in report.log:
# → you must mutate BEFORE the import/finalize step
# → deleting the cache database forces re-import
```

---

## Binary Format Reverse Engineering

When a tool parses a proprietary binary format, reverse the format from valid samples
before writing a mutator.

### Process:

**Step 1: Collect multiple valid samples**
```bash
# run the tool multiple times with different inputs
# collect all output files
find /tmp/result_dir -type f -exec ls -la {} \;
```

**Step 2: Hex dump and cross-compare**
```bash
xxd sample1.bin | head -20
xxd sample2.bin | head -20
xxd sample3.bin | head -20
```

Look for:
- Fixed bytes at offset 0 → magic number
- Bytes that match `filesize - N` → length field (find the offset and formula)
- Known sub-format magic bytes → e.g. `28 B5 2F FD` = Zstandard, `1F 8B` = gzip, `50 4B` = ZIP
- Repeating structures at fixed offsets → record array / section table

**Step 3: Verify length field formula**
```
Verify: length_field_value = filesize - header_size
Test across 3+ samples before assuming the formula is correct
```

**Step 4: Document the format**
```
Offset 0x00: 4 bytes  — magic / tag
Offset 0x04: 4 bytes  — format identifier
Offset 0x08: 2 bytes  — reserved
Offset 0x0A: 2 bytes  — version/flags
Offset 0x0C: 4 bytes  — LE uint32 length (= filesize - 12)
Offset 0x10: 2 bytes  — section tag
Offset 0x12: 4 bytes  — payload compression magic
Offset 0x16: N bytes  — compressed payload
```

---

## Attacker-Controlled Field Identification

Once the format is mapped, classify each field:

| Field type | Attacker control | Risk |
|---|---|---|
| Magic / signature | Fixed — parser likely rejects wrong value | Low |
| Version / flags | Partially — may enable different code paths | Medium |
| **Length / size / count** | **Full control** | **High** |
| Payload data | Full control | High |
| Checksum / CRC | Computable if algorithm is known | Medium |

**Highest-value mutation targets:**
1. Length/size fields used as `malloc()` argument or loop bound
2. Count fields driving array indexing without bounds check
3. Offset fields used for pointer arithmetic into a fixed buffer
4. Enum/type fields selecting a handler function (type confusion)
