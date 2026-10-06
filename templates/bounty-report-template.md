# Vendor Bug Bounty Report Template

> Check the specific program's submission portal and preferred channel
> before using this template — some programs require submission through a
> specific platform (e.g. HackerOne, Intigriti, Bugcrowd, or a vendor's own
> portal) and treat other channels (e.g. a generic support/PSIRT email) as
> not bounty-eligible even for a valid finding.

---

## Overview

**Summary:**
[One paragraph: what is the vulnerability, where is it, and what can an attacker do with it]

**Impact statement:**
[What is the worst-case impact? Data exfiltration? Code execution? Denial of service?
Who is affected — any user who opens a file? An administrator? A remote attacker?]

**Product affected:**
- Name: [Vendor] [Product Name]
- Version: [exact version string from --version output]
- Build: [build number if available]
- Platform: [e.g. Linux x86-64]

---

## Details

**Vulnerability type:**
[e.g. Heap-based buffer overflow / Integer overflow / Use-after-free / OOB read]

**CWE:**
[e.g. CWE-122: Heap-based Buffer Overflow]
[Reference: https://cwe.mitre.org/data/definitions/122.html]

**Vulnerable component:**
- Binary: [e.g. /opt/vendor/product/bin/tool]
- Library: [e.g. libexample_parser.so]
- Function: [e.g. parse_record() at offset 0x...]

**Root cause:**
[Technical explanation: which field is attacker-controlled, how it reaches the vulnerable
operation, and why the existing validation (if any) is insufficient]

**How it can be exploited:**
[Step-by-step attack scenario: what does an attacker need to do, what do they need to
provide, and what privilege/access do they end up with]

**Likelihood of successful exploit:**
[High / Medium / Low — justify based on: attacker access required, mitigations present,
reliability of crash reproduction]

---

## CVSS Scoring

Use whichever CVSS version the program's own severity table is based on
(check their published rules — most currently use 3.1 or 4.0).

**Score:** [X.X]
**Vector:** [full CVSS vector string]

**Justification (field by field):**

| Metric | Value | Justification |
|---|---|---|
| AV (Attack Vector) | N/L/A/P | [why: Network / Local / Adjacent / Physical] |
| AC (Attack Complexity) | L/H | [why: no special conditions needed / requires specific config] |
| PR (Privileges Required) | N/L/H | [why: none / low / high] |
| UI (User Interaction) | N/P/A | [why: none / passive / active] |
| C/I/A (Confidentiality/Integrity/Availability) | N/L/H each | [why, scored only against what was actually demonstrated] |

(For CVSS 4.0 programs, also include AT, and the Subsequent System SC/SI/SA
metrics per that program's template.)

---

## Proof of Concept

### Environment
```
OS: [e.g. distro and version]
Kernel: [output of uname -r]
Product version: [exact --version output]
gdb version: [gdb --version | head -1]
```

### Steps to reproduce

**Step 1: Install the affected product**
```bash
[exact installation commands]
```

**Step 2: Generate a baseline valid input**
```bash
[exact command to create a valid test case]
```

**Step 3: Apply the mutation (PoC)**
```python
# poc_mutator.py
import struct

path = "[path to input file]"
with open(path, "r+b") as f:
    data = bytearray(f.read())
    # mutate field at offset 0xNN: change from [original] to [malicious value]
    data[0xNN:0xNN+4] = struct.pack("<I", 0xFFFFFFFF)
    f.seek(0)
    f.write(data)
print("PoC applied.")
```

**Step 4: Trigger the vulnerability**
```bash
[exact command that triggers the crash]
```

### Expected output (normal behavior)
```
[what the tool normally prints]
```

### Actual output (crash)
```
[full crash output including gdb backtrace]

Program received signal SIGSEGV, Segmentation fault.
[address] in [function] ()
(gdb) bt full
[full backtrace here]

(gdb) info registers
[register state here]
```

### Crash analysis
```
Faulting instruction: [e.g. mov rax, [rdx+0x10]]
Faulting address: [e.g. 0x4141414141414141 — attacker controlled]
Controlled register: [e.g. rdx contains 0xFFFFFFFF from our mutated field]
```

---

## Researcher Information

**Submission platform username:** [your platform username]
**Acknowledgement preference:** [username / anonymous]

---

## Appendix

### A. Affected file format analysis
[Document the binary format you reverse engineered, including field offsets and sizes]

### B. Relevant disassembly
```
[paste the r2 pdf output showing the vulnerable code path]
```

### C. Shared library analysis
```
[readelf / objdump output confirming the vulnerable function's presence]
```
