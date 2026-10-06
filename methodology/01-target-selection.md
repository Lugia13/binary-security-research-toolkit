# 01 — Target Selection

## Goal
Pick a product that is in-scope, currently maintained, and tractable for
your toolchain before investing any analysis time.

---

## Generic Scope Quick-Filter

Most vendor bug bounty programs publish a scope document with distinctions
along these lines — check the specific program's current rules before
assuming any of these, this is only the general shape:

| Category | Typically eligible? |
|---|---|
| First-party vendor products | Usually yes |
| Third-party/bundled products | Usually no |
| Licensed/OEM-specific variants | Often no — check carefully |
| Pre-release / beta builds | Often excluded |
| End-of-life products | Often no bounty, but still worth reporting responsibly |
| Open-source projects solely maintained by the vendor | Often yes |
| Vendor's own corporate IT infrastructure (vs. shipped product) | Usually a separate program or out of scope |
| Physical/open-chassis hardware attacks | Program-dependent |

Always cross-check against the program's current published scope and any
"discontinued products" list before starting — these change over time and
a stale assumption wastes analysis effort on something that's no longer
eligible.

---

## Category Priority (by typical bounty ceiling)

Programs commonly tier reward ceilings by category, roughly in this shape
(check the specific program's current published table for real numbers):

```
Hardware    → highest ceiling   (requires physical hardware, often out of scope for a CLI-only lab)
Firmware    → high ceiling      (requires UEFI/low-level tooling + emulation)
Software    → mid ceiling       ← best fit for a CLI-only lab
Cloud/web   → program-dependent
```

For a CLI-only research environment with no special hardware, software
targets are usually the best fit — tractable with standard binary analysis
tooling, no physical access or emulation required.

---

## Toolchain Fit Check

Before selecting a target, ask:

1. **Is it an ELF binary?**
   - Yes → your full toolchain applies
   - No (PE/TE/UEFI module) → needs PE-aware tooling and UEFI emulation

2. **Is the format known?**
   - Parses standard formats (ELF, XML, ZIP) → faster to start
   - Parses custom binary formats → higher value but more RE effort needed

3. **How is it installed?**
   - APT/deb → use `dpkg-deb -x` or install directly
   - Tarball → extract and analyze in place
   - Requires hardware → out of scope for a CLI-only lab

4. **Is it actively maintained?**
   - Check the vendor's download page for the release date
   - Most programs require a demonstrated bug against the "currently
     supported" version
   - Anything with no update in 2+ years risks being end-of-life

---

## Download Verification

Always download from the vendor's official distribution channel only —
never a mirror or third-party repackaging, since you need to be certain
you're analyzing the genuine, unmodified binary:

```bash
# Official vendor package repository (example shape — adjust for the real target)
wget -O- https://example-vendor.com/gpg-key.pub \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/vendor-archive-keyring.gpg > /dev/null

# Verify you got the official binary
/path/to/tool --version
# Note the exact version string and build number for your report
```

---

## Version Recording (required for most reports)

As soon as you have the binary, record the environment precisely — most
programs require this as a report field, and it's also what lets you (or
anyone else) reproduce your result later:

```bash
# save this immediately
<binary> --version 2>&1
uname -r
lsb_release -a
date -u
```
