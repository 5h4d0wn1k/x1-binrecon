# X1 — Binary Recon Tool — binrecon

Static binary triage CLI for ELF and PE analysis with symbols, dynamic imports, entropy mapping and patch-diff.

The engine **parses real ELF binaries** — sections, symbols (SYMTAB/DYNSYM), dynamic imports (DT_NEEDED + undefined dynsym), strings, per-section entropy — from a sample binary **you compile with `gcc`** (or from a crafted ELF fixture), and emits recon JSON to `reports/`.

## Overview

This project performs offline static analysis of binary files:
- Parses ELF32/ELF64 headers and sections using pure `struct`
- Parses symbol tables (`SYMTAB`/`DYNSYM`), exports functions with addresses, and enumerates dynamic imports + `DT_NEEDED` libraries
- Parses PE DOS/NT headers, sections, and imports using pure `struct`
- Computes per-section Shannon entropy map to identify encrypted/packed regions
- Scores packer heuristics (UPX, ASPack, Themida, etc.) based on section names and entropy
- Extracts printable strings with configurable minimum length
- Provides patch-diff mode comparing two binaries region-by-region
- Emits a structured recon JSON report (header, sections, symbols, imports, entropy, strings) to `reports/`

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/binrecon.py --help
```

## Usage

```bash
# Analyze a real compiled ELF binary (writes reports/recon_<name>.json)
python3 firmware/binrecon.py analyze <binary> [--report OUT.json]
python3 firmware/binrecon.py strings <binary> [--minlen 6]
python3 firmware/binrecon.py diff <binary_a> <binary_b>
# Offline end-to-end demo: compiles samples/vuln.c, parses real ELF, emits recon JSON
python3 firmware/binrecon.py demo
python3 firmware/binrecon.py demo --no-gcc   # uses crafted ELF fixture, no compiler needed
```

### Building the sample target (real engine input)

```bash
gcc -o samples/vuln_test -fno-stack-protector -no-pie samples/vuln.c
python3 firmware/binrecon.py analyze samples/vuln_test
```

The `analyze` output enumerates sections (`.text`, `.rodata`, `.dynamic`, `.dynsym`, ...),
the function symbols (`win_function`, `vulnerable`, `main`), the dynamic imports
(`strcpy`, `printf`, `__libc_start_main`), needed libraries (`libc.so.6`), and
per-section entropy, then writes `reports/recon_vuln_test.json`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. Build the real sample: `gcc -o samples/vuln_test -fno-stack-protector -no-pie samples/vuln.c`
2. `python3 firmware/binrecon.py analyze samples/vuln_test` — confirm ELF64 header, section count and `.dynsym`/`.symtab` sizes match `readelf -SW`.
3. Verify the symbols panel lists `win_function`/`vulnerable`/`main` and imports list `strcpy`/`printf`.
4. `python3 firmware/binrecon.py demo` — compiles, parses the real ELF, writes `reports/recon_vuln_target.json`, then analyzes a synthetic PE fixture; exits 0.
5. `python3 -m unittest discover -s tests` — 37 deterministic assertions on real ELF parse, symbols/imports, entropy math, strings, JSON reports, CLI.

## Metrics

- ELF32/ELF64 + PE32/PE64 parsing via `struct`, no external deps
- Symbols parsed from `SYMTAB`/`DYNSYM`; dynamic imports + `DT_NEEDED` libraries extracted from real ELFs
- Shannon entropy (0.0–8.0) per section; packer heuristic scoring 0.0–1.0
- 37 unittest assertions, all offline/deterministic (real gcc-compiled ELF included)
- Recon JSON emitted to `reports/` (gitignored)

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Unauthorized analysis of binaries may violate applicable laws
- This tool should ONLY be used on binaries you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Copyright Act**: Reverse engineering may be restricted by license agreements
- **State Laws**: Many states have additional computer crime statutes
- **EU Directive 2009/24/EC**: Reverse engineering of software may have legal restrictions

### Acceptable Use
- Analyzing your own binaries for security assessment
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training
- Malware analysis in isolated sandboxes

### Prohibited Use
- Analyzing proprietary software without authorization
- Reverse engineering to circumvent copy protection
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
