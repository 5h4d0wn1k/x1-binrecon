# X1 — Binary Recon Tool — binrecon

Static binary triage CLI for ELF and PE analysis with entropy mapping and patch-diff.

The engine **actually disassembles/parses real ELF handles** (sections, symbols, entry points, entropy, dangerous functions, strings) from a sample binary you compile with gcc, or from a synthetic ELF fixture, and emits recon JSON.

## Overview

This project performs offline static analysis of binary files:
- Parses ELF32/ELF64 headers and sections using pure `struct`
- Parses PE DOS/NT headers, sections, and imports using pure `struct`
- Computes per-section Shannon entropy map to identify encrypted/packed regions
- Scores packer heuristics (UPX, ASPack, Themida, etc.) based on section names and entropy
- Extracts printable strings with configurable minimum length
- Provides patch-diff mode comparing two binaries section-by-section
- Emits a structured recon JSON report (sections, symbols, dangerous functions, entropy, strings) to `reports/`

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/binrecon.py --help
```

## Usage

```bash
# Analyze a real compiled ELF binary
python3 firmware/binrecon.py analyze <binary>
python3 firmware/binrecon.py strings <binary> [--minlen 6]
python3 firmware/binrecon.py diff <binary_a> <binary_b>
python3 firmware/binrecon.py --demo
```

### Building the sample target (real engine input)

```bash
gcc -o samples/vuln_test -fno-stack-protector -no-pie samples/vuln.c
python3 firmware/binrecon.py analyze samples/vuln_test
```

This parses the real ELF64, enumerates sections (`.text`, `.rodata`, `.data`, `.bss`, `.dynsym`, `...`), detects the dangerous `strcpy`/`win_function` symbols, computes per-section entropy, and reports packer score.

### Recon JSON output

Analyze mode writes `reports/recon_<file>.json` containing `{sections, symbols, dangerous_functions, entropy, strings}`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. `build_samples.sh`-equivalent: `gcc -o samples/vuln_test -fno-stack-protector -no-pie samples/vuln.c`
2. `python3 firmware/binrecon.py analyze samples/vuln_test` — confirm ELF64 header, section count, `.interp`/`.dynsym` sizes match `readelf -SW`.
3. `python3 firmware/binrecon.py --demo` — confirms synthetic ELF + PE fixture parse and patch-diff work offline.
4. `python3 -m unittest discover -s tests` — 27 deterministic assertions on real ELF parse, entropy math, strings, CLI.

## Metrics

- ELF32/ELF64 + PE32/PE64 parsing via `struct`, no external deps
- Shannon entropy (0.0–8.0) per section; packer heuristic scoring 0.0–1.0
- 27 unittest assertions, all offline/deterministic
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
