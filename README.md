# X1 — Binary Recon Tool — binrecon

Static binary triage CLI for ELF and PE analysis with entropy mapping and patch-diff.

## Overview

This project performs offline static analysis of binary files:
- Parses ELF32/ELF64 headers and sections using pure `struct`
- Parses PE DOS/NT headers, sections, and imports using pure `struct`
- Computes per-section Shannon entropy map to identify encrypted/packed regions
- Scores packer heuristics (UPX, ASPack, Themida, etc.) based on section names and entropy
- Extracts printable strings with configurable minimum length
- Provides patch-diff mode comparing two binaries section-by-section

## Features

- **ELF parsing**: ELF32/64, section headers, entry point, machine type
- **PE parsing**: DOS stub, NT headers, section table, import directory
- **Entropy analysis**: Shannon entropy per section with visual bar graph
- **Packer detection**: Heuristic scoring against known packer signatures
- **String extraction**: Configurable min-length, offset tracking, ASCII/Unicode
- **Patch-diff**: Side-by-side binary comparison with entropy delta

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/binrecon.py --help
```

## Usage

```bash
python3 firmware/binrecon.py analyze <binary>
python3 firmware/binrecon.py strings <binary> [--minlen 6]
python3 firmware/binrecon.py diff <binary_a> <binary_b>
python3 firmware/binrecon.py --demo
```

## Example Output

```
=== X1 - Binary Recon Tool (binrecon) ===

[ELF Header]
  Class:    ELF64
  Machine:  x86_64
  Entry:    0x1040
  Sections: 27

[Section Entropy]
  .text    : 6.12 ██████████████
  .rodata  : 5.84 █████████████
  .data    : 0.34 █
  .bss     : 0.00

[Packer Score]
  Score: 0.02 — Not packed

[Strings found: 142]
  @0x000042: "/lib64/ld-linux-x86-64.so.2"
  @0x00008a: "printf"

[Patch Diff Summary]
  Sections compared: 4
  Sections differing: 1 (.text — entropy 6.12 vs 6.34)
  Bytes differing: 2048 / 65536 (3.13%)
```

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
