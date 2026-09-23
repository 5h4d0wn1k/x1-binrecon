> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X1 — Binary Recon Tool (binrecon)

**Binary recon suite** by **5h4d0wn1k** for **malware triage and reverse-
engineering education**: static analysis of ELF32/64 and PE32/64 binaries —
headers, sections, symbol tables (SYMTAB/DYNSYM), dynamic imports and
`DT_NEEDED` libraries, per-section Shannon entropy, packer heuristics, string
extraction and patch-diff. Pure `struct`-based Python, no external
dependencies.

## Why static binary triage

Before a sample ever runs, a one-pass static recon answers the urgent
questions: what platform is it, what does it import, is it packed and where
is the interesting data? This tool turns those questions into a reproducible
workflow — parse real ELF headers and sections, enumerate symbol tables and
imports, map Shannon entropy per section to flag encrypted/packed regions,
score packer heuristics and dump printable strings — then emit a structured
recon JSON to `reports/`. Because there is no execution, analysis is safe and
offline. Use it only on binaries you own or are authorized to analyze (e.g. a
sample you compiled with `gcc`, or permitted malware in a sandbox) — see
[ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **ELF parsing** — ELF32/ELF64 headers and sections via pure `struct`
  (`ELFParser`).
- **Symbols and imports** — functions with addresses from `SYMTAB`/`DYNSYM`,
  plus dynamic imports and `DT_NEEDED` libraries from `.dynamic`.
- **PE parsing** — DOS/NT headers, sections and imports via pure `struct`
  (`PEParser`).
- **Entropy mapping** — per-section Shannon entropy (0.0–8.0) with visual
  bars to spot packed regions (`shannon_entropy`, `entropy_bar`).
- **Packer heuristics** — 0.0–1.0 scoring (UPX/ASPack/Themida-style indicators)
  based on section names and entropy (`score_packer`).
- **String extraction** — printable strings with configurable minimum length.
- **Patch-diff** — region-by-region byte comparison of two binaries.
- **Recon JSON** — header, sections, symbols, imports, entropy and strings
  written to `reports/` (gitignored).

## Quickstart

Prerequisites: Python 3.8+ (standard library only). `gcc` is optional and only
needed for the compiled-sample demo.

```bash
# Help
python3 firmware/binrecon.py --help

# Analyze a real compiled ELF binary (writes reports/recon_<name>.json)
python3 firmware/binrecon.py analyze <binary> [--report OUT.json]

# Dump printable strings
python3 firmware/binrecon.py strings <binary> --minlen 6

# Region-by-region diff of two binaries
python3 firmware/binrecon.py diff <binary_a> <binary_b>

# Offline end-to-end demo: compiles samples/vuln.c, parses a real ELF, emits JSON
python3 firmware/binrecon.py demo
python3 firmware/binrecon.py demo --no-gcc   # crafted ELF fixture, no compiler

# Run the test suite (37 deterministic offline tests)
python3 -m unittest discover -s tests
```

### Build and analyze the bundled sample

```bash
gcc -o samples/vuln_test -fno-stack-protector -no-pie samples/vuln.c
python3 firmware/binrecon.py analyze samples/vuln_test
```

The `analyze` output enumerates sections (`.text`, `.rodata`, `.dynamic`,
`.dynsym`), the function symbols (`win_function`, `vulnerable`, `main`),
dynamic imports (`strcpy`, `printf`, `__libc_start_main`), needed libraries
(`libc.so.6`) and per-section entropy — cross-check against `readelf -SW`.

## Project structure

```
firmware/binrecon.py   # ELF/PE parsers, entropy, packer score, CLI engine
samples/vuln.c         # gcc-compilable sample target for real-ELF tests
tests/                 # 37 deterministic assertions on real ELF + fixtures
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized analysis scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

More file formats, entropy heuristics and packer fingerprints are welcome.
Open an issue or PR against the default branch; keep contributions scoped to
educational static-analysis tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for analyzing binaries you own or are explicitly permitted
to inspect.