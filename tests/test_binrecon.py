#!/usr/bin/env python3
"""Tests for X1 - Binary Recon Tool (binrecon)"""
import unittest
import sys
import os
import struct
import json
import subprocess
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from binrecon import (
    ELFParser, PEParser, shannon_entropy, entropy_bar, extract_strings,
    score_packer, build_sample_elf, analyze_elf, analyze_pe,
    run_string_extraction, run_patch_diff, ELFMAG, PE_MAGIC, PE_SIG,
    build_recon, write_recon, build_sample_binary, report_dir, sanitize,
)


class TestShannonEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_uniform(self):
        data = bytes(range(256))
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=1)

    def test_repetitive(self):
        self.assertAlmostEqual(shannon_entropy(b"\x00" * 100), 0.0)

    def test_partial(self):
        ent = shannon_entropy(b"ABABABAB")
        self.assertGreater(ent, 0.0)
        self.assertLess(ent, 8.0)


class TestEntropyBar(unittest.TestCase):
    def test_zero(self):
        bar = entropy_bar(0.0)
        self.assertIn("░", bar)
        self.assertNotIn("█", bar)

    def test_max(self):
        bar = entropy_bar(8.0)
        self.assertIn("█", bar)


class TestELFParser(unittest.TestCase):
    def test_valid_elf64(self):
        data = build_sample_elf(b"test")
        parser = ELFParser(data)
        self.assertEqual(parser.header["class"], "ELF64")
        self.assertEqual(parser.header["machine"], "x86_64")
        self.assertGreater(len(parser.sections), 0)

    def test_section_names(self):
        data = build_sample_elf(b"test")
        parser = ELFParser(data)
        names = [s["name"] for s in parser.sections]
        self.assertIn(".text", names)
        self.assertIn(".rodata", names)

    def test_invalid_magic(self):
        with self.assertRaises(ValueError):
            ELFParser(b"\x00\x00\x00\x00" + b"\x00" * 60)

    def test_entry_point(self):
        data = build_sample_elf(b"test")
        parser = ELFParser(data)
        self.assertEqual(parser.header["entry"], 0x400000)


class TestPEParser(unittest.TestCase):
    def _build_pe(self):
        pe_data = bytearray(1024)
        pe_data[0:2] = PE_MAGIC
        pe_off = 64
        struct.pack_into("<I", pe_data, 0x3c, pe_off)  # e_lfanew
        pe_data[pe_off:pe_off + 4] = PE_SIG             # PE signature
        struct.pack_into("<H", pe_data, pe_off + 4, 0x8664)   # Machine
        struct.pack_into("<H", pe_data, pe_off + 6, 1)        # NumberOfSections
        struct.pack_into("<H", pe_data, pe_off + 20, 240)     # SizeOfOptionalHeader
        # Optional header at pe_off + 24
        opt_off = pe_off + 24
        struct.pack_into("<H", pe_data, opt_off, 0x20b)       # Magic PE64
        struct.pack_into("<I", pe_data, opt_off + 16, 0x1000) # AddressOfEntryPoint
        struct.pack_into("<Q", pe_data, opt_off + 24, 0x140000000)  # ImageBase
        # Section headers at opt_off + 240
        sec_off = opt_off + 240
        pe_data[sec_off:sec_off + 8] = b".text\x00\x00\x00"
        struct.pack_into("<I", pe_data, sec_off + 16, 0x200)  # SizeOfRawData
        struct.pack_into("<I", pe_data, sec_off + 20, 0x200)  # PointerToRawData
        return bytes(pe_data)

    def test_valid_pe(self):
        data = self._build_pe()
        parser = PEParser(data)
        self.assertEqual(parser.header["class"], "PE64")
        self.assertEqual(parser.header["machine"], "x86_64")

    def test_invalid_magic(self):
        with self.assertRaises(ValueError):
            PEParser(b"\x00\x00" + b"\x00" * 62)


class TestExtractStrings(unittest.TestCase):
    def test_basic(self):
        data = b"hello world\x00AAAA\x00"
        strings = extract_strings(data, min_len=4)
        self.assertTrue(any(s == "hello world" for _, s in strings))

    def test_min_len(self):
        data = b"ab\x00abcdefgh\x00"
        strings = extract_strings(data, min_len=8)
        self.assertTrue(any(s == "abcdefgh" for _, s in strings))

    def test_empty(self):
        self.assertEqual(extract_strings(b"\x00\x00\x00"), [])


class TestPackerScore(unittest.TestCase):
    def test_not_packed(self):
        data = build_sample_elf(b"test")
        parser = ELFParser(data)
        score = score_packer(parser.sections, data)
        self.assertLess(score, 0.5)

    def test_packer_marker(self):
        sections = [{"name": "UPX0", "offset": 0, "size": 0}]
        score = score_packer(sections, b"")
        self.assertGreater(score, 0.5)


class TestBuildSampleELF(unittest.TestCase):
    def test_elf_magic(self):
        data = build_sample_elf(b"test")
        self.assertEqual(data[:4], ELFMAG)

    def test_different_sizes(self):
        a = build_sample_elf(b"a", text_size=256)
        b = build_sample_elf(b"b", text_size=1024)
        self.assertGreater(len(b), len(a))


class TestAnalyzeELF(unittest.TestCase):
    def test_runs(self):
        data = build_sample_elf(b"test")
        parser = analyze_elf(data)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.header["class"], "ELF64")


class TestPatchDiff(unittest.TestCase):
    def test_identical(self):
        data = build_sample_elf(b"test")
        run_patch_diff(data, data, "A", "B")

    def test_different(self):
        a = build_sample_elf(b"a")
        b = bytearray(build_sample_elf(b"b"))
        b[100] = 0xFF
        run_patch_diff(a, bytes(b), "A", "B")


class TestCLI(unittest.TestCase):
    def test_help(self):
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "..", "firmware", "binrecon.py"), "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Binary Recon Tool", result.stdout)


class TestCompiledBinaryAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary_path = None
        cls.sample_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
        src = os.path.join(cls.sample_dir, "vuln.c")
        if os.path.exists(src):
            out = os.path.join(cls.sample_dir, "vuln_test")
            try:
                subprocess.run(
                    ["gcc", "-o", out, "-fno-stack-protector", "-no-pie", src],
                    capture_output=True, timeout=10
                )
                if os.path.exists(out):
                    cls.binary_path = out
            except Exception:
                pass

    def test_analyze_real_elf(self):
        if self.binary_path is None:
            self.skipTest("gcc not available or compilation failed")
        data = open(self.binary_path, "rb").read()
        self.assertEqual(data[:4], ELFMAG)
        parser = ELFParser(data)
        self.assertEqual(parser.header["class"], "ELF64")
        self.assertGreater(len(parser.sections), 0)
        names = [s["name"] for s in parser.sections]
        self.assertIn(".text", names)

    def test_strings_real_elf(self):
        if self.binary_path is None:
            self.skipTest("gcc not available")
        data = open(self.binary_path, "rb").read()
        strings = extract_strings(data, min_len=4)
        self.assertGreater(len(strings), 0)

    def test_entropy_real_elf(self):
        if self.binary_path is None:
            self.skipTest("gcc not available")
        data = open(self.binary_path, "rb").read()
        ent = shannon_entropy(data)
        self.assertGreater(ent, 0.0)
        self.assertLessEqual(ent, 8.0)

    def test_compiled_vuln_function(self):
        if self.binary_path is None:
            self.skipTest("gcc not available")
        data = open(self.binary_path, "rb").read()
        self.assertIn(b"win_function", data)


class TestSymbolsAndImports(unittest.TestCase):
    """Parse real symbols / dynamic imports from the gcc-compiled ELF."""

    @classmethod
    def setUpClass(cls):
        cls.sample_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
        src = os.path.join(cls.sample_dir, "vuln.c")
        out = os.path.join(os.path.dirname(__file__), "..", "builds", "vuln_target")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        cls.parser = None
        if os.path.exists(src):
            try:
                subprocess.run(
                    ["gcc", "-o", out, "-fno-stack-protector", "-no-pie", "-O0", src],
                    capture_output=True, timeout=10,
                )
                if os.path.exists(out):
                    with open(out, "rb") as f:
                        cls.parser = ELFParser(f.read())
            except Exception:
                pass

    def test_function_symbols(self):
        if self.parser is None:
            self.skipTest("gcc not available")
        names = [s["name"] for s in self.parser.symbols]
        self.assertIn("win_function", names)
        self.assertIn("vulnerable", names)
        self.assertIn("main", names)

    def test_dynamic_imports(self):
        if self.parser is None:
            self.skipTest("gcc not available")
        self.assertIn("strcpy", self.parser.imports)
        self.assertIn("printf", self.parser.imports)

    def test_needed_libs(self):
        if self.parser is None:
            self.skipTest("gcc not available")
        self.assertIn("libc.so.6", self.parser.needed_libs)

    def test_symbol_value_is_address(self):
        if self.parser is None:
            self.skipTest("gcc not available")
        win = next(s for s in self.parser.symbols if s["name"] == "win_function")
        self.assertGreater(win["value"], 0x400000)
        self.assertLess(win["value"], 0x500000)


class TestBuildRecon(unittest.TestCase):
    def test_recon_record_keys(self):
        data = build_sample_elf(b"t")
        parser = ELFParser(data)
        rec = build_recon(parser, data, source="sample")
        for key in ("format", "sections", "symbols", "imports",
                    "needed_libs", "entropy", "strings", "packer_score"):
            self.assertIn(key, rec)
        self.assertEqual(rec["format"], "elf")

    def test_recon_pe_record(self):
        pe = bytearray(1024)
        pe[0:2] = PE_MAGIC
        pe_off = 64
        struct.pack_into("<I", pe, 0x3c, pe_off)
        pe[pe_off:pe_off + 4] = PE_SIG
        struct.pack_into("<H", pe, pe_off + 4, 0x8664)
        struct.pack_into("<H", pe, pe_off + 6, 1)
        struct.pack_into("<H", pe, pe_off + 20, 240)
        opt_off = pe_off + 24
        struct.pack_into("<H", pe, opt_off, 0x20b)
        sec_off = opt_off + 240
        pe[sec_off:sec_off + 8] = b".text\x00\x00\x00"
        struct.pack_into("<I", pe, sec_off + 16, 0x100)
        struct.pack_into("<I", pe, sec_off + 20, 0x100)
        parser = PEParser(bytes(pe))
        rec = build_recon(parser, bytes(pe), source="pe.bin")
        self.assertEqual(rec["format"], "pe")

    def test_write_recon_json(self):
        data = build_sample_elf(b"t")
        parser = ELFParser(data)
        rec = build_recon(parser, data, source="sample")
        out_dir = tempfile.mkdtemp()
        out = write_recon(rec, os.path.join(out_dir, "recon_test.json"))
        with open(out) as f:
            loaded = json.load(f)
        self.assertEqual(loaded["format"], "elf")
        self.assertGreater(len(loaded["sections"]), 0)

    def test_sanitize(self):
        self.assertEqual(sanitize("/a/b/x#.bin"), "x_.bin")


class TestBuildSampleBinary(unittest.TestCase):
    def test_compiles_when_gcc_available(self):
        data, source = build_sample_binary(tempfile.mkdtemp())
        self.assertEqual(data[:4], ELFMAG)
        self.assertGreater(len(data), 100)

    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "..", "firmware", "binrecon.py"), "demo", "--no-gcc"],
            capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("Demo complete", r.stdout)


if __name__ == "__main__":
    unittest.main()
