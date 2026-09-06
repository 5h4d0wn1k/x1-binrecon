#!/usr/bin/env python3
"""X1 - Binary Recon Tool (binrecon)

Static binary triage: ELF/PE header parsing, entropy, packer heuristics,
string extraction, and patch-diff mode. Pure stdlib (struct only).
"""

import struct
import math
import sys
import os
import argparse

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------
ELFMAG = b"\x7fELF"
EI_NIDENT = 16
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

ET_TYPES = {
    0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE",
}
EM_MACHINES = {
    0: "NONE", 1: "M32", 2: "SPARC", 3: "386", 4: "68K", 5: "88K",
    7: "860", 8: "MIPS", 10: "MIPS_X", 11: "PARISC", 15: "PA-RISC",
    17: "SPARC64", 18: "SPARCV9", 20: "PPC", 21: "PPC64",
    22: "S390", 36: "ARM", 40: "860", 50: "IA64", 53: "MIPS_X",
    62: "x86_64", 183: "AARCH64", 243: "RISCV",
}
SHT_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    11: "DYNSYM",
}
SHT_FLAGS = {0x1: "W", 0x2: "A", 0x4: "X", 0x10: "M", 0x20: "I", 0x40: "S"}

# ---------------------------------------------------------------------------
# PE constants
# ---------------------------------------------------------------------------
PE_MAGIC = b"MZ"
PE_SIG = b"PE\x00\x00"
MACHINE_TYPES = {
    0x0: "UNKNOWN", 0x14c: "i386", 0x8664: "x86_64",
    0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA64",
}
PE_SEC_CHARS = [
    (0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"), (0x02000000, "LNK_INFO"),
    (0x10000000, "LNK_NRELOC_OVFL"), (0x20000000, "LNK_DISCARDABLE"),
    (0x40000000, "LNK_NOCACHE"), (0x80000000, "LNK_NOPAGE"),
]


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------
def shannon_entropy(data):
    """Compute Shannon entropy of byte data (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def entropy_bar(ent, width=16):
    """Return a visual bar for entropy."""
    filled = int(ent / 8.0 * width)
    return "█" * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# ELF Parsers
# ---------------------------------------------------------------------------
class ELFParser:
    """Minimal ELF32/64 parser using struct."""

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.header = {}
        self._parse()

    def _parse(self):
        if len(self.data) < EI_NIDENT or self.data[:4] != ELFMAG:
            raise ValueError("Not a valid ELF file")
        self.cls = self.data[4]
        endian = self.data[5]
        self.endian = "<" if endian == ELFDATA2LSB else ">"
        if self.cls == ELFCLASS64:
            self._parse64()
        elif self.cls == ELFCLASS32:
            self._parse32()
        else:
            raise ValueError(f"Unknown ELF class: {self.cls}")

    def _parse32(self):
        e = self.endian
        hdr = struct.unpack_from(e + "HHIIIIIHHHHHH", self.data, 16)
        self.header = {
            "class": "ELF32", "type": ET_TYPES.get(hdr[0], f"0x{hdr[0]:x}"),
            "machine": EM_MACHINES.get(hdr[1], f"0x{hdr[1]:x}"),
            "entry": hdr[2], "phoff": hdr[3], "shoff": hdr[4],
            "ehsize": hdr[5], "phentsize": hdr[6], "phnum": hdr[7],
            "shentsize": hdr[10], "shnum": hdr[11], "shstrndx": hdr[12],
        }
        self._parse_sections32(hdr[10], hdr[11], hdr[12], hdr[4])

    def _parse64(self):
        e = self.endian
        hdr = struct.unpack_from(e + "HHIQQQIHHHHHH", self.data, 16)
        self.header = {
            "class": "ELF64", "type": ET_TYPES.get(hdr[0], f"0x{hdr[0]:x}"),
            "machine": EM_MACHINES.get(hdr[1], f"0x{hdr[1]:x}"),
            "entry": hdr[3], "phoff": hdr[4], "shoff": hdr[5],
            "ehsize": hdr[6], "phentsize": hdr[7], "phnum": hdr[8],
            "shentsize": hdr[10], "shnum": hdr[11], "shstrndx": hdr[12],
        }
        self._parse_sections64(hdr[10], hdr[11], hdr[12], hdr[5])

    def _parse_sections32(self, shentsize, shnum, shstrndx, shoff):
        if shnum == 0 or shoff == 0:
            return
        strtab_hdr_off = shoff + shstrndx * shentsize
        if strtab_hdr_off + 24 > len(self.data):
            return
        # ELF32 section header: sh_offset at +16, sh_size at +20
        strtab_start = struct.unpack_from(self.endian + "I", self.data, strtab_hdr_off + 16)[0]
        strtab_size = struct.unpack_from(self.endian + "I", self.data, strtab_hdr_off + 20)[0]
        if strtab_size == 0 or strtab_start + strtab_size > len(self.data):
            return
        strtab = self.data[strtab_start:strtab_start + strtab_size]
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + shentsize > len(self.data):
                break
            s = struct.unpack_from(self.endian + "IIIIIIII", self.data, off)
            name_idx = s[0]
            name = ""
            if name_idx < len(strtab):
                end = strtab.index(b'\x00', name_idx) if b'\x00' in strtab[name_idx:] else len(strtab)
                name = strtab[name_idx:end].decode("ascii", errors="replace")
            self.sections.append({
                "name": name, "type": SHT_TYPES.get(s[1], f"0x{s[1]:x}"),
                "flags": s[2], "addr": s[3], "offset": s[4],
                "size": s[5], "ent_size": s[7],
            })

    def _parse_sections64(self, shentsize, shnum, shstrndx, shoff):
        if shnum == 0 or shoff == 0:
            return
        strtab_hdr_off = shoff + shstrndx * shentsize
        if strtab_hdr_off + 64 > len(self.data):
            return
        # ELF64 section header: sh_offset at byte 24, sh_size at byte 32
        strtab_file_off = struct.unpack_from(self.endian + "Q", self.data, strtab_hdr_off + 24)[0]
        strtab_size = struct.unpack_from(self.endian + "Q", self.data, strtab_hdr_off + 32)[0]
        if strtab_size == 0 or strtab_file_off == 0 or strtab_file_off + strtab_size > len(self.data):
            return
        strtab = self.data[strtab_file_off:strtab_file_off + strtab_size]
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + 64 > len(self.data):
                break
            s = struct.unpack_from(self.endian + "IIQQQQIIQQ", self.data, off)
            name_idx = s[0]
            name = ""
            if name_idx < len(strtab):
                end = strtab.index(b'\x00', name_idx) if b'\x00' in strtab[name_idx:] else len(strtab)
                name = strtab[name_idx:end].decode("ascii", errors="replace")
            flags = s[3]
            self.sections.append({
                "name": name, "type": SHT_TYPES.get(s[1], f"0x{s[1]:x}"),
                "flags": s[2], "addr": s[3], "offset": s[4],
                "size": s[5], "ent_size": s[8],
            })


# ---------------------------------------------------------------------------
# PE Parsers
# ---------------------------------------------------------------------------
class PEParser:
    """Minimal PE parser using struct."""

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.header = {}
        self.imports = []
        self._parse()

    def _parse(self):
        if len(self.data) < 64 or self.data[:2] != PE_MAGIC:
            raise ValueError("Not a valid PE file")
        pe_off = struct.unpack_from("<I", self.data, 0x3c)[0]
        if self.data[pe_off:pe_off + 4] != PE_SIG:
            raise ValueError("Invalid PE signature")
        self.pe_off = pe_off
        machine = struct.unpack_from("<H", self.data, pe_off + 4)[0]
        num_sections = struct.unpack_from("<H", self.data, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", self.data, pe_off + 20)[0]
        characteristics = struct.unpack_from("<H", self.data, pe_off + 22)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", self.data, opt_off)[0]
        is64 = magic == 0x20b
        if is64:
            entry = struct.unpack_from("<I", self.data, opt_off + 16)[0]
            image_base = struct.unpack_from("<Q", self.data, opt_off + 24)[0]
        else:
            entry = struct.unpack_from("<I", self.data, opt_off + 16)[0]
            image_base = struct.unpack_from("<I", self.data, opt_off + 28)[0]
        self.header = {
            "class": "PE64" if is64 else "PE32",
            "machine": MACHINE_TYPES.get(machine, f"0x{machine:x}"),
            "num_sections": num_sections, "entry": entry,
            "image_base": image_base, "characteristics": characteristics,
        }
        sec_off = opt_off + opt_hdr_size
        for i in range(num_sections):
            off = sec_off + i * 40
            if off + 40 > len(self.data):
                break
            name_raw = self.data[off:off + 8]
            name = name_raw.split(b'\x00')[0].decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", self.data, off + 8)[0]
            vaddr = struct.unpack_from("<I", self.data, off + 12)[0]
            raw_size = struct.unpack_from("<I", self.data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", self.data, off + 20)[0]
            chars = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append({
                "name": name, "vaddr": vaddr, "vsize": vsize,
                "raw_ptr": raw_ptr, "raw_size": raw_size,
                "characteristics": chars,
            })

    def get_section_data(self, sec):
        ptr = sec["raw_ptr"]
        size = sec["raw_size"]
        if ptr + size <= len(self.data):
            return self.data[ptr:ptr + size]
        return b""


# ---------------------------------------------------------------------------
# Packer heuristics
# ---------------------------------------------------------------------------
KNOWN_PACKERS = [
    ("UPX", [b"UPX0", b"UPX1", b"UPX!"]),
    ("ASPack", [b".aspack", b".adata"]),
    ("Themida", [b".Themida", b".winlice"]),
    ("VMProtect", [b".vmp0", b".vmp1"]),
    ("PECompact", [b"PEC2", b"PEC2to"]),
    ("Armadillo", [b".armadillo"]),
    ("NsPack", [b".nsp0", b".nsp1"]),
    ("MEW", [b"MEW"]),
]


def score_packer(sections, data):
    """Score likelihood of packing (0.0 = not packed, 1.0 = definitely packed)."""
    score = 0.0
    names = [s["name"].lower() for s in sections]
    for pname, sigs in KNOWN_PACKERS:
        for sig in sigs:
            if any(sig.lower() in n.encode() for n in names):
                score = max(score, 0.9)
            elif sig in data:
                score = max(score, 0.7)
    high_entropy = sum(1 for s in sections if shannon_entropy(
        data[s.get("offset", 0):s.get("offset", 0) + min(s.get("size", 0), 4096)]
    ) > 7.0 and s.get("size", 0) > 256)
    if high_entropy >= 2:
        score = max(score, 0.5)
    if len(sections) <= 3 and high_entropy >= 1:
        score = max(score, 0.6)
    return min(score, 1.0)


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------
def extract_strings(data, min_len=4):
    """Extract printable ASCII strings from binary data."""
    results = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        results.append((start, "".join(current)))
    return results


# ---------------------------------------------------------------------------
# Build sample ELF-like byte buffers for demo
# ---------------------------------------------------------------------------
def build_sample_elf(name_bytes, text_size=512, rodata_size=256, data_size=128):
    """Build a minimal ELF64-like byte buffer for demonstration."""
    text = bytes(range(256)) * (text_size // 256 + 1)
    text = text[:text_size]
    rodata = b"\x00" * rodata_size
    rodata = b"/usr/lib/x86_64-linux-gnu/libc.so.6" + b"\x00" * (rodata_size - 36)
    data_section = b"\x41" * data_size

    section_names = [b".shstrtab\x00", b".text\x00", b".rodata\x00", b".data\x00", b".bss\x00"]
    shstrtab = b"".join(section_names)

    shoff = 64
    shentsize = 64
    shnum = 5
    shstrndx = 0

    header = bytearray(64)
    header[0:4] = ELFMAG
    header[4] = ELFCLASS64
    header[5] = ELFDATA2LSB
    header[6] = 1  # EV_CURRENT
    header[7] = 0  # ELFOSABI_NONE
    struct.pack_into("<H", header, 16, 2)     # ET_EXEC
    struct.pack_into("<H", header, 18, 0x3e)  # EM_X86_64
    struct.pack_into("<I", header, 20, 1)     # EV_CURRENT
    struct.pack_into("<Q", header, 24, 0x400000)  # entry
    struct.pack_into("<Q", header, 32, 64)    # phoff
    struct.pack_into("<Q", header, 40, shoff) # shoff
    struct.pack_into("<I", header, 52, 64)    # ehsize
    struct.pack_into("<I", header, 54, 56)    # phentsize
    struct.pack_into("<H", header, 56, 0)     # phnum=0
    struct.pack_into("<H", header, 58, shentsize)
    struct.pack_into("<H", header, 60, shnum)
    struct.pack_into("<H", header, 62, shstrndx)

    sections_layout = [
        (".shstrtab", 1, 0, 0, len(shstrtab)),
        (".text", 1, 1 | 4, 0x400000, text_size),
        (".rodata", 1, 2, 0x401000, rodata_size),
        (".data", 1, 3, 0x402000, data_size),
        (".bss", 8, 3, 0x403000, 256),
    ]

    sec_headers = bytearray(shnum * shentsize)
    data_offset = shoff + shnum * shentsize
    sec_data_parts = [shstrtab]
    file_offsets = []

    current_offset = data_offset
    for i, (name, typ, flags, addr, size) in enumerate(sections_layout):
        off = i * shentsize
        name_idx = shstrtab.index(name.encode() + b"\x00")
        struct.pack_into("<I", sec_headers, off + 0, name_idx)
        struct.pack_into("<I", sec_headers, off + 4, typ)
        struct.pack_into("<Q", sec_headers, off + 8, flags)
        struct.pack_into("<Q", sec_headers, off + 16, addr)
        if name == ".bss":
            struct.pack_into("<Q", sec_headers, off + 24, 0)
            struct.pack_into("<Q", sec_headers, off + 32, 0)
            file_offsets.append(0)
        else:
            struct.pack_into("<Q", sec_headers, off + 24, current_offset)
            struct.pack_into("<Q", sec_headers, off + 32, size)
            file_offsets.append(current_offset)
            if name == ".text":
                sec_data_parts.append(text)
            elif name == ".rodata":
                sec_data_parts.append(rodata)
            elif name == ".data":
                sec_data_parts.append(data_section)
            current_offset += size
        struct.pack_into("<Q", sec_headers, off + 40, size)

    result = bytes(header) + bytes(sec_headers) + b"".join(sec_data_parts)
    return result


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------
def analyze_elf(data):
    """Analyze an ELF binary."""
    parser = ELFParser(data)
    h = parser.header
    print(f"\n[ELF Header]")
    print(f"  Class:    {h['class']}")
    print(f"  Type:     {h['type']}")
    print(f"  Machine:  {h['machine']}")
    print(f"  Entry:    0x{h['entry']:x}")
    print(f"  Sections: {h['shnum']}")
    print(f"\n[Sections]")
    print(f"  {'Name':<16} {'Type':<14} {'Addr':<18} {'Size':<10} {'Flags'}")
    print(f"  {'-'*70}")
    for s in parser.sections:
        flags = ""
        for bit, char in SHT_FLAGS.items():
            if s["flags"] & bit:
                flags += char
        print(f"  {s['name']:<16} {s['type']:<14} 0x{s['addr']:012x}  {s['size']:<10} {flags}")
    print(f"\n[Section Entropy]")
    for s in parser.sections:
        if s["size"] > 0 and s["offset"] > 0:
            chunk = data[s["offset"]:s["offset"] + min(s["size"], 4096)]
            ent = shannon_entropy(chunk)
            print(f"  {s['name']:<16}: {ent:.2f} {entropy_bar(ent)}")
    packer_score = score_packer(parser.sections, data)
    print(f"\n[Packer Score]")
    label = "Definitely packed" if packer_score > 0.7 else "Possibly packed" if packer_score > 0.3 else "Not packed"
    print(f"  Score: {packer_score:.2f} — {label}")
    return parser


def analyze_pe(data):
    """Analyze a PE binary."""
    parser = PEParser(data)
    h = parser.header
    print(f"\n[PE Header]")
    print(f"  Class:       {h['class']}")
    print(f"  Machine:     {h['machine']}")
    print(f"  Sections:    {h['num_sections']}")
    print(f"  Entry:       0x{h['entry']:x}")
    print(f"  Image Base:  0x{h['image_base']:x}")
    print(f"\n[Sections]")
    print(f"  {'Name':<10} {'VAddr':<12} {'VSize':<10} {'RawPtr':<10} {'RawSize':<10} {'Chars'}")
    print(f"  {'-'*60}")
    for s in parser.sections:
        char_strs = []
        for bit, name in PE_SEC_CHARS:
            if s["characteristics"] & bit:
                char_strs.append(name)
        print(f"  {s['name']:<10} 0x{s['vaddr']:08x}  0x{s['vsize']:06x}  "
              f"0x{s['raw_ptr']:06x}  0x{s['raw_size']:06x}  {','.join(char_strs[:3])}")
    print(f"\n[Section Entropy]")
    for s in parser.sections:
        sd = parser.get_section_data(s)
        if sd:
            ent = shannon_entropy(sd)
            print(f"  {s['name']:<10}: {ent:.2f} {entropy_bar(ent)}")
    packer_score = score_packer(parser.sections, data)
    print(f"\n[Packer Score]")
    label = "Definitely packed" if packer_score > 0.7 else "Possibly packed" if packer_score > 0.3 else "Not packed"
    print(f"  Score: {packer_score:.2f} — {label}")
    return parser


def run_string_extraction(data, min_len=4):
    """Extract and display strings."""
    strings = extract_strings(data, min_len)
    print(f"\n[Strings found: {len(strings)}]")
    for offset, s in strings[:20]:
        print(f"  @0x{offset:04x}: \"{s}\"")
    if len(strings) > 20:
        print(f"  ... and {len(strings) - 20} more")


def run_patch_diff(data_a, data_b, label_a="A", label_b="B"):
    """Compare two binaries section-by-section."""
    print(f"\n[Patch Diff]")
    print(f"  File {label_a}: {len(data_a)} bytes")
    print(f"  File {label_b}: {len(data_b)} bytes")
    ent_a = shannon_entropy(data_a)
    ent_b = shannon_entropy(data_b)
    print(f"  Overall entropy: {label_a}={ent_a:.2f}  {label_b}={ent_b:.2f}")
    min_len = min(len(data_a), len(data_b))
    diffs = sum(1 for i in range(min_len) if data_a[i] != data_b[i])
    diffs += abs(len(data_a) - len(data_b))
    total = max(len(data_a), len(data_b))
    pct = diffs / total * 100 if total else 0
    print(f"  Bytes differing: {diffs} / {total} ({pct:.2f}%)")
    chunk_size = max(1, total // 8)
    print(f"\n  Entropy comparison by region:")
    for i in range(0, total, chunk_size):
        chunk_a = data_a[i:i + chunk_size]
        chunk_b = data_b[i:i + chunk_size]
        e_a = shannon_entropy(chunk_a)
        e_b = shannon_entropy(chunk_b)
        delta = abs(e_a - e_b)
        marker = " <<<" if delta > 0.5 else ""
        print(f"    0x{i:06x}: A={e_a:.2f} B={e_b:.2f} (delta={delta:.2f}){marker}")


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) > 1 and sys.argv[1] != "--demo":
        parser = argparse.ArgumentParser(description="X1 - Binary Recon Tool")
        sub = parser.add_subparsers(dest="command")

        p_analyze = sub.add_parser("analyze", help="Analyze a binary file")
        p_analyze.add_argument("file", help="Path to binary file")

        p_strings = sub.add_parser("strings", help="Extract strings")
        p_strings.add_argument("file", help="Path to binary file")
        p_strings.add_argument("--minlen", type=int, default=4, help="Minimum string length")

        p_diff = sub.add_parser("diff", help="Diff two binaries")
        p_diff.add_argument("file_a", help="First binary")
        p_diff.add_argument("file_b", help="Second binary")

        args = parser.parse_args()

        if args.command == "analyze":
            data = open(args.file, "rb").read()
            if data[:4] == ELFMAG:
                analyze_elf(data)
            elif data[:2] == PE_MAGIC:
                analyze_pe(data)
            else:
                print("Unknown format")
        elif args.command == "strings":
            data = open(args.file, "rb").read()
            run_string_extraction(data, args.minlen)
        elif args.command == "diff":
            a = open(args.file_a, "rb").read()
            b = open(args.file_b, "rb").read()
            run_patch_diff(a, b, os.path.basename(args.file_a), os.path.basename(args.file_b))
    else:
        run_demo()


def run_demo():
    print("=== X1 - Binary Recon Tool (binrecon) ===")

    # Build two sample ELF-like buffers
    elf_a = build_sample_elf(b"sample_a", text_size=1024, rodata_size=512, data_size=256)
    elf_b = build_sample_elf(b"sample_b", text_size=1024, rodata_size=512, data_size=256)

    # Modify elf_b slightly for diff demonstration
    elf_b_arr = bytearray(elf_b)
    for i in range(200, 248):
        if i < len(elf_b_arr):
            elf_b_arr[i] = 0xCC
    elf_b = bytes(elf_b_arr)

    print(f"\n--- Analysis of Sample ELF-A ({len(elf_a)} bytes) ---")
    analyze_elf(elf_a)
    run_string_extraction(elf_a, min_len=4)

    print(f"\n--- Analysis of Sample ELF-B ({len(elf_b)} bytes) ---")
    analyze_elf(elf_b)

    print(f"\n--- Patch Diff (A vs B) ---")
    run_patch_diff(elf_a, elf_b, "sample_a", "sample_b")

    # PE sample
    pe_data = bytearray(512)
    pe_data[0:2] = PE_MAGIC
    struct.pack_into("<I", pe_data, 0x3c, 64)
    pe_data[64:68] = PE_SIG
    struct.pack_into("<H", pe_data, 68, 0x8664)  # x86_64
    struct.pack_into("<H", pe_data, 70, 2)        # 2 sections
    struct.pack_into("<I", pe_data, 76, 0)        # timestamp
    struct.pack_into("<I", pe_data, 80, 0)        # sym table
    struct.pack_into("<I", pe_data, 84, 0)        # num syms
    struct.pack_into("<H", pe_data, 88, 240)      # opt hdr size
    struct.pack_into("<H", pe_data, 90, 0x0022)   # characteristics
    struct.pack_into("<H", pe_data, 88, 0)
    opt_off = 64 + 4
    struct.pack_into("<H", pe_data, opt_off, 0x20b)  # PE64
    struct.pack_into("<I", pe_data, opt_off + 16, 0x1000)  # entry
    struct.pack_into("<Q", pe_data, opt_off + 24, 0x140000000)  # image base
    sec_off = opt_off + 240
    text_name = b".text\x00\x00\x00"
    pe_data[sec_off:sec_off + 8] = text_name
    struct.pack_into("<I", pe_data, sec_off + 8, 0x1000)   # vsize
    struct.pack_into("<I", pe_data, sec_off + 12, 0x1000)  # vaddr
    struct.pack_into("<I", pe_data, sec_off + 16, 0x200)   # raw size
    struct.pack_into("<I", pe_data, sec_off + 20, 0x200)   # raw ptr
    struct.pack_into("<I", pe_data, sec_off + 36, 0x60000020)  # chars
    data_name = b".data\x00\x00\x00"
    sec2 = sec_off + 40
    pe_data[sec2:sec2 + 8] = data_name
    struct.pack_into("<I", pe_data, sec2 + 8, 0x1000)
    struct.pack_into("<I", pe_data, sec2 + 12, 0x2000)
    struct.pack_into("<I", pe_data, sec2 + 16, 0x100)
    struct.pack_into("<I", pe_data, sec2 + 20, 0x400)
    struct.pack_into("<I", pe_data, sec2 + 36, 0xC0000040)
    pe_data[0x200:0x300] = bytes(range(256)) * 1

    print(f"\n--- PE Analysis (synthetic, {len(pe_data)} bytes) ---")
    try:
        analyze_pe(bytes(pe_data))
    except Exception as e:
        print(f"  PE parse: {e}")

    print("\n=== Demo complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
