#!/usr/bin/env python3
"""Offline pattern verification against WizardGraphicalClient.exe on disk.

Maps the PE the way the loader would and searches for the patterns the
injector relies on. Read-only, stdlib, no running process needed.

    python3 tools/scan_pe.py [path/to/WizardGraphicalClient.exe]
"""
import struct
import sys
from pathlib import Path

LOGIN_PATTERN = "41 B1 01 45 33 C0 48 8D 55 CF 48 8B 0D"
HOOK_PATTERN = "?? ?? ?? ?? ?? ?? ?? 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84"
AUTOBOT_PATTERN = (
    "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? "
    "55 41 54 41 55 41 56 41 57 "
    "48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? "
    "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? "
    "4C 8B F1 ?? ?? ?? ?? ?? ?? ?? 80 ?? ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ??"
)
HOOK_INSTR_LEN = 7

DEFAULT_EXE = Path.home() / (
    "Games/Wizard101NA/prefix/drive_c/ProgramData/"
    "KingsIsle Entertainment/Wizard101/Bin/WizardGraphicalClient.exe"
)


def parse_pattern(text):
    """Parse a '41 B1 ?? ..' pattern string into a list of int or None wildcards."""
    return [None if tok in ("??", "?") else int(tok, 16) for tok in text.split()]


def scan(image, pattern, limit=16):
    """Return the offsets in `image` matching `pattern`, up to `limit` hits."""
    first = pattern[0]
    plen = len(pattern)
    hits = []
    start = 0
    end = len(image) - plen
    while start <= end:
        if first is None:
            idx = start
        else:
            idx = image.find(bytes([first]), start, end + 1)
            if idx < 0:
                break
        for off, want in enumerate(pattern):
            if want is not None and image[idx + off] != want:
                break
        else:
            hits.append(idx)
            if len(hits) >= limit:
                break
        start = idx + 1
    return hits


def map_pe(path):
    """Map a PE32+ image from disk into its in-memory layout.

    Returns (image_bytes, image_base, size_of_image, machine, sections), where
    sections is a list of (name, vaddr, vsize, rawptr, rawsize).
    """
    raw = path.read_bytes()
    if raw[:2] != b"MZ":
        raise SystemExit(f"{path}: not a PE (no MZ header)")
    pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe_off:pe_off + 4] != b"PE\0\0":
        raise SystemExit(f"{path}: PE header not found")

    coff = pe_off + 4
    machine, n_sections = struct.unpack_from("<HH", raw, coff)
    opt_size = struct.unpack_from("<H", raw, coff + 16)[0]
    opt = coff + 20
    if struct.unpack_from("<H", raw, opt)[0] != 0x20B:
        raise SystemExit(f"{path}: not PE32+, the injector is x64 only")

    size_of_image = struct.unpack_from("<I", raw, opt + 56)[0]
    image_base = struct.unpack_from("<Q", raw, opt + 24)[0]
    size_of_headers = struct.unpack_from("<I", raw, opt + 60)[0]

    image = bytearray(size_of_image)
    image[:size_of_headers] = raw[:size_of_headers]

    sec = opt + opt_size
    sections = []
    for i in range(n_sections):
        base = sec + i * 40
        name = raw[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, base + 8)
        sections.append((name, vaddr, vsize, rawptr, rawsize))
        if rawsize:
            chunk = raw[rawptr:rawptr + rawsize]
            image[vaddr:vaddr + len(chunk)] = chunk
    return bytes(image), image_base, size_of_image, machine, sections


def rip_targets(image, login_rva):
    """Return (dat_rva, func_rva) decoded from the RIP-relative displacements."""
    dat_disp = struct.unpack_from("<i", image, login_rva + 13)[0]
    func_disp = struct.unpack_from("<i", image, login_rva + 18)[0]
    return login_rva + 17 + dat_disp, login_rva + 22 + func_disp


def main():
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    if not exe.exists():
        raise SystemExit(f"Executable not found: {exe}")

    image, base, size, machine, sections = map_pe(exe)
    print(f"File        : {exe}")
    print(f"Machine     : {machine:#06x} ({'x64' if machine == 0x8664 else '??'})")
    print(f"ImageBase   : {base:#x}")
    print(f"SizeOfImage : {size:#x} ({size / 1024 / 1024:.1f} MiB)")
    print("Sections    : " + ", ".join(f"{n}@{v:#x}+{s:#x}" for n, v, s, _, _ in sections))
    print()

    ok = True
    pad = " " * 10 + " " * 16
    for label, text in (
        ("LOGIN_PATTERN", LOGIN_PATTERN),
        ("HOOK_PATTERN", HOOK_PATTERN),
        ("AUTOBOT_PATTERN", AUTOBOT_PATTERN),
    ):
        hits = scan(image, parse_pattern(text))
        if not hits:
            print(f"[FAIL]    {label:<16} no match")
            ok = False
            continue
        note = "" if len(hits) == 1 else f"  <-- {len(hits)} matches, first one is used"
        print(f"[OK]      {label:<16} RVA {hits[0]:#x} (default VA {base + hits[0]:#x}){note}")
        if len(hits) > 1:
            print(pad + "others: " + ", ".join(hex(h) for h in hits[1:]))

        if label == "LOGIN_PATTERN":
            dat, func = rip_targets(image, hits[0])
            print(pad + f"dat  RVA {dat:#x} (default VA {base + dat:#x})")
            print(pad + f"func RVA {func:#x} (default VA {base + func:#x})")
            for nm, va, vs, _, _ in sections:
                if va <= dat < va + vs:
                    print(pad + f"dat  lives in {nm}")
                if va <= func < va + vs:
                    print(pad + f"func lives in {nm}")
        if label == "HOOK_PATTERN":
            orig = image[hits[0]:hits[0] + HOOK_INSTR_LEN]
            print(pad + f"7 bytes to relocate: {orig.hex(' ')}")
            print(pad + f"context: {image[hits[0]:hits[0] + 24].hex(' ')}")

    print()
    print("VERDICT: clear to proceed" if ok else "VERDICT: patterns need rebuilding")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
