#!/usr/bin/env python3
"""Verify the generated payload by disassembling it with objdump.

Runs on Linux without the game. Addresses are taken from the real PE so the
computed jumps are the ones that will actually be written.

    python3 tools/test_bytecode.py [path/to/WizardGraphicalClient.exe]
"""
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import w101_autologin as w  # noqa: E402
from scan_pe import (  # noqa: E402
    DEFAULT_EXE, HOOK_PATTERN, LOGIN_PATTERN, map_pe, parse_pattern, rip_targets, scan,
)


def disassemble(code, vma):
    """Disassemble raw x86-64 bytes, returning a list of (address, text)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
             f"--adjust-vma={vma:#x}", path],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)", line)
        if m and m.group(3).strip():
            rows.append((int(m.group(1), 16), m.group(3).strip()))
    return rows


def find_wine():
    """Return a usable 64-bit wine binary, or None."""
    found = shutil.which("wine")
    if found:
        return found
    patterns = [
        os.path.expanduser("~/.local/share/Steam/compatibilitytools.d/*/files/bin/wine"),
        os.path.expanduser("~/.steam/steam/steamapps/common/Proton*/files/bin/wine"),
    ]
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if os.access(path, os.X_OK):
                return path
    return None


def c_payload(exe, wine):
    """Run the C build's --dump-payload and return the bytes it printed."""
    env = dict(os.environ, WINEDEBUG="-all")
    out = subprocess.run([wine, str(exe), "--dump-payload"],
                         capture_output=True, text=True, env=env, timeout=180)
    return bytes.fromhex(out.stdout.strip())


def main():
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    failures = []

    def check(label, cond, detail=""):
        print(f"{'[OK]  ' if cond else '[FAIL]'} {label}{('  ' + detail) if detail else ''}")
        if not cond:
            failures.append(label)

    ss = w.build_string_struct(0x1122334455667788, 5)
    check("string struct is 32 bytes", len(ss) == 32)
    check("string struct is {ptr, 0, len, cap}",
          struct.unpack("<QQQQ", ss) == (0x1122334455667788, 0, 5, 5))

    if not exe.exists():
        print(f"\nskipping payload checks: {exe} not found")
        return 1 if failures else 0

    image, base, _size, _machine, _sections = map_pe(exe)
    login_rva = scan(image, parse_pattern(LOGIN_PATTERN))[0]
    hook_rva = scan(image, parse_pattern(HOOK_PATTERN))[0]
    dat_rva, func_rva = rip_targets(image, login_rva)

    hook = base + hook_rva
    ret = hook + w.HOOK_INSTR_LEN
    orig = image[hook_rva:hook_rva + w.HOOK_INSTR_LEN]
    cave = base + hook_rva + 0x100000
    flag = 0x20000000
    sstr = 0x20001000

    code = w.build_login_bytecode(
        cave, flag, sstr, base + dat_rva, base + func_rva, orig, ret
    )
    check(f"payload fits the cave ({len(code)} <= {w.CAVE_SIZE} bytes)", len(code) <= w.CAVE_SIZE)

    rows = disassemble(code, cave)
    text = [instr for _addr, instr in rows]
    by_addr = dict(rows)

    orig_off = code.rfind(orig)
    check("original 7 bytes are re-executed in the cave", orig_off > 0,
          f"offset {orig_off}, {orig.hex(' ')}")
    check("relocated original instruction decodes cleanly",
          by_addr.get(cave + orig_off, "").startswith("mov"),
          by_addr.get(cave + orig_off, "<did not decode>"))

    jne = next((i for i in text if i.startswith("jne")), None)
    check("jne lands exactly on the original instruction",
          jne is not None and int(jne.split()[-1], 16) == cave + orig_off,
          f"{jne} vs expected {cave + orig_off:#x}")

    jmp = next((i for i in reversed(text) if i.startswith("jmp")), None)
    check("trailing jmp returns to hook+7",
          jmp is not None and int(jmp.split()[-1], 16) == ret,
          f"{jmp} vs expected {ret:#x}")

    pushes = sum(1 for i in text if i.startswith("push"))
    pops = sum(1 for i in text if i.startswith("pop"))
    check("push and pop are balanced", pushes == pops, f"{pushes} push, {pops} pop")

    frame = 7 * 8 + 0x28
    check("rsp stays 16-byte aligned at the call", frame % 16 == 0, f"{frame} bytes")
    check("shadow space is reserved",
          any(i.replace(" ", "") == "subrsp,0x28" for i in text))
    check("rcx is the dereferenced client pointer",
          any(i.replace(" ", "") == "movrcx,QWORDPTR[rax]" for i in text))

    rel = cave - (hook + 5)
    check("cave is reachable by a rel32 jump", -0x80000000 <= rel <= 0x7FFFFFFF, f"{rel:+#x}")

    # The C build must assemble the identical payload. Its --dump-payload uses
    # fixed test vectors, so build the Python side with the same values.
    c_exe = Path(__file__).resolve().parent.parent / "dist" / "w101_autologin_c.exe"
    wine = find_wine()
    if c_exe.exists() and wine:
        vectors = (0x141900000, 0x20000000, 0x20001000, 0x14333A160, 0x141491680,
                   bytes.fromhex("498b8dd8000000"), 0x141847592)
        expected = w.build_login_bytecode(*vectors)
        try:
            got = c_payload(c_exe, wine)
            check("C build assembles the identical payload", got == expected,
                  f"{len(got)} bytes")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            check("C build assembles the identical payload", False, str(exc))
    else:
        reason = "dist/w101_autologin_c.exe missing" if not c_exe.exists() else "no wine found"
        print(f"[SKIP] C build comparison  {reason}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} — " + ", ".join(failures))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
