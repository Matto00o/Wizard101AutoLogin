#!/usr/bin/env python3
"""Wizard101 auto-login through memory injection.

Python port of libs/wizlaunch/src/login.rs (Deimos-Wizard101), stdlib only.
Licensed under the GNU General Public License v3.0, see LICENSE.

Must run inside the game's Wine prefix: it relies on ReadProcessMemory and
WriteProcessMemory.

    wine python w101_autologin.py --check
    wine python w101_autologin.py
"""

import argparse
import ctypes
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes

LOGIN_PATTERN = "41 B1 01 45 33 C0 48 8D 55 CF 48 8B 0D"
HOOK_PATTERN = "?? ?? ?? ?? ?? ?? ?? 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84"
HOOK_INSTR_LEN = 7

MODULE_NAME = "WizardGraphicalClient.exe"
WINDOW_CLASS = "Wizard Graphical Client"

CAVE_SIZE = 512

if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    WINFUNCTYPE = ctypes.WINFUNCTYPE
else:
    kernel32 = user32 = None
    WINFUNCTYPE = ctypes.CFUNCTYPE

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ACCESS = (
    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION
)
THREAD_SUSPEND_RESUME = 0x0002

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPTHREAD = 0x00000004

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_FREE = 0x10000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_UNREADABLE = 0x101

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_MODULE_NAME32 = 255
MAX_PATH = 260


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


def _bind():
    """Set argtypes/restype on every Win32 entry point used by this module.

    Required before any call: without it 64-bit pointer returns are truncated.
    """
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD,
    ]
    kernel32.VirtualFreeEx.restype = wintypes.BOOL
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
    kernel32.SuspendThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD

    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL


class InjectionError(RuntimeError):
    pass


def _win_error(what):
    """Build an InjectionError carrying the calling thread's last Win32 error."""
    err = ctypes.get_last_error()
    return InjectionError(f"{what}: Win32 error {err} ({ctypes.FormatError(err)})")


def parse_pattern(text):
    """Parse a '41 B1 ?? ..' pattern string into a list of int or None wildcards."""
    return [None if tok in ("??", "?") else int(tok, 16) for tok in text.split()]


def scan(data, pattern, limit=8):
    """Return the offsets in `data` matching `pattern`, up to `limit` hits.

    Args:
        data: buffer to search.
        pattern: list of int or None, as returned by parse_pattern.
        limit: stop after this many matches.
    """
    first = pattern[0]
    plen = len(pattern)
    hits = []
    start = 0
    end = len(data) - plen
    while start <= end:
        if first is None:
            idx = start
        else:
            idx = data.find(bytes([first]), start, end + 1)
            if idx < 0:
                break
        for off, want in enumerate(pattern):
            if want is not None and data[idx + off] != want:
                break
        else:
            hits.append(idx)
            if len(hits) >= limit:
                break
        start = idx + 1
    return hits


class RemoteProcess:
    """Read/write/allocate access to another process, over a Win32 handle.

    Use as a context manager, or call close() to release the handle.
    """

    def __init__(self, pid):
        self.pid = pid
        handle = kernel32.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise _win_error(f"OpenProcess(pid={pid})")
        self.handle = handle

    def close(self):
        """Release the process handle."""
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, addr, size):
        """Read exactly `size` bytes at `addr`, or raise InjectionError."""
        buf = (ctypes.c_char * size)()
        got = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)
        )
        if not ok or got.value != size:
            raise _win_error(f"ReadProcessMemory @ {addr:#x} ({size} bytes)")
        return bytes(buf)

    def write(self, addr, data):
        """Write `data` at `addr`, or raise InjectionError on a short write."""
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        put = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(put)
        )
        if not ok or put.value != len(data):
            raise _win_error(f"WriteProcessMemory @ {addr:#x} ({len(data)} bytes)")

    def read_u64(self, addr):
        """Read a little-endian 64-bit value at `addr`."""
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def query(self, addr):
        """Return the MEMORY_BASIC_INFORMATION for `addr`, or None."""
        mbi = MEMORY_BASIC_INFORMATION()
        n = kernel32.VirtualQueryEx(
            self.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        return mbi if n else None

    def alloc(self, size, executable=False, address=None):
        """Commit `size` bytes in the target, at `address` if given.

        Returns the base address, or None if the allocation failed.
        """
        protect = PAGE_EXECUTE_READWRITE if executable else PAGE_READWRITE
        ptr = kernel32.VirtualAllocEx(
            self.handle,
            ctypes.c_void_p(address) if address else None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            protect,
        )
        return int(ptr) if ptr else None

    def free(self, addr):
        """Release an allocation made by alloc(). Returns True on success."""
        return bool(kernel32.VirtualFreeEx(self.handle, ctypes.c_void_p(addr), 0, MEM_RELEASE))

    def alloc_near(self, near, size):
        """Allocate `size` executable bytes within +-2 GB of `near`.

        The range is what an E9 rel32 jump can reach. Free regions are
        enumerated with VirtualQueryEx and tried closest-first.

        Returns the base address, or None if nothing in range could be had.
        """
        gran = 0x10000
        span = 0x7FFF_0000
        low = max(near - span, 0x10000)
        high = near + span

        free_regions = []
        addr = low
        while addr < high:
            mbi = self.query(addr)
            if mbi is None or mbi.RegionSize == 0:
                break
            if mbi.State == MEM_FREE and mbi.RegionSize >= size:
                free_regions.append((mbi.BaseAddress, mbi.RegionSize))
            addr = mbi.BaseAddress + mbi.RegionSize

        def candidates():
            for base, rsize in free_regions:
                start = (max(base, low) + gran - 1) & ~(gran - 1)
                stop = min(base + rsize, high) - size
                if start > stop:
                    continue
                yield min(max(near, start), stop) & ~(gran - 1)

        for candidate in sorted(candidates(), key=lambda a: abs(a - near)):
            if candidate < low or candidate + size > high:
                continue
            ptr = self.alloc(size, executable=True, address=candidate)
            if ptr:
                return ptr
        return None

    def module(self, name):
        """Return (base_address, size) of the named module in this process."""
        want = name.lower()
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid
        )
        if snap == INVALID_HANDLE_VALUE:
            raise _win_error("CreateToolhelp32Snapshot(MODULE)")
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            if not kernel32.Module32FirstW(snap, ctypes.byref(entry)):
                raise _win_error("Module32FirstW")
            while True:
                if entry.szModule.lower() == want:
                    return int(entry.modBaseAddr), int(entry.modBaseSize)
                if not kernel32.Module32NextW(snap, ctypes.byref(entry)):
                    break
        finally:
            kernel32.CloseHandle(snap)
        raise InjectionError(f"Module '{name}' not found in pid {self.pid}")

    def read_module_image(self, base, size):
        """Read a whole module region by region, zero-filling unreadable gaps.

        A single 55 MB ReadProcessMemory fails outright if any page in the
        range is unreadable, and offsets must stay faithful to the image.
        """
        image = bytearray(size)
        addr = base
        end = base + size
        while addr < end:
            mbi = self.query(addr)
            if mbi is None or mbi.RegionSize == 0:
                break
            region_end = min(mbi.BaseAddress + mbi.RegionSize, end)
            readable = mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_UNREADABLE)
            if readable and region_end > addr:
                try:
                    image[addr - base: region_end - base] = self.read(addr, region_end - addr)
                except InjectionError:
                    pass
            addr = region_end
        return bytes(image)

    def thread_ids(self):
        """Return the thread ids belonging to this process."""
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == INVALID_HANDLE_VALUE:
            raise _win_error("CreateToolhelp32Snapshot(THREAD)")
        ids = []
        try:
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(THREADENTRY32)
            if kernel32.Thread32First(snap, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == self.pid:
                        ids.append(entry.th32ThreadID)
                    if not kernel32.Thread32Next(snap, ctypes.byref(entry)):
                        break
        finally:
            kernel32.CloseHandle(snap)
        return ids


class FrozenThreads:
    """Context manager suspending every thread of `proc` for the duration.

    WriteProcessMemory is not atomic: a thread sitting on the instruction being
    overwritten could otherwise execute a half-written opcode. Pass
    enabled=False to make it a no-op.
    """

    def __init__(self, proc, enabled=True):
        self.proc = proc
        self.enabled = enabled
        self.handles = []

    def __enter__(self):
        if not self.enabled:
            return self
        for tid in self.proc.thread_ids():
            h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if h:
                if kernel32.SuspendThread(h) == 0xFFFFFFFF:
                    kernel32.CloseHandle(h)
                else:
                    self.handles.append(h)
        return self

    def __exit__(self, *exc):
        for h in self.handles:
            kernel32.ResumeThread(h)
            kernel32.CloseHandle(h)
        self.handles = []
        return False


WNDENUMPROC = WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def client_windows():
    """Return the window handles of every open Wizard101 client."""
    found = []

    def callback(hwnd, _lparam):
        buf = ctypes.create_unicode_buffer(len(WINDOW_CLASS) + 2)
        user32.GetClassNameW(hwnd, buf, len(buf))
        if buf.value == WINDOW_CLASS:
            found.append(hwnd)
        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)
    return found


def pid_of_window(hwnd):
    """Return the process id owning `hwnd`."""
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def wait_for_client(timeout, log):
    """Block until a client window appears and return its pid.

    Raises InjectionError if none shows up within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    while True:
        handles = client_windows()
        if handles:
            pid = pid_of_window(handles[0])
            if pid:
                log(f"found client window (hwnd {handles[0]:#x}, pid {pid})")
                return pid
        if time.monotonic() > deadline:
            raise InjectionError(f"No '{WINDOW_CLASS}' window appeared within {timeout:.0f}s")
        time.sleep(0.5)


def build_string_struct(data_addr, length):
    """Build the game's 32-byte string struct: {ptr@0, 0@8, len@16, cap@24}.

    `length` excludes the terminating null.
    """
    return struct.pack("<QQQQ", data_addr, 0, length, length)


def build_login_bytecode(block_addr, flag_addr, string_struct_addr,
                         dat_addr, func_addr, orig_instr, ret_addr):
    """Assemble the code-cave payload that dispatches the login command.

    The payload checks `flag_addr`, and when set calls the game's command
    dispatcher, clears the flag, re-executes `orig_instr` and jumps to
    `ret_addr`. `block_addr` is where the payload will be written, and is
    needed to compute the trailing relative jump.
    """
    bc = bytearray()

    bc += b"\x50"                                             # push rax
    bc += b"\x48\xB8" + struct.pack("<Q", flag_addr)          # mov rax, flag_addr
    bc += b"\x80\x38\x01"                                     # cmp byte [rax], 1
    bc += b"\x58"                                             # pop rax
    bc += b"\x0F\x85"                                         # jne skip
    skip_fixup = len(bc)
    bc += b"\x00\x00\x00\x00"

    bc += b"\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53"     # push rax,rcx,rdx,r8-r11
    bc += b"\x48\x83\xEC\x28"                                 # sub rsp, 0x28
    bc += b"\x41\xB1\x01"                                     # mov r9b, 1
    bc += b"\x45\x33\xC0"                                     # xor r8d, r8d
    bc += b"\x48\xBA" + struct.pack("<Q", string_struct_addr)  # mov rdx, string_struct
    bc += b"\x48\xB8" + struct.pack("<Q", dat_addr)           # mov rax, dat
    bc += b"\x48\x8B\x08"                                     # mov rcx, [rax]
    bc += b"\x48\xB8" + struct.pack("<Q", func_addr)          # mov rax, func
    bc += b"\xFF\xD0"                                         # call rax
    bc += b"\x48\xB8" + struct.pack("<Q", flag_addr)          # mov rax, flag_addr
    bc += b"\xC6\x00\x00"                                     # mov byte [rax], 0
    bc += b"\x48\x83\xC4\x28"                                 # add rsp, 0x28
    bc += b"\x41\x5B\x41\x5A\x41\x59\x41\x58\x5A\x59\x58"     # pop r11-r8,rdx,rcx,rax

    skip_target = len(bc)
    struct.pack_into("<i", bc, skip_fixup, skip_target - skip_fixup - 4)

    bc += orig_instr

    bc += b"\xE9"                                             # jmp ret_addr
    jmp_from = block_addr + len(bc) + 4
    bc += struct.pack("<i", ret_addr - jmp_from)

    return bytes(bc)


class Addresses:
    """Resolved injection addresses for one running client."""

    def __init__(self, mod_base, mod_size, login, dat, func, hook, orig_instr):
        self.mod_base = mod_base
        self.mod_size = mod_size
        self.login = login
        self.dat = dat
        self.func = func
        self.hook = hook
        self.orig_instr = orig_instr

    @property
    def ret(self):
        """Address the payload jumps back to: just past the patched bytes."""
        return self.hook + HOOK_INSTR_LEN


def resolve(proc, log):
    """Locate the dispatcher, its globals and the hook site in `proc`.

    Returns an Addresses instance. Raises InjectionError if a pattern is
    missing, which means the client build changed and the patterns need
    rebuilding in a disassembler.
    """
    mod_base, mod_size = proc.module(MODULE_NAME)
    log(f"{MODULE_NAME} @ {mod_base:#x} ({mod_size / 1024 / 1024:.1f} MiB)")

    image = proc.read_module_image(mod_base, mod_size)

    login_hits = scan(image, parse_pattern(LOGIN_PATTERN))
    if not login_hits:
        raise InjectionError("LOGIN_PATTERN not found")
    if len(login_hits) > 1:
        log(f"warning: LOGIN_PATTERN matched {len(login_hits)} times, using the first")
    login_addr = mod_base + login_hits[0]

    dat_disp = struct.unpack_from("<i", image, login_hits[0] + 13)[0]
    func_disp = struct.unpack_from("<i", image, login_hits[0] + 18)[0]
    dat_addr = login_addr + 17 + dat_disp
    func_addr = login_addr + 22 + func_disp

    hook_hits = scan(image, parse_pattern(HOOK_PATTERN))
    if not hook_hits:
        raise InjectionError("HOOK_PATTERN not found")
    if len(hook_hits) > 1:
        log(f"warning: HOOK_PATTERN matched {len(hook_hits)} times, using the first")
    hook_addr = mod_base + hook_hits[0]
    orig_instr = image[hook_hits[0]: hook_hits[0] + HOOK_INSTR_LEN]

    log(f"login  {login_addr:#x}  (RVA {login_hits[0]:#x})")
    log(f"dat    {dat_addr:#x}")
    log(f"func   {func_addr:#x}")
    log(f"hook   {hook_addr:#x}  (RVA {hook_hits[0]:#x})  orig {orig_instr.hex(' ')}")

    return Addresses(mod_base, mod_size, login_addr, dat_addr, func_addr, hook_addr, orig_instr)


def wait_until_ready(proc, addrs, timeout, log):
    """Block until the game's global client pointer is non-null.

    Injecting before the game populates it would pass rcx = NULL to the
    dispatcher and crash the client.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            ptr = proc.read_u64(addrs.dat)
        except InjectionError:
            ptr = 0
        if ptr:
            log(f"client ready ([dat] = {ptr:#x})")
            return ptr
        if time.monotonic() > deadline:
            raise InjectionError(f"[dat] still NULL after {timeout:.0f}s, client not loaded")
        time.sleep(0.25)


def do_login(proc, addrs, username, password, timeout, suspend, log):
    """Inject and run the login command, then restore the process.

    Allocations are freed and the hook site restored on every exit path.

    Args:
        proc: open RemoteProcess for the client.
        addrs: Addresses from resolve().
        username, password: credentials, forwarded to the game's own command.
        timeout: seconds to wait for the payload to run.
        suspend: freeze threads while patching the hook site.
        log: single-argument logging callable.
    """
    cmd = f"login {username} {password}".encode("utf-8")
    cmd_len = len(cmd)

    allocations = []
    hook_patched = False

    def alloc(size, executable=False):
        addr = proc.alloc(size, executable=executable)
        if addr is None:
            raise _win_error(f"VirtualAllocEx({size})")
        allocations.append(addr)
        return addr

    try:
        str_data = alloc(cmd_len + 1)
        str_struct = alloc(32)
        flag = alloc(8)

        cave = proc.alloc_near(addrs.hook, CAVE_SIZE)
        if cave is None:
            raise InjectionError("No executable memory available within +-2 GB of the hook site")
        allocations.append(cave)
        log(f"code cave {cave:#x} (hook delta {cave - addrs.hook:+#x})")

        proc.write(str_data, cmd + b"\0")
        proc.write(str_struct, build_string_struct(str_data, cmd_len))
        proc.write(flag, b"\0" * 8)

        bytecode = build_login_bytecode(
            cave, flag, str_struct, addrs.dat, addrs.func, addrs.orig_instr, addrs.ret
        )
        if len(bytecode) > CAVE_SIZE:
            raise InjectionError(f"Payload is {len(bytecode)} bytes, cave is {CAVE_SIZE}")
        proc.write(cave, bytecode)
        log(f"payload written ({len(bytecode)} bytes)")

        proc.write(flag, b"\x01")

        rel = cave - (addrs.hook + 5)
        if not (-0x8000_0000 <= rel <= 0x7FFF_FFFF):
            raise InjectionError(f"Code cave out of rel32 range ({rel:#x})")
        jmp = b"\xE9" + struct.pack("<i", rel) + b"\x90\x90"

        with FrozenThreads(proc, suspend):
            current = proc.read(addrs.hook, HOOK_INSTR_LEN)
            if current != addrs.orig_instr:
                raise InjectionError(
                    f"Hook site changed underneath us ({current.hex(' ')}), leaving it alone"
                )
            proc.write(addrs.hook, jmp)
            hook_patched = True
        log("hook armed, waiting for the main thread to run it")

        deadline = time.monotonic() + timeout
        while True:
            time.sleep(0.05)
            if proc.read(flag, 1)[0] == 0:
                log("login command dispatched")
                break
            if time.monotonic() > deadline:
                raise InjectionError(f"Payload never ran within {timeout:.0f}s")
    finally:
        if hook_patched:
            try:
                with FrozenThreads(proc, suspend):
                    proc.write(addrs.hook, addrs.orig_instr)
                log("original bytes restored")
            except InjectionError as exc:
                print(f"[w101] failed to restore hook site: {exc}", file=sys.stderr)
            time.sleep(0.5)
        for addr in allocations:
            proc.free(addr)


def read_credentials_file(path):
    """Read a username and password from the first two lines of a file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise SystemExit(f"Cannot read {path}: {exc}")
    if len(lines) < 2 or not lines[0].strip() or not lines[1].strip():
        raise SystemExit(
            f"{path} must hold the username on line 1 and the password on line 2"
        )
    return lines[0].strip(), lines[1].strip()


def launch_game(game_dir, login_server, steam, log):
    """Start the client directly, skipping the launcher.

    `game_dir` is the Wizard101 install root; the client lives in its Bin
    subdirectory, which also becomes the working directory.
    """
    host, _, port = login_server.rpartition(":")
    if not host or not port:
        raise SystemExit(f"--login-server wants host:port, got {login_server!r}")

    bin_dir = os.path.join(game_dir, "Bin")
    exe = os.path.join(bin_dir, "WizardGraphicalClient.exe")
    if not os.path.exists(exe):
        raise InjectionError(f"Client not found: {exe}")

    argv = [exe] + (["-ST"] if steam else []) + ["-L", host, port]
    proc = subprocess.Popen(argv, cwd=bin_dir)
    log(f"launched {exe} (pid {proc.pid})")


def get_credentials(args):
    """Resolve credentials from a file, CLI arguments or the environment.

    Returns (username, password). Exits with a message if they are missing or
    contain whitespace, which the space-separated login command cannot carry.
    """
    username = password = None
    if args.credentials_file:
        username, password = read_credentials_file(args.credentials_file)
    username = args.username or username or os.environ.get("W101_USER")
    password = args.password or password or os.environ.get("W101_PASS")
    if not username or not password:
        raise SystemExit(
            "Missing credentials: use --credentials-file, --username/--password, "
            "or export W101_USER and W101_PASS."
        )
    for label, value in (("username", username), ("password", password)):
        if any(c.isspace() for c in value):
            raise SystemExit(f"The {label} contains whitespace, which 'login <user> <pass>' "
                             "cannot represent.")
    return username, password


def main(argv=None):
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        description="Wizard101 auto-login through memory injection (run under Wine)."
    )
    parser.add_argument("--pid", type=int, help="client pid (default: find it from the window)")
    parser.add_argument("--username", help="prefer W101_USER, argv is world-readable")
    parser.add_argument("--password", help="prefer W101_PASS, argv is world-readable")
    parser.add_argument("--credentials-file",
                        help="username on line 1, password on line 2")
    parser.add_argument("--launch", metavar="DIR",
                        help="start the client from DIR first, skipping the launcher")
    parser.add_argument("--login-server", default="login.us.wizard101.com:12000",
                        help="login server for --launch (default %(default)s)")
    parser.add_argument("--steam", action="store_true",
                        help="pass -ST to the client, for the Steam build")
    parser.add_argument("--check", action="store_true",
                        help="read-only: resolve and print the addresses, write nothing")
    parser.add_argument("--wait", type=float, default=120.0,
                        help="seconds to wait for the client window (default 120)")
    parser.add_argument("--ready-timeout", type=float, default=120.0,
                        help="seconds to wait for [dat] to become valid (default 120)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="seconds to wait for the payload to run (default 10)")
    parser.add_argument("--no-suspend", action="store_true",
                        help="do not freeze threads while patching the hook site")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(argv)

    def log(msg):
        if not args.quiet:
            print(f"[w101] {msg}", flush=True)

    if sys.platform != "win32":
        raise SystemExit(
            "This must run under Wine inside the game prefix: ReadProcessMemory and "
            "WriteProcessMemory do not exist on native Linux.\n"
            "For offline pattern verification use tools/scan_pe.py."
        )
    if struct.calcsize("P") != 8:
        raise SystemExit("A 64-bit Python is required: the client is x64.")

    _bind()

    username = password = None
    if not args.check:
        username, password = get_credentials(args)

    try:
        if args.launch:
            launch_game(args.launch, args.login_server, args.steam, log)
        pid = args.pid or wait_for_client(args.wait, log)
        with RemoteProcess(pid) as proc:
            addrs = resolve(proc, log)
            if args.check:
                try:
                    ptr = proc.read_u64(addrs.dat)
                    log(f"[dat] = {ptr:#x}" + ("" if ptr else "  (client not ready yet)"))
                except InjectionError:
                    log("[dat] not readable")
                log("check complete, nothing was written")
                return 0
            wait_until_ready(proc, addrs, args.ready_timeout, log)
            do_login(proc, addrs, username, password, args.timeout, not args.no_suspend, log)
        log("login sent")
        return 0
    except (InjectionError, OSError) as exc:
        print(f"[w101] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
