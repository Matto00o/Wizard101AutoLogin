# Internals

Port of `libs/wizlaunch/src/login.rs` from Deimos-Wizard101. See the
[README](../README.md) for what it does and how to run it.

## Layout

| File | Runs on | Purpose |
| --- | --- | --- |
| `w101_autologin.c` | Wine or Windows | the injector, 204 KB compiled, no dependencies |
| `w101_autologin.py` | Wine or Windows | same injector in Python, the readable reference |
| `build-c.sh` | Linux | cross-compiles the C version with Zig |
| `build-exe.sh` | Linux | builds the Python version into an exe with PyInstaller |
| `tools/scan_pe.py` | Linux | offline pattern check against the exe on disk |
| `tools/test_bytecode.py` | Linux | disassembles the payload, and diffs C against Python |
| `lutris-prelaunch.sh` | Linux | Lutris pre-launch hook |
| `w101-autologin.cmd` | Windows | launch the client and auto-login, in one step |
| `setup-prefix.sh` | Linux | optional: embeddable Python in the game prefix, for iterating without rebuilding |

`tools/test_bytecode.py` asserts that the C build assembles a byte-identical
payload, so the Python stays a faithful reference rather than drifting into a
second dialect.

## Skipping the launcher

`WizardGraphicalClient.exe -L <host> <port>`, with the working directory set to
`Bin`, and `-ST` prepended for the Steam build. No patching, no version check.
This is exactly what the official launcher runs once it has finished patching —
which is the catch: without the launcher the game no longer receives patches.

## The auto-login

1. Scan `WizardGraphicalClient.exe` for `LOGIN_PATTERN`, an existing call site
   of the game's text command dispatcher, and decode the RIP-relative
   displacements to get `dat` (the global client pointer) and `func` (the
   dispatcher).
2. Scan for `HOOK_PATTERN`, 7 bytes on a path the main thread crosses
   constantly. The main thread is required: the dispatcher touches game and UI
   state that is not thread-safe, so `CreateRemoteThread` crashes.
3. Write the command string, a 32-byte game string struct
   `{ptr@0, 0@8, len@16, cap@24}` and a one-byte flag into the target.
4. Write a payload into a code cave within ±2 GB, the reach of an `E9 rel32`.
   It tests the flag, and on the one pass where it is set, saves registers,
   reserves shadow space, calls the dispatcher, clears the flag, restores
   registers, re-executes the original 7 bytes and jumps back.
5. Arm the flag, patch the site with `E9 rel32 + 90 90`, poll the flag until it
   clears, then restore the original bytes and free everything.

## Current pattern values

```
LOGIN_PATTERN    RVA 0x16dd0a2    dat RVA 0x333a160 (.data), func RVA 0x1491680 (.text)
HOOK_PATTERN     RVA 0x184758b    7 bytes: 49 8b 8d d8 00 00 00  = mov rcx,[r13+0xd8]
```

The relocated instruction is not RIP-relative, so copying it into the cave needs
no fixups. If a game update breaks the patterns, they have to be rebuilt in a
disassembler and everything downstream changes.

## Differences from the Rust original

- **Threads are frozen while the 7 bytes are patched.** `WriteProcessMemory` is
  not atomic; a thread parked on that instruction could otherwise execute a
  half-written opcode. `--no-suspend` turns this off.
- **`alloc_near` enumerates free regions with `VirtualQueryEx`** and tries the
  closest first, instead of probing every 64 KB out to 2 GB. That also removes
  any need for wizwalker's AUTOBOT arena, so no game function gets zeroed.
- **The client pointer is checked before arming.** Injecting before the game
  populates `dat` would pass `rcx = NULL` to the dispatcher and crash the
  client.
- **The module is read region by region.** One 55 MB `ReadProcessMemory` fails
  outright if any page in the range is unreadable.
- **The hook site is re-read before patching** and left alone if something else
  already changed it, and the cave is freed half a second after the bytes are
  restored, so no thread is left executing inside freed memory.

## Builds

Either build produces a Windows executable that still has to *run* inside the
game prefix under Wine, since `ReadProcessMemory` exists nowhere else.
Compiling avoids installing Python in that prefix, not running inside it. The
pre-launch script prefers the C build, then the PyInstaller one, then the `.py`.

**`build-c.sh` — 204 KB, recommended.** Cross-compiles with Zig, which bundles
the mingw-w64 headers and import libraries. On first run it fetches the Zig
tarball into `~/.cache/w101-autologin/zig` and touches nothing else: no root, no
container, no package manager, which matters on an immutable host like Bazzite
where `dnf install mingw64-gcc` is not an option. `./build-c.sh --clean` drops
the cached toolchain. It also honours `W101_ZIG`, or a `zig` already on `PATH`.

**`build-exe.sh` — 7.4 MB.** PyInstaller onefile. It needs a Windows Python, but
not in the game prefix: it creates a throwaway prefix under
`~/.cache/w101-autologin/buildpfx`, installs Python and PyInstaller there, and
copies only the finished exe out. Any 64-bit wine works, including the
`files/bin/wine` of an installed Proton build, which is what it falls back to
when there is no system wine. `./build-exe.sh --clean` discards the prefix.

`setup-prefix.sh` is the other way round: it drops an embeddable Python into the
game prefix so `w101_autologin.py` can be run directly. Useful while iterating
on the patterns, since it skips the rebuild.

## Credentials on Linux

The pre-launch script is an ordinary Linux process, so it reads the credentials
on the Linux side and passes them into Wine through the environment. Nothing is
stored inside the prefix.

That indirection buys two things: the password never appears in `argv`
(`/proc/PID/cmdline` is world-readable, `/proc/PID/environ` is not), and it
makes the system keyring usable, since `secret-tool` has no meaning inside Wine.

Resolution order, first hit wins:

1. `W101_USER` / `W101_PASS` already exported.
2. The keyring, if `W101_USER` is set and `secret-tool` is available:
   `secret-tool store --label=Wizard101 service w101-autologin account myuser`
3. `~/.config/w101-autologin/credentials`, mode 600.

To skip the script, the exe reads the file itself and the path can be anywhere
Wine can see, including a Linux path through `Z:`:

```sh
wine dist/w101_autologin_c.exe --credentials-file 'Z:\home\you\.config\w101-autologin\credentials'
```

Wizlaunch's Windows Credential Manager is no better under Wine: it is a plain
file store there rather than DPAPI.

## Configuration

`lutris-prelaunch.sh` sources `~/.config/w101-autologin/config` if present:

| Variable | Default |
| --- | --- |
| `W101_PREFIX` | `~/Games/Wizard101NA/prefix` |
| `W101_WINE` | the `files/bin/wine` of the Proton build named in `<prefix>/version` |
| `W101_EXE_C` | `dist/w101_autologin_c.exe`, preferred when it exists |
| `W101_EXE` | `dist/w101_autologin.exe`, the fallback |
| `W101_PYTHON_WIN` | `<prefix>/drive_c/PythonEmbed/python.exe` |
| `W101_CRED_FILE` | `~/.config/w101-autologin/credentials` |
| `W101_DISPLAY` | `:1` |
| `W101_LOG` | `~/.local/state/w101-autologin.log` |
