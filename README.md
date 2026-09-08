# Wizard101 auto-login

Start Wizard101 straight into the game, skipping both the launcher and the
login screen. Works on Windows and on Linux under Wine or Proton.

The login screen is drawn by the game, not by Windows controls, so there are no
fields to fill from outside. Instead this hands the credentials to the game's
own internal command dispatcher, through a short-lived hook in the client's
memory. The patch is removed a few frames later.

Two builds of the same thing: a 204 KB C binary with no dependencies, and a
Python version kept as the readable reference. They assemble a byte-identical
payload.

## Requirements

- 64-bit Wizard101 client
- Linux: any Wine or Proton build, plus `curl` and `python3` for the build script
- Windows: nothing, the exe is self-contained

## Build

```sh
./build-c.sh            # -> dist/w101_autologin_c.exe
```

Fetches the Zig cross-compiler into `~/.cache/w101-autologin` on first run and
touches nothing else. On Windows, compile with any C compiler:

```
zig cc w101_autologin.c -lkernel32 -luser32 -o w101_autologin.exe
```

## Credentials

Create a file with the username on the first line and the password on the
second:

- Linux: `~/.config/w101-autologin/credentials`, then `chmod 600`
- Windows: `%APPDATA%\w101-autologin\credentials`

The username and password cannot contain spaces. The injector can also take
`--username`/`--password`, or `W101_USER`/`W101_PASS` from the environment.

This is plaintext on disk. It protects nothing from anything already running as
you. On Linux `lutris-prelaunch.sh` will use the system keyring instead when
`W101_USER` is set and `secret-tool` is available.

## Usage on Windows

Edit `GAME_DIR` at the top of `w101-autologin.cmd` if Wizard101 is not in the
default location, then double-click it. It launches the client and logs in.

Or call the exe directly:

```
w101_autologin_c.exe --launch "C:\ProgramData\KingsIsle Entertainment\Wizard101" ^
                     --credentials-file "%APPDATA%\w101-autologin\credentials"
```

Add `--steam` for the Steam build.

## Usage on Linux

Point Lutris at the client instead of the launcher:

- Executable: `<prefix>/drive_c/ProgramData/KingsIsle Entertainment/Wizard101/Bin/WizardGraphicalClient.exe`
- Arguments: `-L login.us.wizard101.com 12000`
- Working directory: that `Bin` folder

Then under System options → advanced, set **Pre-launch command** to
`lutris-prelaunch.sh` and leave **Wait for completion** off. It waits for the
client window and injects, in parallel with the launch Lutris performs.

The script assumes the prefix is at `~/Games/Wizard101NA/prefix`. If yours is
elsewhere, put `W101_PREFIX=/path/to/prefix` in
`~/.config/w101-autologin/config`; see [docs/internals.md](docs/internals.md)
for the other settings.

It must stay a pre-launch command rather than the game executable: it finishes
and exits, and gamescope tears everything down when its direct child
terminates. Under gamescope the wineserver is on `:1`, which is the default;
override with `W101_DISPLAY`. Logs go to `~/.local/state/w101-autologin.log`.

Without the launcher the game no longer receives patches, so run `wizpatch`
separately when an update lands.

## After a game update

An update can move the byte patterns the injector looks for. Both checks are
read-only and need neither the game running nor Wine:

```sh
python3 tools/scan_pe.py        # do the patterns still match?
python3 tools/test_bytecode.py  # does the payload still assemble correctly?
```

Against a running client, `--check` resolves the addresses and writes nothing.
If `scan_pe.py` reports a miss, the patterns have to be rebuilt in a
disassembler.

## How it works

See [docs/internals.md](docs/internals.md).

## License and credits

GPL-3.0, as a port of `libs/wizlaunch/src/login.rs` from
[Deimos-Wizard101](https://github.com/Deimos-Wizard101/Deimos-Wizard101).

- [Click](https://github.com/CIick) — reverse engineering and the original
  memory-based login
- [Slackaduts](https://github.com/Slackaduts) — the Rust implementation this
  ports from
