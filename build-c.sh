#!/usr/bin/env bash
# Cross-compile w101_autologin.c into a dependency-free Windows executable.
#
# Uses Zig as the cross-compiler: one tarball, no root, no container, and it
# bundles the mingw-w64 headers and import libraries. It is fetched into the
# project cache on first run and touches nothing else on the system.
#
#   ./build-c.sh          build dist/w101_autologin_c.exe
#   ./build-c.sh --clean  drop the cached toolchain first

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${W101_BUILD_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/w101-autologin}"
ZIG_DIR="$CACHE/zig"
OUT="$HERE/dist/w101_autologin_c.exe"

if [[ "${1:-}" == "--clean" ]]; then
    echo "Removing $ZIG_DIR"
    rm -rf "$ZIG_DIR"
    shift
fi

ZIG="${W101_ZIG:-$(command -v zig || true)}"

if [[ ! -x "${ZIG:-}" && -x "$ZIG_DIR/zig" ]]; then
    ZIG="$ZIG_DIR/zig"
fi

if [[ ! -x "${ZIG:-}" ]]; then
    echo "Fetching the Zig toolchain into $ZIG_DIR"
    mkdir -p "$CACHE"
    url="$(curl -fsSL https://ziglang.org/download/index.json | python3 -c '
import json, sys
releases = json.load(sys.stdin)
versions = sorted((v for v in releases if v != "master"),
                  key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)
for v in versions:
    tarball = releases[v].get("x86_64-linux", {}).get("tarball")
    if tarball:
        print(tarball)
        break
')"
    [[ -n "$url" ]] || { echo "could not resolve a Zig download URL" >&2; exit 1; }
    echo "  $url"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fL --proto '=https' --tlsv1.2 -o "$tmp/zig.tar.xz" "$url"
    mkdir -p "$ZIG_DIR"
    tar -xJf "$tmp/zig.tar.xz" -C "$ZIG_DIR" --strip-components=1
    ZIG="$ZIG_DIR/zig"
fi

echo "zig: $ZIG ($("$ZIG" version))"

mkdir -p "$HERE/dist"
"$ZIG" cc \
    -target x86_64-windows-gnu \
    -O2 \
    -g0 \
    -std=c99 \
    -Wall -Wextra \
    -o "$OUT" \
    "$HERE/w101_autologin.c" \
    -lkernel32 -luser32

# zig cc emits a pdb alongside the exe even at -g0; it is not part of the deliverable
rm -f "${OUT%.exe}.pdb"

ls -la "$OUT"
echo
echo "Done. Nothing was installed outside $CACHE."
