#!/usr/bin/env bash
# Install a 64-bit embeddable Python into the game prefix so the injector can
# run under Wine without compiling anything.
#
# The embeddable zip only needs unpacking: no installer, ~15 MB.

set -euo pipefail

PREFIX="${W101_PREFIX:-$HOME/Games/Wizard101NA/prefix}"
PYVER="${W101_PYVER:-3.12.8}"
DEST="$PREFIX/drive_c/PythonEmbed"
URL="https://www.python.org/ftp/python/${PYVER}/python-${PYVER}-embed-amd64.zip"

[[ -d "$PREFIX" ]] || { echo "prefix not found: $PREFIX" >&2; exit 1; }

if [[ -f "$DEST/python.exe" ]]; then
    echo "Python already present at $DEST"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $URL"
curl -fL --proto '=https' --tlsv1.2 -o "$tmp/python-embed.zip" "$URL"

mkdir -p "$DEST"
if command -v unzip >/dev/null 2>&1; then
    unzip -q "$tmp/python-embed.zip" -d "$DEST"
else
    python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
        "$tmp/python-embed.zip" "$DEST"
fi

echo "Installed at $DEST"
echo "Test with:  WINEPREFIX=$PREFIX wine $DEST/python.exe --version"
