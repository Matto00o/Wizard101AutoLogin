#!/usr/bin/env bash
# Build w101_autologin.exe with PyInstaller, in a throwaway Wine prefix.
#
# The build prefix is separate from the game prefix, which never gets a Python
# installed into it. Only the finished exe is copied out, into dist/.
#
#   ./build-exe.sh          build
#   ./build-exe.sh --clean  delete the build prefix and start over

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${W101_BUILD_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/w101-autologin}"
BUILD_PREFIX="$CACHE/buildpfx"
PYVER="${W101_PYVER:-3.12.8}"
PYDIR='C:\Python312'
INSTALLER_URL="https://www.python.org/ftp/python/${PYVER}/python-${PYVER}-amd64.exe"

if [[ "${1:-}" == "--clean" ]]; then
    echo "Removing $BUILD_PREFIX"
    rm -rf "$BUILD_PREFIX"
    shift
fi

# Any 64-bit wine will do; the build prefix has nothing to do with the game one.
if [[ -z "${W101_WINE:-}" ]]; then
    for candidate in \
        "$(command -v wine || true)" \
        "$HOME"/.local/share/Steam/compatibilitytools.d/*/files/bin/wine \
        "$HOME"/.steam/steam/steamapps/common/Proton*/files/bin/wine
    do
        [[ -x "${candidate:-}" ]] && { W101_WINE="$candidate"; break; }
    done
fi
[[ -x "${W101_WINE:-}" ]] || { echo "no wine binary found, set W101_WINE" >&2; exit 1; }

export WINEPREFIX="$BUILD_PREFIX"
export WINEARCH=win64
export WINEDEBUG="${WINEDEBUG:--all}"
export DISPLAY="${DISPLAY:-}"

echo "wine   : $W101_WINE"
echo "prefix : $WINEPREFIX"

mkdir -p "$CACHE"

if [[ ! -d "$WINEPREFIX" ]]; then
    echo "Creating the build prefix"
    "$W101_WINE" wineboot -u
    "${W101_WINE}server" -w
fi

if [[ ! -f "$WINEPREFIX/drive_c/Python312/python.exe" ]]; then
    installer="$CACHE/python-${PYVER}-amd64.exe"
    if [[ ! -f "$installer" ]]; then
        echo "Downloading $INSTALLER_URL"
        curl -fL --proto '=https' --tlsv1.2 -o "$installer.part" "$INSTALLER_URL"
        mv "$installer.part" "$installer"
    fi
    echo "Installing Python into the build prefix"
    "$W101_WINE" "$installer" /quiet InstallAllUsers=0 "TargetDir=$PYDIR" \
        Include_test=0 Include_doc=0 Include_launcher=0 InstallLauncherAllUsers=0 \
        AssociateFiles=0 Shortcuts=0 PrependPath=0 || true
    "${W101_WINE}server" -w
    [[ -f "$WINEPREFIX/drive_c/Python312/python.exe" ]] \
        || { echo "Python install failed, see $WINEPREFIX" >&2; exit 1; }
fi

"$W101_WINE" "$PYDIR\\python.exe" --version

if ! "$W101_WINE" "$PYDIR\\python.exe" -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller"
    "$W101_WINE" "$PYDIR\\python.exe" -m pip install --disable-pip-version-check \
        --no-warn-script-location --upgrade pip
    "$W101_WINE" "$PYDIR\\python.exe" -m pip install --disable-pip-version-check \
        --no-warn-script-location pyinstaller
fi

cd "$HERE"
echo "Building"
"$W101_WINE" "$PYDIR\\python.exe" -m PyInstaller \
    --onefile \
    --console \
    --name w101_autologin \
    --distpath dist \
    --workpath "$CACHE/work" \
    --specpath "$CACHE" \
    --noconfirm \
    --exclude-module tkinter \
    --exclude-module unittest \
    --exclude-module pydoc_data \
    --exclude-module lib2to3 \
    --exclude-module sqlite3 \
    w101_autologin.py

"${W101_WINE}server" -w
ls -la dist/w101_autologin.exe
echo
echo "Done. The game prefix was not touched."
echo "Smoke test:"
echo "  WINEPREFIX=\$W101_PREFIX wine $HERE/dist/w101_autologin.exe --check"
