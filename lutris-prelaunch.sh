#!/usr/bin/env bash
# Lutris pre-launch script: wait for the client window, then inject the login.
#
# Lutris > Configure > System options > advanced:
#   "Pre-launch command"  = /path/to/lutris-prelaunch.sh
#   "Wait for completion" = OFF
#
# Keep it a pre-launch command rather than the game executable: it finishes and
# exits, and gamescope tears everything down when its direct child terminates.

set -uo pipefail

CONFIG="${W101_CONFIG:-$HOME/.config/w101-autologin/config}"
# shellcheck source=/dev/null
[[ -r "$CONFIG" ]] && source "$CONFIG"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${W101_PREFIX:-$HOME/Games/Wizard101NA/prefix}"
SCRIPT="${W101_SCRIPT:-$HERE/w101_autologin.py}"
EXE_C="${W101_EXE_C:-$HERE/dist/w101_autologin_c.exe}"
EXE="${W101_EXE:-$HERE/dist/w101_autologin.exe}"
PYTHON_WIN="${W101_PYTHON_WIN:-$PREFIX/drive_c/PythonEmbed/python.exe}"
LOG="${W101_LOG:-${XDG_STATE_HOME:-$HOME/.local/state}/w101-autologin.log}"
export DISPLAY="${W101_DISPLAY:-${DISPLAY:-:1}}"

mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1
echo "=== $(date -Is) prelaunch (DISPLAY=$DISPLAY) ==="

die() { echo "error: $*" >&2; exit 1; }

# Same Proton build the game runs under, so both share one wineserver.
if [[ -z "${W101_WINE:-}" ]]; then
    version="$(cat "$PREFIX/version" 2>/dev/null || true)"
    for candidate in \
        "$HOME/.local/share/Steam/compatibilitytools.d/${version}-x86_64/files/bin/wine" \
        "$HOME/.local/share/Steam/compatibilitytools.d/${version}/files/bin/wine" \
        "$HOME/.steam/steam/steamapps/common/${version}/files/bin/wine"
    do
        [[ -x "$candidate" ]] && { W101_WINE="$candidate"; break; }
    done
fi
W101_WINE="${W101_WINE:-$(command -v wine || true)}"
[[ -x "${W101_WINE:-}" ]] || die "no wine binary found, set W101_WINE"
echo "wine: $W101_WINE"

# --check needs no credentials; anything else does.
wants_check=0
for a in "$@"; do
    [[ "$a" == "--check" ]] && wants_check=1
done

# Credentials: exported environment, then the keyring, then a 0600 file.
if [[ -z "${W101_PASS:-}" && -n "${W101_USER:-}" ]] && command -v secret-tool >/dev/null 2>&1; then
    W101_PASS="$(secret-tool lookup service w101-autologin account "$W101_USER" 2>/dev/null || true)"
    [[ -n "$W101_PASS" ]] && echo "credentials: keyring"
fi
if [[ -z "${W101_PASS:-}" ]]; then
    CRED_FILE="${W101_CRED_FILE:-$HOME/.config/w101-autologin/credentials}"
    if [[ -r "$CRED_FILE" ]]; then
        perms="$(stat -c %a "$CRED_FILE")"
        [[ "$perms" == "600" ]] || echo "warning: $CRED_FILE is mode $perms, expected 600"
        W101_USER="$(sed -n '1p' "$CRED_FILE")"
        W101_PASS="$(sed -n '2p' "$CRED_FILE")"
        echo "credentials: $CRED_FILE"
    fi
fi
if [[ $wants_check -eq 0 ]]; then
    [[ -n "${W101_USER:-}" && -n "${W101_PASS:-}" ]] || die "no credentials found, see README"
fi
export W101_USER W101_PASS

if [[ -f "$EXE_C" ]]; then
    target=("$EXE_C")
elif [[ -f "$EXE" ]]; then
    target=("$EXE")
elif [[ -f "$PYTHON_WIN" ]]; then
    target=("$PYTHON_WIN" "$SCRIPT")
else
    die "no injector found, run ./build-c.sh"
fi
echo "injector: ${target[*]}"

export WINEPREFIX="$PREFIX"
export WINEDEBUG="${WINEDEBUG:--all}"

"$W101_WINE" "${target[@]}" "$@"
echo "=== injector exited with $? ==="
exit 0
