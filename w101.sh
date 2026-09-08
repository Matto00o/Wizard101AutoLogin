#!/usr/bin/env bash
# Run the injector against the running client, printing to the terminal.
#
# Resolves the prefix and the Proton wine build, then passes every argument
# straight through to the injector.
#
#   ./w101.sh --check     read-only, resolve and print the addresses
#   ./w101.sh             log in, reading ~/.config/w101-autologin/credentials
#
# For the automatic path use lutris-prelaunch.sh instead; this one is for
# testing by hand.

set -uo pipefail

CONFIG="${W101_CONFIG:-$HOME/.config/w101-autologin/config}"
# shellcheck source=/dev/null
[[ -r "$CONFIG" ]] && source "$CONFIG"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${W101_PREFIX:-$HOME/Games/Wizard101NA/prefix}"
EXE="${W101_EXE_C:-$HERE/dist/w101_autologin_c.exe}"
CRED_FILE="${W101_CRED_FILE:-$HOME/.config/w101-autologin/credentials}"

die() { echo "error: $*" >&2; exit 1; }

# Wine names the wineserver socket directory after the prefix device and inode.
wineserver_socket() {
    local dev ino
    read -r dev ino < <(stat -c '%d %i' "$1")
    printf '/tmp/.wine-%s/server-%x-%x/socket' "$(id -u)" "$dev" "$ino"
}

[[ -d "$PREFIX" ]] || die "prefix not found: $PREFIX (set W101_PREFIX)"
[[ -f "$EXE" ]] || die "injector not found: $EXE (run ./build-c.sh)"

if [[ -z "${W101_WINE:-}" ]]; then
    version="$(cat "$PREFIX/version" 2>/dev/null || true)"
    for candidate in \
        "$HOME/.local/share/Steam/compatibilitytools.d/${version}-x86_64/files/bin/wine" \
        "$HOME/.local/share/Steam/compatibilitytools.d/${version}/files/bin/wine" \
        "$HOME/.steam/steam/steamapps/common/${version}/files/bin/wine" \
        "$(command -v wine || true)"
    do
        [[ -x "${candidate:-}" ]] && { W101_WINE="$candidate"; break; }
    done
fi
[[ -x "${W101_WINE:-}" ]] || die "no wine binary found, set W101_WINE"

# Attaching to a live wineserver is fine; starting one is not, because Proton
# then cannot launch the game into it.
[[ -S "$(wineserver_socket "$PREFIX")" ]] \
    || die "no wineserver running for $PREFIX -- start the game first"

# --check needs no credentials; anything else does.
args=("$@")
wants_check=0
for a in "${args[@]}"; do
    [[ "$a" == "--check" ]] && wants_check=1
done
if [[ $wants_check -eq 0 && -z "${W101_PASS:-}" ]]; then
    [[ -r "$CRED_FILE" ]] || die "no credentials: create $CRED_FILE (user on line 1, password on line 2)"
    args+=(--credentials-file "$(printf 'Z:%s' "$CRED_FILE" | tr '/' '\\')")
fi

export WINEPREFIX="$PREFIX"
export WINEDEBUG="${WINEDEBUG:--all}"

exec "$W101_WINE" "$EXE" "${args[@]}"
