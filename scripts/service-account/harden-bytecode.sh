#!/bin/sh
# Prevent bytecode writes by console scripts of an installation (B2).
#
#   harden-bytecode.sh <prefix>
#
# Run by the unprivileged builder, on the tree at its final path, before root takes
# ownership. It does two things:
#   - adds -B to each console script whose first line is exactly a direct shebang of
#     the venv interpreter, so bytecode writing is off from interpreter start;
#   - compiles the venv's site-packages and the bundled standard library as
#     checked-hash bytecode, so a metadata change does not make them stale.
#
# Any other launcher form is left alone, and check_bytecode.py then fails on it. This
# is bytecode-write prevention: it does not make the installation immutable.
set -eu

die() { echo "harden-bytecode: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: harden-bytecode.sh <prefix>"
[ "$(id -u)" -ne 0 ] || die "run as the builder, not root"
PREFIX=$(cd "$1" && pwd) || die "no such prefix: $1"
BIN=$PREFIX/venv/bin
PY=$BIN/python
[ -x "$PY" ] || die "no interpreter at $PY"
VERSION=$("$PY" -I -B -S -c 'import sys; print("python%d.%d" % sys.version_info[:2])')
HOME_DIR=$(sed -n 's/^home = //p' "$PREFIX/venv/pyvenv.cfg")
[ -n "$HOME_DIR" ] || die "pyvenv.cfg names no interpreter home"
REAL_HOME=$(realpath "$HOME_DIR")
case "$REAL_HOME" in
    "$(realpath "$PREFIX")"/*) ;;
    *) die "the interpreter home is outside the prefix" ;;
esac
STDLIB=$(dirname "$REAL_HOME")/lib/$VERSION
SITE=$PREFIX/venv/lib/$VERSION/site-packages
[ -d "$STDLIB" ] || die "no standard library at $STDLIB"
[ -d "$SITE" ] || die "no site-packages at $SITE"

for launcher in "$BIN"/*; do
    if [ -L "$launcher" ] || [ ! -f "$launcher" ]; then
        continue
    fi
    first=$(head -c 4096 "$launcher" | head -n 1 | tr -d '\000')
    case "$first" in
        "#!$BIN/python" | "#!$BIN/python3" | "#!$BIN/$VERSION")
            sed -i '1s/$/ -B/' "$launcher"
            ;;
    esac
done

"$PY" -I -B -m compileall -q -f -j0 --invalidation-mode checked-hash "$SITE" "$STDLIB" \
    || die "compile failed"
echo "harden-bytecode: launchers hardened and bytecode compiled under $PREFIX"
