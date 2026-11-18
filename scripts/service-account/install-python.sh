#!/bin/sh
# Install the installation's CPython, as the pinned uv binary's built-in download list
# names it, and nothing else (B7 U16, X21).
#
#   scripts/service-account/install-python.sh <prefix>
#
# install.sh runs this for $PREFIX/python, through `/usr/bin/env -i <allow-list> /bin/sh`,
# so the shell that decides starts without the caller's SHELLOPTS, BASHOPTS, PS4,
# exported functions or loader (LD_*) variables, which bash, as sh, and the dynamic
# loader would otherwise apply before the first line below. Run it only that way. On
# success it prints one line: the absolute path and the sha256 of the uv that ran
# (install.sh records them in INSTALL); on any refusal it prints nothing to stdout.
#
# Why: left to the caller, `uv python install` takes its download list (each archive's
# URL and checksum) from UV_PYTHON_DOWNLOADS_JSON_URL, UV_CONFIG_FILE, --config-file or
# any uv.toml or [tool.uv] it finds, and checks the archive only against that list's own
# checksum. A hash shows integrity, not provenance: only the list built into the pinned
# uv binary is an authority. So:
#
#   - uv is resolved once to an absolute path, must be a regular executable file with
#     the pinned sha256, and that same file is what runs (never a new PATH lookup);
#   - it runs through scripts/uv-clean.sh (allow-listed environment, --no-config), with
#     UV_PYTHON_CACHE_DIR passed for this step only, so U3 can supply the archive offline
#     (uv checks a cached archive against the built-in checksum);
#   - the request is exact, and no list, mirror or configuration-file option is given;
#   - the result must be exactly one CPython 3.12.14 installation.
#
# Decisions use only shell syntax and absolute paths (output too, through /usr/bin/printf),
# so even run with an inherited exported function, none can change them. The trust model:
# install.sh, the parent, is trusted, and this mechanism does not contain a compromised
# parent or a same-account attacker who can write the uv file, the source tree or the
# prefix: a uv file the developer can write may be replaced between the check and the run,
# and an installation planted in $PREFIX/python after the check would be kept by uv; file
# ownership is the boundary there.
#
# Upgrading uv or CPython means changing the pins below, with new U3 evidence.
set -eu
UV_SHA256=b8299463da6fa7da3b94464444d252d0afca8ac6c96cb229f1baf4012f365246 # uv 0.12.20
PYTHON_REQUEST=cpython-3.12.14-linux-x86_64-gnu
PYTHON_VERSION=3.12.14

die() {
    /usr/bin/printf '%s\n' "install-python: refusing: $*" >&2
    exit 1
}

case "$#" in 1) ;; *) die "usage: install-python.sh <prefix>" ;; esac
PREFIX=$1
case "$PREFIX" in
    /*) ;;
    *) die "the prefix must be an absolute path" ;;
esac
TARGET=$PREFIX/python
if /usr/bin/test -e "$TARGET" || /usr/bin/test -L "$TARGET"; then
    die "$TARGET already exists: uv would keep an installation it finds there"
fi
case "$0" in
    */*) ;;
    *) die "run it by its path, as install.sh does" ;;
esac
SCRIPTS=$(/usr/bin/readlink -f -- "${0%/*}/..") || die "cannot locate scripts/"
WRAPPER=$SCRIPTS/uv-clean.sh
/usr/bin/test -f "$WRAPPER" || die "$WRAPPER is missing"

# Resolve uv once, from absolute PATH entries only: an empty or relative entry would find
# uv relative to the working directory. A relative answer (a shell function named uv) is
# refused too.
case ":$PATH:" in
    *::*) die "PATH has an empty entry, which is not an absolute path" ;;
esac
IFS_WAS=$IFS
IFS=:
set -f
for entry in $PATH; do
    case "$entry" in
        /*) ;;
        *) die "PATH entry '$entry' is not an absolute path" ;;
    esac
done
set +f
IFS=$IFS_WAS
FOUND=$(command -v uv) || die "uv not found on PATH"
case "$FOUND" in
    /*) ;;
    *) die "uv resolves to '$FOUND', not an absolute path" ;;
esac
UV=$(/usr/bin/readlink -f -- "$FOUND") || die "cannot resolve $FOUND"
# env(1) takes any argument containing '=' before the command for an assignment, so
# uv-clean.sh's `env -i ... "$UV"` would run another program (`python` from PATH).
case "$UV" in
    *=*) die "uv's path $UV contains '=', which env(1) would read as an assignment" ;;
esac
if /usr/bin/test -f "$UV" && /usr/bin/test -x "$UV"; then :; else
    die "uv ($UV) is not a regular executable file"
fi
SUM=$(/usr/bin/sha256sum -- "$UV") || die "cannot hash $UV"
SUM=${SUM%% *}
case "$SUM" in
    "$UV_SHA256") ;;
    *) die "uv ($UV) has sha256 $SUM, not the pinned $UV_SHA256" ;;
esac

/bin/sh "$WRAPPER" --python-install "$UV" python install --no-config \
    --install-dir "$TARGET" --no-bin "$PYTHON_REQUEST" >&2 \
    || die "installing $PYTHON_REQUEST failed"

# Exactly one installation, a real directory; any other cpython-* entry is uv's
# minor-version link to it; uv's own dot entries are not matched by the glob.
DIR=$TARGET/$PYTHON_REQUEST
if /usr/bin/test -d "$DIR" && ! /usr/bin/test -L "$DIR"; then :; else
    die "no installation directory $DIR"
fi
REAL=$(/usr/bin/readlink -f -- "$DIR") || die "cannot resolve $DIR"
for entry in "$TARGET"/*; do
    case "${entry##*/}" in
        "$PYTHON_REQUEST") ;;
        cpython-*)
            /usr/bin/test -L "$entry" || die "a second installation: $entry"
            LINK=$(/usr/bin/readlink -f -- "$entry") || die "cannot resolve $entry"
            case "$LINK" in
                "$REAL") ;;
                *) die "$entry does not point to $DIR" ;;
            esac
            ;;
        *) die "unexpected entry $entry" ;;
    esac
done
PY=$DIR/bin/python3.12
if /usr/bin/test -f "$PY" && ! /usr/bin/test -L "$PY"; then :; else
    die "$PY is not a regular file"
fi
VERSION=$("$PY" -I -S -B -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])') \
    || die "$PY does not run"
case "$VERSION" in
    "$PYTHON_VERSION") ;;
    *) die "$PY reports $VERSION, not $PYTHON_VERSION" ;;
esac
/usr/bin/printf '%s %s\n' "$UV" "$SUM"
