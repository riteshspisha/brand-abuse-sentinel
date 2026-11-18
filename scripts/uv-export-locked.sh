#!/bin/sh
# Export the dependency set of exactly one project's committed uv.lock (B7 U10).
#
#   scripts/uv-export-locked.sh <project dir> <uv export selection and format options>
#
# The project's pyproject.toml and uv.lock are the only inputs. Left to itself, uv
# follows UV_PROJECT or UV_WORKING_DIR to another project, drops the dev group on
# UV_NO_DEV, and exports the lock of a workspace declared in an ancestor directory, all
# with exit 0. So every UV_* variable is cleared, no uv configuration file is read and no
# cache is used, the project is named by its absolute physical path, the lock is used as
# committed and offline, and a pyproject.toml in any ancestor directory (logical or
# physical path) is refused. scripts/build-sandbox-image.sh and
# scripts/service-account/install.sh export through this script; image_manifest.py
# applies the same rules in Python.
set -eu
die() { echo "uv-export-locked: refusing: $*" >&2; exit 1; }
[ "$#" -ge 1 ] || die "usage: uv-export-locked.sh <project dir> <uv export options>"
PROJECT=$1
shift
case "$PROJECT" in
    '' | -*) die "the project directory must not be empty or start with '-'" ;;
esac
NL='
'
case "$PROJECT" in *"$NL"*) die "the project directory must not contain a newline" ;; esac
[ -f "$PROJECT/pyproject.toml" ] && [ -f "$PROJECT/uv.lock" ] \
    || die "$PROJECT has no pyproject.toml and uv.lock"
LOGICAL=$(CDPATH='' cd -- "$PROJECT" && pwd -L)
PHYSICAL=$(CDPATH='' cd -- "$PROJECT" && pwd -P)
for dir in "$LOGICAL" "$PHYSICAL"; do
    while [ "$dir" != / ]; do
        dir=$(dirname -- "$dir")
        if [ -e "$dir/pyproject.toml" ] || [ -L "$dir/pyproject.toml" ]; then
            die "$dir/pyproject.toml above the project could make uv export another workspace's lock"
        fi
    done
done
for name in $(env | sed -n 's/^\(UV_[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$name"
done
exec uv export --no-config --no-cache --project "$PHYSICAL" --frozen --offline "$@"
