#!/bin/sh
# Build the service installation in /opt/brandsentinel (SP1, R50).
#
# Run as the DEVELOPER, unprivileged, while root has temporarily handed an EMPTY
# /opt/brandsentinel to you. Root then takes ownership of everything, so the
# service account can read but never modify its code (see
# docs/runbooks/service-account.md for the full sequence).
#
# Layout:
#   /opt/brandsentinel/src          `git archive` of the committed HEAD
#   /opt/brandsentinel/python       CPython 3.12.14 from the pinned uv's built-in download
#                                   list (install-python.sh, B7 U16)
#   /opt/brandsentinel/venv         hash-pinned dependencies from uv.lock + the package
#                                   (non-editable) + the dev group, for validation
#   /opt/brandsentinel/bin          dockerd-rootless.sh (pinned to Docker 29.9.0, sha256 checked)
#   /opt/brandsentinel/etc          service.yaml (no developer override)
#   /opt/brandsentinel/INSTALL      what was installed, from which commit; published last,
#                                   so its presence means that the install completed
set -eu
# Copy, never hardlink, from the developer's uv cache: a hardlinked file shares
# its inode with the cache, and the later `chown -R root` would change the
# ownership of the developer's own cache files too.
export UV_LINK_MODE=copy

PREFIX=${PREFIX:-/opt/brandsentinel}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
DOCKERD_ROOTLESS_SHA256=200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488
DOCKERD_ROOTLESS_URL=https://raw.githubusercontent.com/moby/moby/docker-v29.9.0/contrib/dockerd-rootless.sh

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run as the developer, not root"
[ -d "$PREFIX" ] && [ -w "$PREFIX" ] || die "$PREFIX must exist and be writable by you (see the runbook)"
[ -z "$(ls -A "$PREFIX")" ] || die "$PREFIX is not empty"
[ -z "$(git -C "$REPO" status --porcelain)" ] || die "uncommitted changes in $REPO: install only a commit"
command -v uv >/dev/null || die "uv not found"
COMMIT=$(git -C "$REPO" rev-parse HEAD)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "install: source $COMMIT -> $PREFIX/src"
mkdir "$PREFIX/src"
git -C "$REPO" archive --format=tar "$COMMIT" | tar -x -C "$PREFIX/src"

echo "install: python 3.12.14 -> $PREFIX/python"
# Only the archive the pinned uv's built-in download list names: no uv variable,
# configuration file, mirror or other download list can choose it, and the uv that runs is
# the one checked against the pin. Prints that uv's path and sha256 (B7 U16, X21).
# The step starts from an allow-listed environment (uv-clean.sh's list), by absolute
# paths: bash, as sh, would apply an inherited SHELLOPTS, BASHOPTS, PS4 or exported
# function, and the loader LD_* variables, before the step's first line could check.
UV_RECORD=$(/usr/bin/env -i \
    ${PATH+"PATH=$PATH"} ${HOME+"HOME=$HOME"} ${TMPDIR+"TMPDIR=$TMPDIR"} \
    ${XDG_DATA_HOME+"XDG_DATA_HOME=$XDG_DATA_HOME"} \
    ${XDG_CACHE_HOME+"XDG_CACHE_HOME=$XDG_CACHE_HOME"} \
    ${UV_OFFLINE+"UV_OFFLINE=$UV_OFFLINE"} ${UV_CACHE_DIR+"UV_CACHE_DIR=$UV_CACHE_DIR"} \
    ${UV_LINK_MODE+"UV_LINK_MODE=$UV_LINK_MODE"} \
    ${UV_PYTHON_CACHE_DIR+"UV_PYTHON_CACHE_DIR=$UV_PYTHON_CACHE_DIR"} \
    ${HTTP_PROXY+"HTTP_PROXY=$HTTP_PROXY"} ${HTTPS_PROXY+"HTTPS_PROXY=$HTTPS_PROXY"} \
    ${NO_PROXY+"NO_PROXY=$NO_PROXY"} ${ALL_PROXY+"ALL_PROXY=$ALL_PROXY"} \
    ${http_proxy+"http_proxy=$http_proxy"} ${https_proxy+"https_proxy=$https_proxy"} \
    ${no_proxy+"no_proxy=$no_proxy"} ${all_proxy+"all_proxy=$all_proxy"} \
    ${SSL_CERT_FILE+"SSL_CERT_FILE=$SSL_CERT_FILE"} ${SSL_CERT_DIR+"SSL_CERT_DIR=$SSL_CERT_DIR"} \
    /bin/sh "$PREFIX/src/scripts/service-account/install-python.sh" "$PREFIX") \
    || die "the Python step refused or failed (see above); rebuild from an empty $PREFIX"
PY=$PREFIX/python/cpython-3.12.14-linux-x86_64-gnu/bin/python3.12

echo "install: venv -> $PREFIX/venv"
# Every uv call that creates, fills or builds for the installation runs through
# uv-clean.sh, without the caller's uv, Python or backend settings and with --no-config:
# UV_EXCLUDE would drop a pinned package, UV_COMPILE_BYTECODE or a uv.toml would add
# bytecode, UV_PROJECT would build another project (B7 U10).
sh "$PREFIX/src/scripts/uv-clean.sh" venv --no-config --python "$PY" "$PREFIX/venv"
# Only the installed source's committed uv.lock decides the installed dependencies: no uv
# variable (UV_NO_DEV would drop the dev group), configuration file or ancestor workspace
# can change them (B7 U10).
sh "$PREFIX/src/scripts/uv-export-locked.sh" "$PREFIX/src" --group dev --no-emit-project \
    --format requirements-txt --output-file "$STAGE/requirements.txt" >/dev/null
sh "$PREFIX/src/scripts/uv-clean.sh" pip install --no-config --python "$PREFIX/venv/bin/python" \
    --require-hashes --requirement "$STAGE/requirements.txt"
# The pinned, hash-checked build backend (B7 U11), with the same command as
# build-sandbox-image.sh, so this wheel equals the image's. A mismatch fails, and no uv
# configuration file or caller setting may switch off build isolation or hash checks.
(cd "$PREFIX/src" && sh scripts/uv-clean.sh build --no-config --wheel \
    --build-constraints build-constraints.txt --require-hashes \
    --out-dir "$STAGE/dist" >/dev/null) \
    || die "wheel build with the pinned backend (build-constraints.txt) failed; rebuild from an empty $PREFIX"
sh "$PREFIX/src/scripts/uv-clean.sh" pip install --no-config --python "$PREFIX/venv/bin/python" \
    --no-deps "$STAGE"/dist/*.whl

echo "install: dockerd-rootless.sh -> $PREFIX/bin"
mkdir "$PREFIX/bin"
SRC=${DOCKERD_ROOTLESS_SH:-$HOME/.local/bin/dockerd-rootless.sh}
if [ -f "$SRC" ]; then
    cp "$SRC" "$STAGE/dockerd-rootless.sh"
else
    curl -fsSL -o "$STAGE/dockerd-rootless.sh" "$DOCKERD_ROOTLESS_URL"
fi
echo "$DOCKERD_ROOTLESS_SHA256  $STAGE/dockerd-rootless.sh" | sha256sum -c --quiet \
    || die "dockerd-rootless.sh checksum mismatch"
install -m 0755 "$STAGE/dockerd-rootless.sh" "$PREFIX/bin/dockerd-rootless.sh"

echo "install: config -> $PREFIX/etc/service.yaml"
mkdir "$PREFIX/etc"
install -m 0644 "$PREFIX/src/config/service.yaml" "$PREFIX/etc/service.yaml"

echo "install: launchers and bytecode (B2)"
"$PREFIX/src/scripts/service-account/harden-bytecode.sh" "$PREFIX" \
    || die "bytecode hardening failed"

"$PREFIX/venv/bin/brandsentinel" version >/dev/null || die "installed CLI does not run"
# Nothing may share an inode with a file outside the install (see UV_LINK_MODE).
[ -z "$(find "$PREFIX" -type f -links +1 | head -1)" ] || die "hardlinked files under $PREFIX"
# The interpreter must live inside the install, not in the developer's home.
case "$(readlink -f "$PREFIX/venv/bin/python")" in
    "$PREFIX"/*) ;;
    *) die "venv interpreter resolves outside $PREFIX" ;;
esac
# The last check, so that it also sees anything the steps above wrote.
"$PREFIX/venv/bin/python" -I -B -S "$PREFIX/src/scripts/service-account/check_bytecode.py" "$PREFIX" \
    || die "bytecode verification failed: this installation is not complete"

WHEEL=$(sha256sum "$STAGE"/dist/*.whl | cut -d' ' -f1)
cat > "$STAGE/INSTALL" <<EOF
commit: $COMMIT
installed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
installed_by: $(id -un)
python: $("$PREFIX/venv/bin/python" -I -B -S -c 'import sys; print(sys.version.split()[0])')
wheel_sha256: $WHEEL
uv_lock_sha256: $(sha256sum "$PREFIX/src/uv.lock" | cut -d' ' -f1)
dockerd_rootless_sha256: $DOCKERD_ROOTLESS_SHA256
uv: $UV_RECORD
EOF
# Published by rename, after every check: a partial install has no record.
cp "$STAGE/INSTALL" "$PREFIX/.INSTALL.tmp"
mv "$PREFIX/.INSTALL.tmp" "$PREFIX/INSTALL"

echo
cat "$PREFIX/INSTALL"
echo
echo "install: done. Now, as root:  sudo chown -R root:root $PREFIX && sudo chmod -R go-w $PREFIX"
