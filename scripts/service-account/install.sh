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
#   /opt/brandsentinel/python       uv-managed CPython 3.12 (checksum-verified download)
#   /opt/brandsentinel/venv         hash-pinned dependencies from uv.lock + the package
#                                   (non-editable) + the dev group, for validation
#   /opt/brandsentinel/bin          dockerd-rootless.sh (pinned to Docker 29.9.0, sha256 checked)
#   /opt/brandsentinel/etc          service.yaml (no developer override)
#   /opt/brandsentinel/INSTALL      what was installed, from which commit
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

echo "install: python 3.12 -> $PREFIX/python"
uv python install --install-dir "$PREFIX/python" --no-bin 3.12
PY=$(find "$PREFIX/python" -maxdepth 3 -path '*/bin/python3.12' -type f | head -1)
[ -n "$PY" ] || die "managed python not found under $PREFIX/python"

echo "install: venv -> $PREFIX/venv"
uv venv --python "$PY" "$PREFIX/venv"
(cd "$PREFIX/src" && uv export --frozen --group dev --no-emit-project \
    --format requirements-txt --output-file "$STAGE/requirements.txt" >/dev/null)
uv pip install --python "$PREFIX/venv/bin/python" --require-hashes \
    --requirement "$STAGE/requirements.txt"
(cd "$PREFIX/src" && uv build --wheel --out-dir "$STAGE/dist" >/dev/null)
uv pip install --python "$PREFIX/venv/bin/python" --no-deps "$STAGE"/dist/*.whl

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

WHEEL=$(sha256sum "$STAGE"/dist/*.whl | cut -d' ' -f1)
cat > "$PREFIX/INSTALL" <<EOF
commit: $COMMIT
installed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
installed_by: $(id -un)
python: $("$PREFIX/venv/bin/python" -c 'import sys; print(sys.version.split()[0])')
wheel_sha256: $WHEEL
uv_lock_sha256: $(sha256sum "$PREFIX/src/uv.lock" | cut -d' ' -f1)
dockerd_rootless_sha256: $DOCKERD_ROOTLESS_SHA256
EOF
"$PREFIX/venv/bin/brandsentinel" version >/dev/null || die "installed CLI does not run"
# Nothing may share an inode with a file outside the install (see UV_LINK_MODE).
[ -z "$(find "$PREFIX" -type f -links +1 | head -1)" ] || die "hardlinked files under $PREFIX"
# The interpreter must live inside the install, not in the developer's home.
case "$(readlink -f "$PREFIX/venv/bin/python")" in
    "$PREFIX"/*) ;;
    *) die "venv interpreter resolves outside $PREFIX" ;;
esac

echo
cat "$PREFIX/INSTALL"
echo
echo "install: done. Now, as root:  sudo chown -R root:root $PREFIX && sudo chmod -R go-w $PREFIX"
