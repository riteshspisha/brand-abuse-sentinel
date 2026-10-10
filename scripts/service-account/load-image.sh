#!/bin/sh
# Load the sandbox image into the service account's daemon from a stream and
# verify its identity (SP1).
#
#   docker --host unix://$XDG_RUNTIME_DIR/docker.sock save brandsentinel-sandbox:local | \
#     sudo systemd-run --user -M brandsentinel@ --wait --pipe --collect \
#       /opt/brandsentinel/src/scripts/service-account/load-image.sh sha256:<expected id>
#
# Streaming: no temporary copy of the image is written anywhere. Refuses to start
# with less than MIN_FREE_GIB free on the daemon's filesystem (measured need:
# ~3.8 GiB for the image in the containerd store, plus unpacking headroom).
set -eu

PREFIX=${PREFIX:-/opt/brandsentinel}
MIN_FREE_GIB=${MIN_FREE_GIB:-8}
EXPECTED=${1:?usage: load-image.sh sha256:<expected image id>}
SOCK=unix://${XDG_RUNTIME_DIR:?run inside the user manager}/docker.sock
die() { echo "load-image: FAIL: $*" >&2; exit 1; }

ROOT=$(docker --host "$SOCK" info --format '{{.DockerRootDir}}')
FREE_KIB=$(df --output=avail -k "$ROOT" | tail -1 | tr -d ' ')
[ "$FREE_KIB" -ge $((MIN_FREE_GIB * 1024 * 1024)) ] \
    || die "only $((FREE_KIB / 1024 / 1024)) GiB free under $ROOT (need $MIN_FREE_GIB)"
echo "load-image: $((FREE_KIB / 1024 / 1024)) GiB free under $ROOT before loading"

docker --host "$SOCK" load
FREE_AFTER=$(df --output=avail -k "$ROOT" | tail -1 | tr -d ' ')
echo "load-image: used $(((FREE_KIB - FREE_AFTER) / 1024)) MiB; $((FREE_AFTER / 1024 / 1024)) GiB free"

"$PREFIX/venv/bin/python" "$PREFIX/src/scripts/service-account/image_manifest.py" \
    --docker-host "$SOCK" --source "$PREFIX/src" --expect-id "$EXPECTED"
