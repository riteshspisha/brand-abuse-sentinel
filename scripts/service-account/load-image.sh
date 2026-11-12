#!/bin/sh
# Load the sandbox image into the service account's daemon from a stream and
# verify its identity (SP1).
#
#   docker --host unix://$XDG_RUNTIME_DIR/docker.sock save brandsentinel-sandbox:local | \
#     as-account /opt/brandsentinel/src/scripts/service-account/load-image.sh sha256:<expected id>
#
# The expected ID must come from the sealed, approved build record (runbook step 1).
# The check addresses the loaded image by that ID, whatever tag the stream carries. For
# a promotion, stream it under a release tag (B7 plan G1) and retag :local only after a
# pass (G5). Loading is not transactional: the image is loaded, and tagged as the
# stream says, before it is verified. A failed check exits non-zero but leaves it
# loaded and tagged (an open promotion gate; see the runbook).
#
# (as-account: the launch chain in docs/runbooks/service-account.md)
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
VERIFIER=$PREFIX/src/scripts/service-account/image_manifest.py

# Refuse before loading anything. The whole value is checked (not line by line).
BADID="the expected image ID must be sha256:<64 hex digits>"
case "$EXPECTED" in
    sha256:*) HEX=${EXPECTED#sha256:} ;;
    *) die "$BADID" ;;
esac
[ "${#HEX}" -eq 64 ] || die "$BADID"
case "$HEX" in *[!0-9a-f]*) die "$BADID" ;; esac
[ -x "$PREFIX/venv/bin/python" ] || die "no interpreter at $PREFIX/venv/bin/python"
[ -f "$VERIFIER" ] || die "no verifier at $VERIFIER"

ROOT=$(docker --host "$SOCK" info --format '{{.DockerRootDir}}')
FREE_KIB=$(df --output=avail -k "$ROOT" | tail -1 | tr -d ' ')
[ "$FREE_KIB" -ge $((MIN_FREE_GIB * 1024 * 1024)) ] \
    || die "only $((FREE_KIB / 1024 / 1024)) GiB free under $ROOT (need $MIN_FREE_GIB)"
echo "load-image: $((FREE_KIB / 1024 / 1024)) GiB free under $ROOT before loading"

LOADED=$(docker --host "$SOCK" load) || die "docker load failed; what it loaded is unverified"
printf '%s\n' "$LOADED"
# Every image the stream loaded, by tag or by ID, must be the expected one; otherwise a
# tag would now name an image this script never verifies.
FOUND=0
for REF in $(printf '%s\n' "$LOADED" | sed -n 's/^Loaded image\( ID\)\{0,1\}: //p'); do
    FOUND=1
    ID=$(docker --host "$SOCK" image inspect --format '{{.Id}}' "$REF") \
        || die "cannot inspect $REF, which the stream loaded; it may name an unverified image"
    [ "$ID" = "$EXPECTED" ] \
        || die "the stream loaded $REF as $ID, not the expected image; $REF now names an unverified image"
done
[ "$FOUND" -eq 1 ] || die "docker load reported no loaded image"
FREE_AFTER=$(df --output=avail -k "$ROOT" | tail -1 | tr -d ' ') || FREE_AFTER=
case "$FREE_AFTER" in
    '' | *[!0-9]*) echo "load-image: free space after loading unknown" ;;
    *) echo "load-image: used $(((FREE_KIB - FREE_AFTER) / 1024)) MiB; $((FREE_AFTER / 1024 / 1024)) GiB free" ;;
esac

RC=0
"$PREFIX/venv/bin/python" -I -B "$VERIFIER" \
    --profile load --docker-host "$SOCK" --source "$PREFIX/src" --installed "$PREFIX" \
    --image "$EXPECTED" --expect-id "$EXPECTED" || RC=$?
if [ "$RC" -ne 0 ]; then
    LOCAL=$(docker --host "$SOCK" image inspect --format '{{.Id}}' \
        brandsentinel-sandbox:local 2>/dev/null || true)
    if [ "$LOCAL" = "$EXPECTED" ]; then
        echo "load-image: WARNING: brandsentinel-sandbox:local now names this unverified" \
            "image; sandbox stages must not run until it is resolved" >&2
    fi
    echo "load-image: FAIL: image verification exited $RC; the image stays loaded" >&2
    exit "$RC"
fi
