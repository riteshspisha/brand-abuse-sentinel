#!/bin/sh
# Check free disk space before building the sandbox image or installing models.
#
#   scripts/check-disk-budget.sh            # sandbox image budget only
#   MODELS_GIB=8 scripts/check-disk-budget.sh
#
# Measures the filesystems holding the rootless Docker data root and the
# application data directory. Exits 1 when either has less than the budget.
set -eu

IMAGE_GIB=${IMAGE_GIB:-5}        # sandbox image (~4 GiB) plus build layers;
                                 # lower it when the base image is already pulled
MODELS_GIB=${MODELS_GIB:-0}      # Kev-0.8B / Laya weights (M8)
MARGIN_GIB=${MARGIN_GIB:-2}      # headroom kept free for the store and logs
DOCKER_ROOT=${DOCKER_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/docker}
DATA_DIR=${DATA_DIR:-data}

need_gib=$((IMAGE_GIB + MODELS_GIB + MARGIN_GIB))
status=0
for path in "$DOCKER_ROOT" "$DATA_DIR"; do
    probe=$path
    while [ ! -e "$probe" ]; do probe=$(dirname "$probe"); done
    free_kib=$(df -Pk "$probe" | awk 'NR == 2 { print $4 }')
    free_gib=$((free_kib / 1048576))
    if [ "$free_gib" -lt "$need_gib" ]; then
        echo "FAIL $path: ${free_gib} GiB free, need ${need_gib} GiB" \
             "(image ${IMAGE_GIB} + models ${MODELS_GIB} + margin ${MARGIN_GIB})" >&2
        status=1
    else
        echo "ok   $path: ${free_gib} GiB free, need ${need_gib} GiB"
    fi
done
exit "$status"
