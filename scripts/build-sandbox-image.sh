#!/bin/sh
# Build brandsentinel-sandbox:local on the account's rootless Docker.
# Refuses a rootful endpoint: the sandbox runtime must be rootless (R50).
set -eu
cd "$(dirname "$0")/.."

DOCKER_HOST=${DOCKER_HOST:-unix://${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock}
export DOCKER_HOST
TAG=${TAG:-brandsentinel-sandbox:local}

if ! docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
    echo "refusing to build: $DOCKER_HOST is not a rootless Docker endpoint" >&2
    exit 1
fi
scripts/check-disk-budget.sh

rm -rf docker/dist
mkdir -p docker/dist
uv build --wheel --out-dir docker/dist
uv export --frozen --no-dev --extra sandbox --no-emit-project \
    --format requirements-txt --output-file docker/dist/requirements.txt >/dev/null
docker build --file docker/Dockerfile.sandbox --tag "$TAG" docker
rm -rf docker/dist
docker image inspect --format 'built {{.Id}} ({{.Size}} bytes)' "$TAG"
