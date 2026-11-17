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
# The same pinned, hash-checked build backend as install.sh (B7 U11), so the image
# wheel and the installed wheel are byte-equal. A missing or mismatched backend fails.
# No uv configuration file or variable may switch off build isolation (which would
# ignore the pin) or hash checks, or change the wheel's timestamps.
env -u UV_NO_BUILD_ISOLATION -u UV_NO_BUILD_ISOLATION_PACKAGE -u UV_NO_VERIFY_HASHES \
    -u UV_CONFIG_FILE -u SOURCE_DATE_EPOCH \
    uv build --no-config --wheel --build-constraints build-constraints.txt --require-hashes \
    --out-dir docker/dist
# The wheel equals install.sh's only when built from the same commit with no local changes.
echo "wheel source: $(git rev-parse HEAD 2>/dev/null || echo unknown)$(
    [ -z "$(git status --porcelain 2>/dev/null)" ] || echo ' + uncommitted changes (not reproducible)')"
# Record the image-path wheel before docker/dist is removed: its sha256 is the value
# image_manifest.py binds with --expect-wheel-sha256. Its backend must be the pinned one.
python3 -I -S - docker/dist build-constraints.txt <<'EOF'
import hashlib, pathlib, re, sys, zipfile
wheels = sorted(pathlib.Path(sys.argv[1]).glob("*.whl"))
if len(wheels) != 1:
    sys.exit(f"refusing: expected one wheel in {sys.argv[1]}, found {len(wheels)}")
pin = re.search(r"^hatchling==(\S+)", pathlib.Path(sys.argv[2]).read_text(), re.M)
with zipfile.ZipFile(wheels[0]) as whl:
    names = [n for n in whl.namelist() if re.fullmatch(r"[^/]+\.dist-info/WHEEL", n)]
    lines = whl.read(names[0]).decode().splitlines() if len(names) == 1 else []
generator = next((x.split(":", 1)[1].strip() for x in lines if x.startswith("Generator:")), "")
print(f"wheel {wheels[0].name} sha256 {hashlib.sha256(wheels[0].read_bytes()).hexdigest()}")
print(f"wheel Generator: {generator or '(missing)'}")
if pin is None or generator != f"hatchling {pin.group(1)}":
    sys.exit("refusing: the wheel was not built by the pinned backend")
EOF
# Only this checkout's committed uv.lock decides the image's dependencies: no uv variable,
# configuration file or ancestor workspace can select another lock (B7 U10). No header:
# it would copy the checkout's absolute path into an image layer.
sh scripts/uv-export-locked.sh . --no-dev --extra sandbox --no-emit-project --no-header \
    --format requirements-txt --output-file docker/dist/requirements.txt >/dev/null
docker build --file docker/Dockerfile.sandbox --tag "$TAG" docker
rm -rf docker/dist
docker image inspect --format 'built {{.Id}} ({{.Size}} bytes)' "$TAG"
