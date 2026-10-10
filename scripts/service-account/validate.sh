#!/bin/sh
# SP1 acceptance under the dedicated service account.
#
#   sudo systemd-run --user -M brandsentinel@ --wait --pipe --collect \
#     /opt/brandsentinel/src/scripts/service-account/validate.sh
#
# 1. account: not root, not in `docker`, no rootful socket, cannot modify the
#    installed application, config without the developer override;
# 2. the production sandbox stack on the account's own rootless daemon;
# 3. `brandsentinel sandbox check --strict` (no failures, no warnings);
# 4. every security and real-container suite (`-m "security or docker"`), with
#    any skipped test counted as a failure.
#
# Needs 127.0.0.1:3129 free (the lab proxy's published port): stop any other
# account's lab first. The account's lab is stopped again at the end; its
# sandbox stack keeps running. Results: stdout and ~/sp1-validation-<time>/.
set -u

PREFIX=${PREFIX:-/opt/brandsentinel}
ACCOUNT=${BRANDSENTINEL_ACCOUNT:-brandsentinel}
SOCK=unix://${XDG_RUNTIME_DIR:?run inside the user manager}/docker.sock
OUT=$HOME/sp1-validation-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"
FAILED=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }
check() { desc=$1; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
not() { ! "$@"; }

echo "== SP1 validation as $(id -un) (uid $(id -u)), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "== install: $(tr '\n' ' ' < "$PREFIX/INSTALL")"

echo "== 1. account"
check "running as $ACCOUNT" test "$(id -un)" = "$ACCOUNT"
check "not root" test "$(id -u)" -ne 0
check "not in the docker group ($(id -nG))" not sh -c 'id -nG | tr " " "\n" | grep -qx docker'
for s in /run/docker.sock /var/run/docker.sock; do
    check "cannot open rootful socket $s" not sh -c "test -r $s && test -w $s"
done
check "rootful daemon refuses this account" not docker --host unix:///run/docker.sock info
check "$PREFIX owned by root" test "$(stat -c %U "$PREFIX")" = root
WRITABLE=$(find "$PREFIX" -writable 2>/dev/null | head -5)
check "nothing under $PREFIX is writable (${WRITABLE:-none})" test -z "$WRITABLE"
check "cannot create files in $PREFIX/src" not touch "$PREFIX/src/.sp1-write-test"
check "service config has no developer override" \
    not grep -q allow_developer_account "$PREFIX/etc/service.yaml"
check "code owner is not this account" \
    test "$(stat -c %u "$("$PREFIX/venv/bin/python" -c 'import brandsentinel,os;print(os.path.dirname(brandsentinel.__file__))')")" != "$(id -u)"

echo "== 2. sandbox stack on $SOCK"
check "daemon is rootless" sh -c "docker --host $SOCK info --format '{{json .SecurityOptions}}' | grep -q name=rootless"
cd "$PREFIX/src" || exit 2
docker --host "$SOCK" compose -f docker/compose.yaml --profile sandbox up -d >"$OUT/compose.log" 2>&1 \
    && pass "compose --profile sandbox up" || fail "compose --profile sandbox up (see $OUT/compose.log)"
docker --host "$SOCK" network inspect bs_sandbox \
    --format 'bs_sandbox: internal={{.Internal}} options={{json .Options}} ipam={{json .IPAM.Config}}'
if ss -ltnH 'sport = :3129' | grep -q .; then
    fail "127.0.0.1:3129 is in use (stop the other account's lab: docker compose -f docker/lab.compose.yaml stop)"
fi

echo "== 3. sandbox check --strict"
"$PREFIX/venv/bin/brandsentinel" -c "$PREFIX/etc/service.yaml" sandbox check --strict \
    2>&1 | tee "$OUT/sandbox-check.txt"
check "sandbox check --strict" sh -c \
    "'$PREFIX/venv/bin/brandsentinel' -c '$PREFIX/etc/service.yaml' sandbox check --strict"

echo "== 4. security and real-container suites"
PYTHONDONTWRITEBYTECODE=1 DOCKER_HOST=$SOCK "$PREFIX/venv/bin/python" -m pytest \
    -p no:cacheprovider -m "security or docker" -rs -q \
    --junitxml="$OUT/junit.xml" tests 2>&1 | tee "$OUT/pytest.txt" | tail -25
"$PREFIX/venv/bin/python" - "$OUT/junit.xml" <<'EOF' || FAILED=1
import sys, xml.etree.ElementTree as ET
s = ET.parse(sys.argv[1]).getroot()
s = s if s.tag == "testsuite" else s.find("testsuite")
n, f, e, k = (int(s.get(a, 0)) for a in ("tests", "failures", "errors", "skipped"))
print(f"{'PASS' if f + e + k == 0 and n else 'FAIL'}  pytest: {n} tests, {f} failed, {e} errors, {k} skipped")
sys.exit(0 if f + e + k == 0 and n else 1)
EOF

docker --host "$SOCK" compose -f docker/lab.compose.yaml stop >/dev/null 2>&1 || true

echo "== results in $OUT"
if [ "$FAILED" -eq 0 ]; then echo "SP1 VALIDATION: PASS"; else echo "SP1 VALIDATION: FAIL"; fi
exit "$FAILED"
