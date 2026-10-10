#!/bin/sh
# Start the service account's own rootless Docker daemon (SP1, R50).
#
# Run AS the `brandsentinel` account INSIDE its systemd user manager, e.g.:
#   sudo systemd-run --user -M brandsentinel@ --wait --pipe --collect \
#     /opt/brandsentinel/src/scripts/service-account/setup-rootless.sh
# (no login shell is needed; the manager sets XDG_RUNTIME_DIR and the cgroup).
#
# Verifies the prerequisites first and changes nothing if one is missing. It
# writes one user unit in the account's own home and starts it; nothing outside
# the account is touched.
set -eu

PREFIX=${PREFIX:-/opt/brandsentinel}
ACCOUNT=${BRANDSENTINEL_ACCOUNT:-brandsentinel}
die() { echo "setup-rootless: FAIL: $*" >&2; exit 1; }
ok() { echo "setup-rootless: ok: $*"; }

[ "$(id -un)" = "$ACCOUNT" ] || die "run as $ACCOUNT (now $(id -un))"
UID_=$(id -u)
[ "${XDG_RUNTIME_DIR:-}" = "/run/user/$UID_" ] && [ -d "$XDG_RUNTIME_DIR" ] \
    || die "XDG_RUNTIME_DIR is not /run/user/$UID_: run inside the user manager (systemd-run --user -M $ACCOUNT@)"
ok "user manager runtime dir $XDG_RUNTIME_DIR"

case " $(id -nG) " in *" docker "*) die "$ACCOUNT is in the docker group" ;; esac
ok "not in the docker group"
for s in /run/docker.sock /var/run/docker.sock; do
    if [ -e "$s" ] && [ -r "$s" ] && [ -w "$s" ]; then die "rootful socket $s is accessible"; fi
done
ok "no access to a rootful Docker socket"

grep -q "^$ACCOUNT:" /etc/subuid || die "no subordinate UID range in /etc/subuid"
grep -q "^$ACCOUNT:" /etc/subgid || die "no subordinate GID range in /etc/subgid"
ok "subordinate ranges: $(grep "^$ACCOUNT:" /etc/subuid | cut -d: -f2-) / $(grep "^$ACCOUNT:" /etc/subgid | cut -d: -f2-)"

CG=/sys/fs/cgroup/user.slice/user-$UID_.slice/user@$UID_.service/cgroup.controllers
for c in cpu memory pids; do
    grep -qw "$c" "$CG" || die "cgroup controller $c is not delegated ($CG: $(cat "$CG"))"
done
ok "delegated cgroup controllers: $(cat "$CG")"

[ -x "$PREFIX/bin/dockerd-rootless.sh" ] || die "$PREFIX/bin/dockerd-rootless.sh missing"
[ "$(stat -c %U "$PREFIX/bin/dockerd-rootless.sh")" = root ] || die "$PREFIX is not root-owned yet"
if [ -w "$PREFIX/bin/dockerd-rootless.sh" ] || [ -w "$PREFIX/src" ] || [ -w "$PREFIX/venv" ]; then
    die "$ACCOUNT can modify $PREFIX"
fi
ok "$PREFIX is root-owned and read-only to $ACCOUNT"
for b in rootlesskit slirp4netns newuidmap newgidmap docker; do
    command -v "$b" >/dev/null || die "$b not found"
done

UNIT_DIR=$HOME/.config/systemd/user
mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/docker-rootless.service" <<EOF
[Unit]
Description=Rootless Docker for BrandSentinel sandboxes (service account)

[Service]
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=$PREFIX/bin/dockerd-rootless.sh
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
Type=notify
NotifyAccess=all
KillMode=mixed

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now docker-rootless.service
ok "docker-rootless.service enabled and started"

SOCK=unix://$XDG_RUNTIME_DIR/docker.sock
i=0
until docker --host "$SOCK" info >/dev/null 2>&1; do
    i=$((i + 1)); [ $i -lt 60 ] || die "daemon did not answer on $SOCK"; sleep 1
done
docker --host "$SOCK" info --format '{{json .SecurityOptions}}' | grep -q name=rootless \
    || die "daemon at $SOCK is not rootless"
ok "rootless daemon: $(docker --host "$SOCK" info --format 'Docker {{.ServerVersion}}, cgroup v{{.CgroupVersion}} ({{.CgroupDriver}}), storage {{.Driver}}, root {{.DockerRootDir}}')"
