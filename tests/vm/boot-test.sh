#!/bin/bash
# Boot a Sparewall image in a VM and check bootstrap mode, a first apply
# confirmed over a fresh connection, and the automatic revert of an
# unconfirmed change.
#
#   tests/vm/boot-test.sh IMAGE [WORKDIR]
#
# Needs root (podman for bootc-image-builder, KVM), qemu-system-x86_64,
# swtpm and OVMF (the node boots UEFI with a TPM 2.0, so secrets are
# sealed to it).
set -euo pipefail

IMAGE=${1:?usage: boot-test.sh IMAGE [WORKDIR]}
WORK=${2:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
SSH_PORT=${SSH_PORT:-2222}
MAC=52:54:00:12:34:56
mkdir -p "$WORK/output"
cd "$WORK"

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
trap 'dump' ERR

log "building a qcow2 from $IMAGE"
"$HERE/build-disk.sh" "$IMAGE" "$WORK"
cp output/qcow2/disk.qcow2 vm.qcow2

# shellcheck source=conformance.sh
. "$HERE/conformance.sh"
setup_trunk

log "booting"
rm -f id_ed25519 id_ed25519.pub
ssh-keygen -q -t ed25519 -N '' -f id_ed25519
cat > identity.json <<JSON
{"node": "fw1", "ssh_keys": ["$(cat id_ed25519.pub)"], "management": {"nic": "$MAC"}}
JSON
CRED=$(base64 -w0 identity.json)
# A software TPM 2.0 for the node; it ends when QEMU does. A new state
# directory is a new TPM, as on reinstalled hardware.
start_tpm() {
    rm -rf tpm tpm.sock
    mkdir tpm
    swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
        --ctrl type=unixio,path="$WORK/tpm.sock" --terminate --daemon
    local deadline=$((SECONDS + 10))
    until [ -S tpm.sock ]; do
        [ $SECONDS -lt $deadline ] || fail "swtpm did not start"
        sleep 0.2
    done
}
# UEFI, as on real nodes: the firmware's TPM event log is part of what
# systemd checks before it seals to the TPM.
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
start_vm() {
    start_tpm
    # The firmware's variables are the machine's own: fresh for a new
    # install, kept across a reboot (QEMU keeps running).
    cp "$OVMF_VARS" efivars.fd
    sudo qemu-system-x86_64 \
        -machine q35,accel=kvm -cpu host -m 2048 -smp 2 \
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive if=pflash,format=raw,file=efivars.fd \
        -drive file=vm.qcow2,if=virtio,format=qcow2 \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
        -device "virtio-net-pci,netdev=n0,mac=$MAC" \
        -netdev tap,id=n1,ifname=swtap0,script=no,downscript=no \
        -device virtio-net-pci,netdev=n1,mac=52:54:00:12:34:57 \
        -chardev "socket,id=chrtpm,path=$WORK/tpm.sock" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0 \
        -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$CRED" \
        -display none -serial file:serial.log \
        -pidfile qemu.pid -daemonize
}
start_vm

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        vm 'systemctl --failed --no-legend; sudo journalctl -b -u sparewall-early -u sparewalld -u systemd-networkd --no-pager | tail -80' 2>/dev/null || true
    fi
    if [ -f qemu.pid ]; then sudo kill "$(sudo cat qemu.pid)" 2>/dev/null || true; fi
    pkill -f "tpmstate dir=$WORK/tpm" 2>/dev/null || true
    if [ -f rest-server.pid ]; then kill "$(cat rest-server.pid)" 2>/dev/null || true; fi
    sudo chmod a+r serial.log 2>/dev/null || true
}
trap cleanup EXIT

SSH=(ssh -p "$SSH_PORT" -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR
     admin@127.0.0.1)
vm() { "${SSH[@]}" "$@"; }

dump() {
    echo "--- serial console (last 150 lines)"
    sudo tail -150 serial.log || true
}

wait_ssh() {
    local deadline=$((SECONDS + ${1:-600}))
    until vm true 2>/dev/null; do
        [ $SECONDS -lt $deadline ] || { dump; fail "no SSH"; }
        sleep 5
    done
}
wait_ssh 900
log "up: $(vm uname -r)"
full_audit vm fw1

vm 'systemctl is-system-running --wait' || {
    vm 'systemctl --failed --no-legend'
    vm 'sudo journalctl -b -p warning --no-pager | tail -100'
}
vm 'sudo journalctl -b -u sparewall-early -u sparewalld --no-pager | tail -40'

log "bootstrap mode"
vm 'sudo sparewall status'
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .role status.json)" = bootstrap ] || fail "expected bootstrap role"
vm 'sudo nft list table inet sparewall' | grep -q anti-lockout || fail "no anti-lockout rule"
vm 'ip -br link' | grep -q '^mgmt0 ' || fail "management port not named mgmt0"
# The node name is the hostname (#109): running, static, in the journal.
[ "$(vm hostname)" = fw1 ] || fail "hostname is $(vm hostname), not fw1"
[ "$(vm 'hostnamectl hostname --static')" = fw1 ] || fail "the static hostname is not fw1"
vm 'logger -t sparewall-hostname-check here'
host=$(vm 'sudo journalctl -b -t sparewall-hostname-check -o json -n 1' | jq -r ._HOSTNAME)
[ "$host" = fw1 ] || fail "the journal records hostname $host, not fw1"

# The login banner (#83): written within seconds of a change, and shown
# by pam_motd to an interactive login.
banner() { vm 'cat /run/motd.d/50-sparewall' 2>/dev/null; }
wait_banner() { # what (a fixed string), [not]
    local deadline=$((SECONDS + 30))
    while :; do
        if [ "${2:-}" = not ]; then ! banner | grep -qF "$1" && return; else banner | grep -qF "$1" && return; fi
        [ $SECONDS -lt $deadline ] || fail "login banner: ${2:+no }'$1' expected, got: $(banner)"
        sleep 2
    done
}
wait_banner "Sparewall fw1: bootstrap, generation 0"
echo exit | "${SSH[@]}" -tt 2>/dev/null | tr -d '\r' | grep -q '^Sparewall fw1: bootstrap' \
    || fail "an interactive login does not show the banner"
echo exit | "${SSH[@]}" -tt 2>/dev/null | tr -d '\r' | grep -q 'admin@fw1' \
    || fail "the shell prompt does not show the node name"
if ! vm 'sudo podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage image exists $(sed -n "s/^Image=//p" /usr/share/containers/systemd/sparewall-kea.container)'; then
    vm 'set -x; sed -n "s/^Image=//p" /usr/share/containers/systemd/sparewall-kea.container
        ls -la /usr/lib/bootc/ /sysroot/ostree/bootc/ 2>&1; sudo ls -la /usr/lib/bootc/storage/ 2>&1
        sudo podman images --all 2>&1; sudo podman --storage-opt additionalimagestore=/usr/lib/bootc/storage images 2>&1
        sudo podman info --format "{{json .Store}}" 2>&1 | head -c 2000; echo
        cat /etc/containers/storage.conf; sudo bootc status 2>&1 | head -40
        sudo journalctl -b --no-pager | grep -i bound | tail -20' || true
    fail "the bound Kea image is not visible to podman"
fi

log "first apply, confirmed over a fresh connection"
vm 'cat > /tmp/site.yaml' < "$HERE/site.yaml"
# The port is renamed (mgmt0 -> uplink), which may cut this session.
vm 'sudo sparewall apply -f /tmp/site.yaml --confirm 180 --no-prompt' || true
sleep 5
wait_ssh 120
vm 'sudo sparewall status'
vm 'sudo sparewall confirm'
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .sync.active status.json)" = 1 ] || fail "generation 1 not active"
[ "$(jq -r .sync.confirmed status.json)" = 1 ] || fail "generation 1 not confirmed"
[ "$(jq -r .health.level status.json)" = ok ] || fail "health not ok: $(jq -c .health status.json)"
vm 'ip -br link' | grep -q '^uplink ' || fail "port not renamed to uplink"
vm 'sudo nft list chain inet sparewall in_mgmt' | grep -q 'rule:mgmt->self:ping' || fail "policy not loaded"
wait_banner "Sparewall fw1: standalone, generation 1, health ok"

log "an unconfirmed change reverts"
vm 'sudo sparewall set "policy.mgmt->self.action=reject" --confirm 15 --no-prompt'
vm 'sudo sparewall get "policy.mgmt->self.action"' | grep -q reject || fail "change not applied"
wait_banner "generation 2 (pending confirmation)"
sleep 25
vm 'sudo sparewall get "policy.mgmt->self.action"' | grep -q drop || fail "change not reverted"
wait_banner "pending confirmation" not
vm 'sudo sparewall history'

log "a secret sealed to the TPM"
vm 'sudo systemd-analyze has-tpm2' || fail "the node cannot seal to its TPM"
printf %s 's3cret' | vm 'sudo sparewall secret set log-token'

log "the configuration survives a reboot"
vm 'sudo systemctl reboot' || true
sleep 15
wait_ssh 600
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .sync.active status.json)" = 1 ] || fail "generation 1 not active after reboot"
vm 'ip -br link' | grep -q '^uplink ' || fail "port not named uplink after reboot"
# From /etc/hostname at boot, before sparewalld runs: the early unit,
# which starts before it, logs under the node name already.
host=$(vm 'sudo journalctl -b -u sparewall-early -o json | head -1' | jq -r ._HOSTNAME)
[ "$host" = fw1 ] || fail "sparewall-early logged under hostname $host, not fw1"
# udev names the port at coldplug; sparewalld should not have to.
if vm 'sudo journalctl -b -u sparewalld --no-pager' | grep -q 'renaming interface'; then
    fail "the port was renamed late, by sparewalld, not at coldplug"
fi
[ "$(jq -r .health.level status.json)" = ok ] || fail "health not ok after reboot: $(jq -c .health status.json)"

log "metrics, with host metrics from node_exporter"
token=$(vm 'sudo sparewall token create ci-monitor --role monitor -q')
# node_exporter may still be starting after the reboot above.
deadline=$((SECONDS + 60))
while :; do
    vm "curl -sfk -H 'Authorization: Bearer $token' https://localhost/metrics" > metrics.txt \
        || fail "/metrics refused a monitor token"
    grep -q '^node_network_receive_bytes_total{device="uplink"}' metrics.txt && break
    [ $SECONDS -lt $deadline ] || break
    sleep 3
done
grep -q '^sparewall_generation' metrics.txt || fail "no coordinator metrics: $(head -5 metrics.txt)"
grep -q '^node_network_receive_bytes_total{device="uplink"}' metrics.txt || {
    vm 'systemctl status prometheus-node-exporter.service --no-pager' || true
    fail "no node_exporter metrics for the uplink: $(grep -c '^node_' metrics.txt) node_ samples"
}
vm 'curl -sk https://localhost/metrics' | grep -q '^node_' && fail "/metrics without a token leaked host metrics"

log "live firewall drift fails readiness (issue #5)"
ready() { vm 'curl -sk -o /dev/null -w "%{http_code}" https://localhost/readyz'; }
[ "$(ready)" = 200 ] || fail "/readyz is $(ready) before the drift"
# Rules removed outside Sparewall, the chain kept (anti-lockout keeps SSH).
vm 'sudo nft flush chain inet sparewall in_mgmt'
[ "$(ready)" = 503 ] || fail "/readyz is $(ready) with the mgmt rules flushed"
vm 'sudo sparewall health --verbose' | tee drift.txt || true
grep -q 'rules in_mgmt' drift.txt || fail "health does not name the drifted chain"
vm 'sudo systemctl restart sparewalld'
deadline=$((SECONDS + 60))
until [ "$(ready)" = 200 ]; do
    [ $SECONDS -lt $deadline ] || fail "/readyz did not recover after restarting sparewalld"
    sleep 3
done

run_conformance

log "the admin console password (#89)"
admin_hash() { vm 'sudo getent shadow admin' | cut -d: -f2; }
takes_password() { # hash password
    H="$1" P="$2" perl -e 'exit(crypt($ENV{P}, $ENV{H}) eq $ENV{H} ? 0 : 1)'
}
printf 'console only\n' | vm 'sudo sparewall passwd'
takes_password "$(admin_hash)" 'console only' || fail "the admin password is not set"
! takes_password "$(admin_hash)" 'something else' || fail "the admin password takes anything"
ssh_password() {
    sshpass -p 'console only' ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o ConnectTimeout=5 \
        admin@127.0.0.1 true 2>/dev/null
}
# Not over SSH: the password is for the console.
! ssh_password || fail "SSH took the admin password"
# Unless the document opts in. sshd is reloaded; a key login shows it is
# listening again before the password is tried.
vm 'sudo sparewall set management.ssh.password=true --confirm 0'
wait_ssh 60
ssh_password || fail "SSH refused the admin password after management.ssh.password=true"
vm 'sudo sparewall set management.ssh.password=false --confirm 0'
wait_ssh 60
! ssh_password || fail "SSH still takes the admin password after opting out"
vm 'sudo systemctl restart sparewalld'
takes_password "$(admin_hash)" 'console only' || fail "the admin password changed on restart"

log "API tokens on the restricted socket"
# admin (not root) with a token: the token's role, not sudo, decides.
VIEWER=$(vm 'sudo sparewall token create ci-viewer --role viewer -q')
OPERATOR=$(vm 'sudo sparewall token create ci-operator --role operator -q')
vm "SPAREWALL_TOKEN=$VIEWER sparewall status" >/dev/null || fail "a viewer token cannot read status"
rc=0; vm "SPAREWALL_TOKEN=$VIEWER sparewall set management.ssh.password=true --confirm 0" || rc=$?
[ "$rc" = 6 ] || fail "a viewer token changed the configuration (exit $rc)"
vm "SPAREWALL_TOKEN=$OPERATOR sparewall set management.ssh.password=true --confirm 0" \
    || fail "an operator token cannot change the configuration"
wait_ssh 60
vm 'sudo sparewall history -o json' | grep -q '"author": *"token ci-operator"' \
    || fail "the change is not recorded with its token"
vm 'sudo sparewall set management.ssh.password=false --confirm 0'
wait_ssh 60
rc=0; vm "SPAREWALL_TOKEN=$OPERATOR sparewall token list" || rc=$?
[ "$rc" = 6 ] || fail "an operator token listed tokens (exit $rc)"
vm 'sudo sparewall token revoke ci-operator'
rc=0; vm "SPAREWALL_TOKEN=$OPERATOR sparewall status" || rc=$?
[ "$rc" = 6 ] || fail "a revoked token still works (exit $rc)"
vm 'sudo sparewall token revoke ci-viewer'

log "the web UI and HTTP API (management.web)"
# sparewalld keeps HTTPS and passes all but the health endpoints to
# sparewall-httpd, which runs only while the document asks for it.
status() { vm "curl -sk -o /dev/null -w '%{http_code}' $*"; }
web_up() { # want: active or inactive
    local deadline=$((SECONDS + 60))
    until [ "$(vm 'systemctl is-active sparewall-httpd' || true)" = "$1" ]; do
        [ $SECONDS -lt $deadline ] || fail "sparewall-httpd is not $1"
        sleep 2
    done
}
[ "$(status https://localhost/openapi.json)" = 404 ] || fail "the HTTP API answers before management.web"
vm 'sudo sparewall set management.web=true --confirm 0'
web_up active
vm 'ps -eo label,comm' | grep -q 'sparewall_httpd_t.*sparewall-httpd' \
    || fail "sparewall-httpd does not run in sparewall_httpd_t"
vm 'curl -sfk https://localhost/openapi.json' | jq -e '.paths["/call/org.sparewall.Firewall.Status"]' >/dev/null \
    || fail "no OpenAPI description at /openapi.json"
[ "$(status https://localhost/readyz)" = 200 ] || fail "/readyz is not the coordinator's with management.web"
# The UI's page, and its assets, under the gateway's labels.
vm 'curl -sfk https://localhost/' | grep -q '<app-root' || fail "no web UI at /"
vm 'curl -sfk https://localhost/history' | grep -q '<app-root' || fail "the UI's routes do not lead to its page"
main_js=$(vm 'curl -sfk https://localhost/' | grep -o 'main-[A-Za-z0-9]*\.js' | head -1)
[ "$(status "https://localhost/$main_js")" = 200 ] || fail "the UI's script $main_js is not served"
# Searched on the node: grep -q stops reading at the first match, and here
# pipefail would count the SSH session it cut short as a failure.
vm "curl -sfk https://localhost/licenses.txt | grep -q 'SIL OPEN FONT LICENSE'" \
    || fail "the UI does not serve its third-party licenses"
vm 'ls -Zd /usr/share/sparewall/ui' | grep -q sparewall_httpd_content_t \
    || fail "the UI's files are not labelled sparewall_httpd_content_t"
WEB=$(vm 'sudo sparewall token create ci-web --role viewer -q')
vm "curl -sfk -X POST -H 'Authorization: Bearer $WEB' https://localhost/call/org.sparewall.Firewall.Status" \
    | jq -e '.role' >/dev/null || fail "a viewer token cannot call Status over HTTPS"
[ "$(status -X POST -H "'Authorization: Bearer $WEB'" https://localhost/call/org.sparewall.Auth.ListUsers)" = 403 ] \
    || fail "a viewer token listed users over HTTPS"
vm 'sudo sparewall token revoke ci-web'
[ "$(status -X POST -H "'Authorization: Bearer $WEB'" https://localhost/call/org.sparewall.Firewall.Status)" = 401 ] \
    || fail "a revoked token still works over HTTPS"
# A browser: the admin's password, then the session cookie with the
# custom header.
vm "curl -sk -c /tmp/jar -o /dev/null -w '%{http_code}' -X POST -H 'X-Sparewall-Request: 1' \
    -d '{\"user\": \"admin\", \"password\": \"console only\"}' \
    https://localhost/call/org.sparewall.Auth.Login" | grep -qx 200 || fail "the admin cannot log in over HTTPS"
vm "curl -sfk -b /tmp/jar -X POST -H 'X-Sparewall-Request: 1' https://localhost/call/org.sparewall.Auth.ListUsers" \
    | jq -e '.users' >/dev/null || fail "the admin's session cannot list users"
vm 'rm -f /tmp/jar'
vm 'sudo sparewall set management.web=false --confirm 0'
web_up inactive
[ "$(status https://localhost/openapi.json)" = 404 ] || fail "the HTTP API still answers after management.web=false"

log "backup to a restic REST server"
start_rest_server
REPO=rest:http://10.0.2.2:8000/fw1
PASSWORD="ci backup password"
vm "printf %s '$PASSWORD' | sudo sparewall secret set backup-password"
vm "sudo sparewall set backup.enabled=true backup.repository=$REPO 'backup.schedule=*:0/15' --confirm 0"
vm 'sudo sparewall backup' 2>&1 | tee backup.txt
grep -q snapshot backup.txt || fail "the bundle was not sent to the repository"
grep -q 'no cluster secrets' backup.txt && fail "the bundle left out the secrets"
# The bundle carries the secrets decrypted: log-token, sealed before the
# reboot, was unsealed by the coordinator.
deadline=$((SECONDS + 120))
until vm 'systemctl list-timers --all --no-legend sparewall-backup.timer' | grep -q sparewall-backup; do
    [ $SECONDS -lt $deadline ] || fail "no backup timer"
    sleep 5
done
vm 'systemctl list-timers --all --no-legend sparewall-backup.timer'
vm 'sudo sparewall status -o json' > before.json
vm 'sudo sparewall secret list -o json' > secrets-before.json
vm 'sudo sparewall export' > export-before.yaml

log "restore drill: the node is lost and reinstalled"
sudo kill "$(sudo cat qemu.pid)"
sleep 2
cp output/qcow2/disk.qcow2 vm.qcow2
start_vm
wait_ssh 900
full_audit vm fw1
vm 'systemctl is-system-running --wait' || true
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .role status.json)" = bootstrap ] || fail "the reinstalled node is not in bootstrap mode"
vm 'sudo systemctl stop sparewalld.socket sparewalld.service'
vm "printf '%s\n' '$PASSWORD' > /tmp/pw"
vm "sudo sparewall restore --repository $REPO --password-file /tmp/pw" 2>&1 | tee restore.txt
grep -q '3 secrets' restore.txt || fail "the secrets were not restored"
vm 'sudo test -s /var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv' \
    || fail "the DHCP leases were not restored"
vm 'sudo systemctl start sparewalld.socket sparewalld.service' || true
sleep 5
wait_ssh 120
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .sync.active status.json)" = "$(jq -r .sync.active before.json)" ] \
    || fail "restored generation $(jq -r .sync.active status.json), not $(jq -r .sync.active before.json)"
vm 'sudo sparewall export' > export-after.yaml
diff -u export-before.yaml export-after.yaml || fail "the restored document differs"
vm 'sudo sparewall secret list -o json' > secrets-after.json
[ "$(jq -c '[.[].name]' secrets-after.json)" = "$(jq -c '[.[].name]' secrets-before.json)" ] \
    || fail "secrets differ: $(jq -c '[.[].name]' secrets-after.json)"
vm 'ip -br link' | grep -q '^uplink ' || fail "port not named uplink after the restore"
deadline=$((SECONDS + 180))
until vm 'sudo sparewall health' >/dev/null 2>&1; do
    [ $SECONDS -lt $deadline ] || { vm 'sudo sparewall health --verbose' || true; fail "health not ok after the restore"; }
    sleep 5
done
vm 'sudo sparewall health --verbose'
# The restored lease is honoured, and the policy holds again.
dhcp_script
[ "$(lease users)" = 192.0.2.20 ] || fail "users lost its reservation after the restore"
can users 192.0.2.1 || fail "users cannot ping the gateway after the restore"
takes_password "$(admin_hash)" 'console only' || fail "the admin password was not restored"
# The restored secrets were sealed to the new node's own TPM; a backup
# unseals them.
vm 'sudo sparewall backup' 2>&1 | tee backup-after.txt
grep -q snapshot backup-after.txt || fail "no backup after the restore"

log "the coordinator's SELinux domain"
selinux_report vm fw1
selinux_health vm fw1
permissive_drill vm fw1
selinux_gate || exit 1
log "PASS"
