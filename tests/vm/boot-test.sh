#!/bin/bash
# Boot a Sparewall image in a VM and check bootstrap mode, a first apply
# confirmed over a fresh connection, and the automatic revert of an
# unconfirmed change.
#
#   tests/vm/boot-test.sh IMAGE [WORKDIR]
#
# Needs root (podman for bootc-image-builder, KVM), qemu-system-x86_64.
set -euo pipefail

IMAGE=${1:?usage: boot-test.sh IMAGE [WORKDIR]}
WORK=${2:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
BIB=${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}
SSH_PORT=${SSH_PORT:-2222}
MAC=52:54:00:12:34:56
mkdir -p "$WORK/output"
cd "$WORK"

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
trap 'dump' ERR

log "building a qcow2 from $IMAGE"
if [ ! -f output/qcow2/disk.qcow2 ]; then
    # bootc copies the logically bound provider images into the new system
    # from the host's container storage, so they must be there first.
    for ref in $(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
            'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done'); do
        sudo podman image exists "$ref" || sudo podman pull "$ref"
    done
    auth=()
    if sudo test -f /run/containers/0/auth.json; then
        auth=(-v /run/containers/0/auth.json:/run/containers/0/auth.json:ro)
    fi
    sudo podman run --rm --privileged \
        --security-opt label=type:unconfined_t \
        "${auth[@]}" \
        -v "$WORK/output:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        "$BIB" --type qcow2 --rootfs xfs "$IMAGE"
fi
sudo chown -R "$(id -u):$(id -g)" output
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
sudo qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -m 2048 -smp 2 \
    -drive file=vm.qcow2,if=virtio,format=qcow2 \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device "virtio-net-pci,netdev=n0,mac=$MAC" \
    -netdev tap,id=n1,ifname=swtap0,script=no,downscript=no \
    -device virtio-net-pci,netdev=n1,mac=52:54:00:12:34:57 \
    -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$CRED" \
    -display none -serial file:serial.log \
    -pidfile qemu.pid -daemonize

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        vm 'systemctl --failed --no-legend; sudo journalctl -b -u sparewall-early -u sparewalld -u systemd-networkd --no-pager | tail -80' 2>/dev/null || true
    fi
    if [ -f qemu.pid ]; then sudo kill "$(sudo cat qemu.pid)" 2>/dev/null || true; fi
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

log "an unconfirmed change reverts"
vm 'sudo sparewall set "policy.mgmt->self.action=reject" --confirm 15 --no-prompt'
vm 'sudo sparewall get "policy.mgmt->self.action"' | grep -q reject || fail "change not applied"
sleep 25
vm 'sudo sparewall get "policy.mgmt->self.action"' | grep -q drop || fail "change not reverted"
vm 'sudo sparewall history'

log "the configuration survives a reboot"
vm 'sudo systemctl reboot' || true
sleep 15
wait_ssh 600
vm 'sudo sparewall status -o json' > status.json
[ "$(jq -r .sync.active status.json)" = 1 ] || fail "generation 1 not active after reboot"
vm 'ip -br link' | grep -q '^uplink ' || fail "port not named uplink after reboot"
# udev names the port at coldplug; sparewalld should not have to.
if vm 'sudo journalctl -b -u sparewalld --no-pager' | grep -q 'renaming interface'; then
    fail "the port was renamed late, by sparewalld, not at coldplug"
fi
[ "$(jq -r .health.level status.json)" = ok ] || fail "health not ok after reboot: $(jq -c .health status.json)"

run_conformance

log "PASS"
