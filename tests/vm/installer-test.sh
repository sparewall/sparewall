#!/bin/bash
# Install from the ISO with no network, then boot the installed system
# (design: "To prove in the lab": container images absent after an
# offline install). The installed node gets its identity from a seed
# stick, as a physical machine would, and must reach bootstrap mode with
# every logically bound provider image already in place.
#
#   tests/vm/installer-test.sh IMAGE WORKDIR
#
# Needs root (podman for bootc-image-builder, KVM), qemu-system-x86_64,
# xorriso, mkfs.vfat and mcopy.
set -euo pipefail
IMAGE=${1:?usage: installer-test.sh IMAGE WORKDIR}
WORK=${2:?usage: installer-test.sh IMAGE WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
BIB=${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}
SSH_PORT=2240
MAC=52:54:00:12:36:56
mkdir -p "$WORK/output"
cd "$WORK"
log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        for f in install.serial installed.serial; do
            [ -f "$f" ] && { echo "--- $f"; sudo tail -80 "$f"; }
        done
    fi
    [ -f installed.pid ] && sudo kill "$(sudo cat installed.pid)" 2>/dev/null || true
}
trap cleanup EXIT

log "building the installer ISO from $IMAGE"
if [ ! -f output/bootiso/install.iso ]; then
    # The bound provider images must be in the host's storage, as for a
    # disk image (build-disk.sh).
    for ref in $(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
            'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done'); do
        sudo podman image exists "$ref" || sudo podman pull "$ref"
    done
    sudo podman run --rm --privileged \
        --security-opt label=type:unconfined_t \
        -v "$WORK/output:/output" \
        -v "$HERE/../../image/installer.toml:/config.toml:ro" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        "$BIB" --type anaconda-iso --rootfs xfs "$IMAGE"
fi
sudo chown -R "$(id -u):$(id -g)" output
ls -la output/bootiso/install.iso

log "installing with no network"
rm -f installed.qcow2
qemu-img create -q -f qcow2 installed.qcow2 20G
# The ISO's own kernel and arguments, plus a serial console, so the
# install shows in install.serial; the ISO stays attached as the source.
rm -rf iso && mkdir iso
xorriso -osirrox on -indev output/bootiso/install.iso \
    -extract /images/pxeboot/vmlinuz iso/vmlinuz \
    -extract /images/pxeboot/initrd.img iso/initrd.img \
    -extract /EFI/BOOT/grub.cfg iso/grub.cfg >/dev/null 2>&1 \
    || fail "cannot read the kernel from the ISO"
args=$(sed -nE 's/^[[:space:]]*linux(efi)?[[:space:]]+[^[:space:]]+[[:space:]]+//p' iso/grub.cfg | head -1)
[ -n "$args" ] || fail "no kernel arguments in the ISO's grub.cfg"
echo "installer arguments: $args"
# The kickstart installs unattended to the first fixed disk and reboots;
# -no-reboot turns that into an exit.
timeout 2400 sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 3072 -smp 2 \
    -drive "file=installed.qcow2,if=virtio,format=qcow2" \
    -cdrom output/bootiso/install.iso \
    -kernel iso/vmlinuz -initrd iso/initrd.img -append "$args console=ttyS0" \
    -nic none -no-reboot \
    -display none -serial "file:install.serial" \
    || fail "the installer did not finish"

log "booting the installed system with a seed stick, still offline"
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f id_ed25519
cat > sparewall-identity.yaml <<YAML
node: fw1
ssh_keys: ["$(cat id_ed25519.pub)"]
management: { nic: "$MAC" }
YAML
rm -f seed.img
mkfs.vfat -C -n SPAREWALL seed.img 4096 >/dev/null
mcopy -i seed.img sparewall-identity.yaml ::sparewall-identity.yaml
# restrict=on: the guest reaches neither the host nor the internet, but
# the SSH forward still works.
sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 2048 -smp 2 \
    -drive "file=installed.qcow2,if=virtio,format=qcow2" \
    -netdev "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device "virtio-net-pci,netdev=n0,mac=$MAC" \
    -drive "file=seed.img,if=none,id=seed,format=raw,readonly=on" \
    -device "usb-ehci" -device "usb-storage,drive=seed,removable=on" \
    -display none -serial "file:installed.serial" -pidfile installed.pid -daemonize
vm() {
    timeout 60 ssh -p "$SSH_PORT" -i id_ed25519 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR \
        admin@127.0.0.1 "$@"
}
deadline=$((SECONDS + 900))
until vm true 2>/dev/null; do
    [ $SECONDS -lt $deadline ] || fail "no SSH on the installed system"
    sleep 5
done
[ "$(vm 'sudo sparewall status -o json' | jq -r .role)" = bootstrap ] \
    || fail "the installed node is not in bootstrap mode"
vm 'sudo journalctl -b -u "sparewall-seed@*" --no-pager' | grep -q "recorded the identity" \
    || fail "the identity did not come from the seed stick"

log "the bound provider images"
missing=0
for f in $(vm 'ls /usr/lib/bootc/bound-images.d/'); do
    ref=$(vm "sed -n 's/^Image=//p' /usr/lib/bootc/bound-images.d/$f")
    # Where bootc keeps them, as the Quadlet units read them.
    if vm "sudo podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage image exists $ref"; then
        echo "present: $ref"
    else
        echo "MISSING: $ref"
        missing=1
    fi
done
vm 'sudo bootc status --format=json' | jq -r '.status.booted.image.image.image'
[ $missing = 0 ] || fail "bound images are missing after an offline install"
log "installer PASS"
