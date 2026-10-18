#!/bin/bash
# The ISO refuses a disk that is not blank. Then install from it with no
# network, to a disk with an empty partition table, and boot the installed system
# (design: "To prove in the lab": container images absent after an
# offline install). The installed node gets its identity and a first
# configuration from a seed stick, as a physical machine would: it must
# apply and confirm that configuration by itself (its port bound by PCI
# path), with every logically bound provider image already in place.
#
#   tests/vm/installer-test.sh IMAGE WORKDIR
#
# Needs root (podman for bootc-image-builder, KVM), qemu-system-x86_64,
# xorriso, sfdisk, mkfs.vfat and mcopy.
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
        for f in refused.serial install.serial installed.serial; do
            [ -f "$f" ] && { echo "--- $f"; sudo tail -80 "$f"; }
        done
        # The installed node's denials, from its console: they show
        # there even when SSH does not.
        [ -f installed.serial ] && { echo "--- denials on the installed node"; sudo grep -a 'avc: *denied' installed.serial || echo none; }
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
    sudo chown -R "$(id -u):$(id -g)" output
    "$HERE/../../image/embed-bound-images.sh" "$IMAGE" output/bootiso/install.iso
fi
sudo chown -R "$(id -u):$(id -g)" output
ls -la output/bootiso/install.iso

# A 20 GB disk, with a partition table made by sfdisk from $1.
disk() { # qcow2 sfdisk-script
    rm -f "$1" disk.raw
    truncate -s 20G disk.raw
    printf '%s\n' "$2" | sfdisk -q disk.raw
    qemu-img convert -O qcow2 disk.raw "$1"
    rm -f disk.raw
}
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
run_installer() { # disk timeout serial-log
    timeout "$2" sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 3072 -smp 2 \
        -drive "file=$1,if=virtio,format=qcow2" \
        -cdrom output/bootiso/install.iso \
        -kernel iso/vmlinuz -initrd iso/initrd.img -append "$args console=ttyS0" \
        -nic none -no-reboot \
        -display none -serial "file:$3"
}

log "a disk that is not blank is not erased"
disk used.qcow2 $'label: gpt\n,100M'
# Anaconda then waits at its error screen, for someone to read it: stop
# the VM once the message is out.
rm -f refused.serial
run_installer used.qcow2 900 refused.serial &
deadline=$((SECONDS + 900))
until sudo grep -aq "SPAREWALL: /dev/vda is not blank" refused.serial 2>/dev/null; do
    if [ $SECONDS -ge $deadline ] || ! kill -0 $! 2>/dev/null; then
        sudo sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' refused.serial | tail -40 >&2 || true
        fail "the installer did not refuse a disk with a partition"
    fi
    sleep 5
done
sudo pkill -f "file:refused.serial" || true
wait $! || true
qemu-img convert -O raw used.qcow2 used.raw
sfdisk -d used.raw | grep -q 'start=' || fail "the refused disk lost its partition"
rm -f used.qcow2 used.raw

log "installing with no network, to a disk with an empty partition table"
disk installed.qcow2 'label: gpt'
run_installer installed.qcow2 2400 install.serial || fail "the installer did not finish"
if grep -aq "The installer will now terminate" install.serial; then
    sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' install.serial | grep -a -B3 -A8 "exact error message" >&2 || true
    fail "the installer failed"
fi

log "booting the installed system with a seed stick, still offline"
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f id_ed25519
cat > sparewall-identity.yaml <<YAML
node: fw1
ssh_keys: ["$(cat id_ed25519.pub)"]
management: { nic: "$MAC" }
YAML
# And a first configuration, applied by the node itself. Its port is
# bound by PCI path, as for hardware not seen before (the NIC is placed at
# 00:05.0 below). The first stick's is for another node, so it is
# refused; a corrected stick replaces it later.
sed 's|nic: "52:54:00:12:34:56"|nic: "pci-0000:00:05.0"|' "$HERE/site.yaml" > sparewall-config.yaml
grep -q pci-0000 sparewall-config.yaml || fail "no PCI path in the seeded configuration"
stick() { # image config
    rm -f "$1"
    mkfs.vfat -C -n SPAREWALL "$1" 4096 >/dev/null
    mcopy -i "$1" sparewall-identity.yaml ::sparewall-identity.yaml
    mcopy -i "$1" "$2" ::sparewall-config.yaml
}
sed 's|nodes: \[fw1\]|nodes: [fw9]|; s|^  fw1:|  fw9:|' sparewall-config.yaml > wrong-config.yaml
grep -q fw9 wrong-config.yaml || fail "could not make the wrong configuration"
stick seed.img wrong-config.yaml
stick seed2.img sparewall-config.yaml
# restrict=on: the guest reaches neither the host nor the internet, but
# the SSH forward still works.
# bootindex: the firmware would otherwise try the seed stick first.
sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 2048 -smp 2 \
    -drive "file=installed.qcow2,if=none,id=disk,format=qcow2" \
    -device "virtio-blk-pci,drive=disk,bootindex=0" \
    -netdev "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device "virtio-net-pci,netdev=n0,mac=$MAC,bus=pcie.0,addr=0x5" \
    -drive "file=seed.img,if=none,id=seed,format=raw,readonly=on" \
    -device "usb-ehci" -device "usb-storage,drive=seed,id=stick,removable=on,bootindex=1" \
    -monitor "unix:$WORK/monitor.sock,server=on,wait=off" \
    -display none -serial "file:installed.serial" -pidfile installed.pid -daemonize
# A QEMU monitor command (HMP), for unplugging and plugging sticks.
monitor() {
    sudo python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
time.sleep(0.5)
s.recv(65536)
s.sendall(sys.argv[2].encode() + b"\n")
time.sleep(1)
print(s.recv(65536).decode(errors="replace"))' "$WORK/monitor.sock" "$1"
}
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
# Every denial, hidden or not, on the console without rate limiting, so
# that a failure that cuts SSH still shows what was denied.
vm 'sudo semodule -DB && sudo sysctl -q -w kernel.printk_ratelimit=0 kernel.printk_ratelimit_burst=100000' \
    || fail "cannot set up auditing on the installed system"
vm 'sudo journalctl -b -u "sparewall-seed@*" --no-pager' | grep -q "recorded the identity" \
    || fail "the identity did not come from the seed stick"

log "a seed for another node is refused, and says so"
refused() {
    vm 'sudo sparewall health --verbose -o json' \
        | jq -e '.checks[] | select(.name == "seed" and .level == "degraded") | .message | test("refused")' >/dev/null
}
deadline=$((SECONDS + 120))
until refused 2>/dev/null; do
    if [ $SECONDS -ge $deadline ]; then
        vm 'sudo sparewall health --verbose; sudo journalctl -b -u sparewalld --no-pager | tail -40' || true
        fail "the wrong seed was not reported as refused"
    fi
    sleep 5
done
[ "$(vm 'sudo sparewall status -o json' | jq .sync.active)" = 0 ] || fail "the wrong seed was applied"

log "a corrected stick, put in in its place"
monitor "device_del stick"
sleep 3
monitor "drive_add 0 if=none,id=seed2,file=$WORK/seed2.img,format=raw,readonly=on"
monitor "device_add usb-storage,drive=seed2,id=stick2,removable=on"

log "the seeded configuration, applied and confirmed by the node"
seeded() { vm 'sudo sparewall status -o json' | jq -e '.sync.active == 1 and .sync.confirmed == 1' >/dev/null; }
deadline=$((SECONDS + 300))
until seeded 2>/dev/null; do
    if [ $SECONDS -ge $deadline ]; then
        vm 'sudo sparewall health --verbose; sudo journalctl -b -u sparewalld --no-pager | tail -40' || true
        fail "the seeded configuration was not applied and confirmed"
    fi
    sleep 5
done
vm 'sudo sparewall history'
[ "$(vm 'sudo sparewall history -o json' | jq -r '.[] | select(.id == 1) | .author')" = seed ] \
    || fail "generation 1 is not the seeded configuration"
vm 'ip -br link show uplink' | grep -q UP || fail "the port bound by PCI path is not up"

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
