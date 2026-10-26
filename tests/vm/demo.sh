#!/bin/bash
# A Sparewall node in a VM on this machine, to try the web UI and demo it
# before a release. It runs under libvirt's per-user session
# (qemu:///session), so nothing but the disk build needs root.
#
#   tests/vm/demo.sh disk [IMAGE]  build the base disk from IMAGE, by default
#                                  the published testing image (uses sudo:
#                                  bootc-image-builder runs as root)
#   tests/vm/demo.sh up            create the node from the base disk, set it
#                                  up (tests/vm/demo.yaml, the web UI, demo
#                                  users) and say how to reach it
#   tests/vm/demo.sh stop | start  stop it or start it again, state kept
#   tests/vm/demo.sh reset         a fresh install from the base disk, set up
#   tests/vm/demo.sh destroy       remove the node; the base disk stays
#   tests/vm/demo.sh ssh [CMD]     a shell (or CMD) on it, as admin
#   tests/vm/demo.sh info          how to reach it, and the demo users
#
# The web UI and SSH are forwarded from loopback only: https://localhost:8443/
# and localhost:2222 (SPAREWALL_DEMO_WEB_PORT, SPAREWALL_DEMO_SSH_PORT).
# The VM has three NICs: management (forwarded, through passt), WAN (NAT
# to this machine's network, through qemu) and a LAN trunk with nothing on
# it.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${SPAREWALL_DEMO_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/sparewall-demo}
NAME=${SPAREWALL_DEMO_NAME:-sparewall-demo}
URI=qemu:///session
WEB_PORT=${SPAREWALL_DEMO_WEB_PORT:-8443}
SSH_PORT=${SPAREWALL_DEMO_SSH_PORT:-2222}
IMAGE_DEFAULT=ghcr.io/sparewall/sparewall:testing
# The NICs tests/vm/demo.yaml names.
MGMT_MAC=52:54:00:5a:00:01
WAN_MAC=52:54:00:5a:00:02
LAN_MAC=52:54:00:5a:00:03
# Demo users and their passwords: a demo VM on loopback, nothing more.
ADMIN_PASSWORD=demo-admin
DEMO_USERS=("olivia:operator:demo-operator" "victor:viewer:demo-viewer")

log() { printf '=== %s\n' "$*"; }
fail() { echo "demo: $*" >&2; exit 1; }
virsh() { command virsh -c "$URI" "$@"; }
exists() { virsh dominfo "$NAME" >/dev/null 2>&1; }

SSH=(ssh -p "$SSH_PORT" -i "$DIR/id_ed25519" -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR
     admin@127.0.0.1)
node() { "${SSH[@]}" "$@"; }

disk() {
    local image=${1:-$IMAGE_DEFAULT}
    mkdir -p "$DIR"
    rm -rf "$DIR/build"
    # bootc-image-builder reads the image from root's container storage.
    # A tag such as testing moves, so pull even when a copy is there: an
    # earlier disk's image would otherwise be built again. "newer" still
    # uses a local image the registry cannot be asked about.
    log "pulling $image"
    sudo podman pull --policy newer "$image"
    log "building a disk from $image (several minutes)"
    "$HERE/build-disk.sh" "$image" "$DIR/build"
    mv "$DIR/build/output/qcow2/disk.qcow2" "$DIR/base.qcow2"
    rm -rf "$DIR/build"
    sudo podman image inspect --format '{{.Digest}}' "$image" \
        | sed "s|^|$image@|" > "$DIR/base.txt"
    log "base disk: $DIR/base.qcow2 ($(cat "$DIR/base.txt"))"
}

# The domain: UEFI, a TPM (secrets are sealed to it), the node identity as
# a systemd credential, and user-mode NICs, each in its own subnet so the
# management and WAN networks do not overlap. Management is passt, which
# forwards the ports; it presents those connections as coming from its
# gateway, this machine's own gateway. The WAN is qemu's own user
# networking, whose gateway is its own: were it passt too, both default
# routes would lead to the same address, and replies to the forwarded
# connections would leave through the WAN.
domain_xml() {
    local cred=$1
    virt-install --connect "$URI" --name "$NAME" --memory 3072 --vcpus 2 \
        --import --osinfo fedora-unknown \
        --disk "path=$DIR/node.qcow2,bus=virtio" \
        --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
        --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
        --sysinfo "type=smbios,oemStrings.entry0=io.systemd.credential.binary:sparewall.identity=$cred" \
        --network "type=user,backend.type=passt,mac=$MGMT_MAC,portForward0.proto=tcp,portForward0.range0.start=$WEB_PORT,portForward0.range0.to=443,portForward1.proto=tcp,portForward1.range0.start=$SSH_PORT,portForward1.range0.to=22" \
        --network "type=user,mac=$WAN_MAC" \
        --network "type=user,backend.type=passt,mac=$LAN_MAC" \
        --graphics none --console pty --print-xml \
    | python3 -I -c '
import sys, xml.etree.ElementTree as ET
# passt takes the guest address, qemu user networking the network.
nets = {"52:54:00:5a:00:01": "10.88.0.10", "52:54:00:5a:00:02": "10.89.0.0", "52:54:00:5a:00:03": "10.90.0.10"}
dom = ET.parse(sys.stdin).getroot()
for i in dom.iter("interface"):
    ET.SubElement(i, "ip", family="ipv4", address=nets[i.find("mac").get("address")], prefix="24")
    for f in i.findall("portForward"):
        f.set("address", "127.0.0.1")
print(ET.tostring(dom, encoding="unicode"))
'
}

up() {
    [ -f "$DIR/base.qcow2" ] || fail "no base disk: run tests/vm/demo.sh disk first"
    exists && fail "$NAME exists: start it, or reset it for a fresh install"
    command -v virt-install >/dev/null || fail "virt-install is not installed"

    [ -f "$DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C sparewall-demo -f "$DIR/id_ed25519"
    # This machine's own keys too, so plain ssh works.
    local keys
    keys=$(cat "$DIR/id_ed25519.pub" ~/.ssh/id_*.pub 2>/dev/null \
        | python3 -I -c 'import json, sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    local cred
    cred=$(printf '{"node": "fw1", "ssh_keys": %s, "management": {"nic": "%s"}}' "$keys" "$MGMT_MAC" | base64 -w0)

    log "creating $NAME"
    qemu-img create -q -f qcow2 -b "$DIR/base.qcow2" -F qcow2 "$DIR/node.qcow2" 20G
    domain_xml "$cred" > "$DIR/domain.xml"
    virsh define "$DIR/domain.xml" >/dev/null
    virsh start "$NAME" >/dev/null
    setup
}

wait_ssh() {
    local deadline=$((SECONDS + 900))
    log "waiting for the node to boot (the first boot takes a few minutes)"
    until node true 2>/dev/null; do
        [ $SECONDS -lt $deadline ] || fail "no SSH after 15 minutes: tests/vm/demo.sh console shows why"
        sleep 5
    done
}

setup() {
    wait_ssh
    log "setting it up"
    printf '%s' "$ADMIN_PASSWORD" | node 'sudo sparewall passwd' >/dev/null
    node 'cat > /tmp/demo.yaml' < "$HERE/demo.yaml"
    node 'sudo sparewall apply -f /tmp/demo.yaml --confirm 0' | tail -1
    local u name role password
    for u in "${DEMO_USERS[@]}"; do
        IFS=: read -r name role password <<<"$u"
        printf '%s' "$password" | node "sudo sparewall user add $name --role $role" >/dev/null
    done
    local deadline=$((SECONDS + 120))
    until curl -sfk -o /dev/null "https://localhost:$WEB_PORT/"; do
        [ $SECONDS -lt $deadline ] || fail "the web UI did not come up: tests/vm/demo.sh ssh 'systemctl status sparewall-httpd'"
        sleep 3
    done
    info
}

info() {
    cat <<EOF

  Web UI   https://localhost:$WEB_PORT/   (self-signed certificate)
  Users    admin / $ADMIN_PASSWORD
EOF
    local u name role password
    for u in "${DEMO_USERS[@]}"; do
        IFS=: read -r name role password <<<"$u"
        printf '           %s / %s (%s)\n' "$name" "$password" "$role"
    done
    cat <<EOF
  SSH      tests/vm/demo.sh ssh   (or: ssh -p $SSH_PORT admin@localhost)
  Image    $(cat "$DIR/base.txt" 2>/dev/null || echo unknown)

EOF
}

destroy() {
    if exists; then
        virsh destroy "$NAME" >/dev/null 2>&1 || true
        virsh undefine "$NAME" --nvram --tpm >/dev/null
    fi
    rm -f "$DIR/node.qcow2" "$DIR/domain.xml"
}

case ${1:-} in
    disk) shift; disk "$@" ;;
    up) up ;;
    start) virsh start "$NAME" >/dev/null && wait_ssh && info ;;
    stop) virsh shutdown "$NAME" ;;
    reset) destroy; up ;;
    destroy) destroy ;;
    ssh) shift; node "$@" ;;
    console) virsh console "$NAME" ;;
    info) info ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
