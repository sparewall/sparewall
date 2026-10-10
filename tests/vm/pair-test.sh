#!/bin/bash
# Two-node suite (design: milestone 3): pairing, push, the gateway address,
# DHCP from the Kea HA pair, and failover when the master dies.
#
#   tests/vm/pair-test.sh WORKDIR    (reuses WORKDIR/output/qcow2/disk.qcow2
#                                     from boot-test.sh)
set -euo pipefail
WORK=${1:?usage: pair-test.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$WORK"
log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ns() { local n=$1; shift; sudo ip netns exec "sw-$n" "$@"; }

# Bridge and the users client from boot-test.sh, or fresh ones.
if ! ip link show swbr >/dev/null 2>&1; then
    . "$HERE/conformance.sh"
    setup_trunk
fi
for t in swtap1 swtap2; do
    sudo ip tuntap add "$t" mode tap
    sudo ip link set "$t" master swbr up
    sudo bridge vlan del dev "$t" vid 1
    sudo bridge vlan add dev "$t" vid 20
    sudo bridge vlan add dev "$t" vid 4000
done

boot() { # name ssh-port mgmt-mac trunk-mac tap
    local name=$1 port=$2 mac=$3 tmac=$4 tap=$5
    cp output/qcow2/disk.qcow2 "$name.qcow2"
    cat > "$name.json" <<JSON
{"node": "$name", "ssh_keys": ["$(cat id_ed25519.pub)"], "management": {"nic": "$mac"}}
JSON
    sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 1536 -smp 2 \
        -drive "file=$name.qcow2,if=virtio,format=qcow2" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${port}-:22" \
        -device "virtio-net-pci,netdev=n0,mac=$mac" \
        -netdev "tap,id=n1,ifname=$tap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n1,mac=$tmac" \
        -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 "$name.json")" \
        -display none -serial "file:$name.serial" -pidfile "$name.pid" -daemonize
}

at() { # node command...
    local port; case $1 in fw1) port=2231 ;; fw2) port=2232 ;; esac; shift
    ssh -p "$port" -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR \
        admin@127.0.0.1 "$@"
}

wait_for() { # seconds description command...
    local deadline=$((SECONDS + $1)) what=$2; shift 2
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || fail "timed out: $what"
        sleep 5
    done
}

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        for n in fw1 fw2; do
            echo "--- $n"
            at "$n" 'sudo sparewall status
                sudo wg show swsync 2>&1; ip -br addr
                for u in keepalived conntrackd sparewall-kea; do echo "-- $u"; sudo journalctl -b -u $u --no-pager | tail -15; done
                echo "-- networkd"; sudo journalctl -b -u systemd-networkd --no-pager | grep -iE "swsync|wireguard|key" | tail -15
                echo "-- AVC"; sudo journalctl -b -k --no-pager | grep -oE "avc: +denied.*" | sed -E "s/pid=[0-9]+ //; s/ino=[0-9]+ //" | sort | uniq -c | tail -25
                ls -laZ /run/keepalived/' 2>/dev/null \
                || sudo tail -60 "$n.serial" || true
        done
    fi
    for n in fw1 fw2; do
        [ -f "$n.pid" ] && sudo kill "$(sudo cat "$n.pid")" 2>/dev/null || true
    done
}
trap cleanup EXIT

log "booting two nodes"
boot fw1 2231 52:54:00:12:34:56 52:54:00:12:34:57 swtap1
boot fw2 2232 52:54:00:12:35:56 52:54:00:12:35:57 swtap2
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "pairing"
k1=$(at fw1 'sudo sparewall status -o json' | jq -r .sync.sync_public_key)
k2=$(at fw2 'sudo sparewall status -o json' | jq -r .sync.sync_public_key)
sed -e "s|@FW1_KEY@|$k1|" -e "s|@FW2_KEY@|$k2|" "$HERE/site-pair.yaml" > pair.yaml
for n in fw1 fw2; do
    at "$n" 'cat > /tmp/pair.yaml' < pair.yaml
    at "$n" 'sudo sparewall apply -f /tmp/pair.yaml --confirm 0' || fail "pairing apply failed on $n"
done
in_sync() { at "$1" 'sudo sparewall status -o json' | jq -e '.sync.state == "in-sync"'; }
wait_for 300 "fw1 in sync" in_sync fw1
wait_for 120 "fw2 in sync" in_sync fw2
role() { at "$1" 'sudo sparewall status -o json' | jq -r .role; }
is_master() { [ "$(role "$1")" = MASTER ]; }
wait_for 120 "fw1 master" is_master fw1
[ "$(role fw2)" = BACKUP ] || fail "fw2 is $(role fw2), not BACKUP"

log "a change on fw1 reaches fw2"
at fw1 'sudo sparewall set dhcp.users.lease_time=3600 --confirm 0'
gen=$(at fw1 'sudo sparewall status -o json' | jq .sync.active)
fw2_gen() { [ "$(at fw2 'sudo sparewall status -o json' | jq .sync.active)" = "$gen" ]; }
wait_for 120 "fw2 at generation $gen" fw2_gen

log "the gateway address and DHCP"
. "$HERE/conformance.sh"
dhcp_script
ns users ip addr flush dev eth0
ns users busybox udhcpc -i eth0 -n -q -t 10 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1 || fail "no DHCP lease from the pair"
ns users ping -c 2 -W 2 192.0.2.1 >/dev/null || fail "gateway address unreachable"

log "failover"
sudo kill "$(sudo cat fw1.pid)"; rm -f fw1.pid
wait_for 60 "fw2 master" is_master fw2
ns users ping -c 3 -W 2 192.0.2.1 >/dev/null || fail "gateway address unreachable after failover"
at fw2 'sudo sparewall status' | grep -q 'peer-unreachable' || fail "fw2 does not report the peer down"
log "pair PASS"
