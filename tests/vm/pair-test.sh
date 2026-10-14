#!/bin/bash
# Two-node suite (design: milestone 3): pairing, push, the gateway address,
# DHCP from the Kea HA pair, a cut sync VLAN with divergence resolved by
# `sync --from`, and failover when the master dies, with an established
# TCP connection (conntrackd) and the client's lease (Kea HA) surviving
# it. With IMAGE set (the image the disk was built from), the failed node
# then returns, an unsigned image is refused, and `sparewall upgrade`
# rolls the pair onto a derived image served from a local registry,
# handing the gateway over between the reboots. Remote-access VPN clients
# (vpn.sh) measure tunnel recovery and inner-flow continuity across the
# master loss and the rolling upgrade.
#
#   [IMAGE=localhost/sparewall:ci] tests/vm/pair-test.sh WORKDIR
#       (reuses WORKDIR/output/qcow2/disk.qcow2 from boot-test.sh)
set -euo pipefail
WORK=${1:?usage: pair-test.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$WORK"
log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ns() { local n=$1; shift; sudo ip netns exec "sw-$n" "$@"; }
# shellcheck source=vpn.sh
. "$HERE/vpn.sh"

# Bridge and the users client from boot-test.sh, or fresh ones.
if ! ip link show swbr >/dev/null 2>&1; then
    . "$HERE/conformance.sh"
    setup_trunk
fi
# Trunks carry the service VLANs (WAN 10, users 20, servers 30); each
# node's dedicated sync port, VLAN 4000.
for t in swtap1 swtap2 swtap1s swtap2s; do
    sudo ip tuntap add "$t" mode tap
    sudo ip link set "$t" master swbr up
    sudo bridge vlan del dev "$t" vid 1
    case $t in
    *s) sudo bridge vlan add dev "$t" vid 4000 ;;
    *) for v in 10 20 30; do sudo bridge vlan add dev "$t" vid $v; done ;;
    esac
done

boot() { # name ssh-port mgmt-mac trunk-mac tap sync-mac sync-tap
    cp output/qcow2/disk.qcow2 "$1.qcow2"
    cat > "$1.json" <<JSON
{"node": "$1", "ssh_keys": ["$(cat id_ed25519.pub)"], "management": {"nic": "$3"}}
JSON
    start "$@"
}

start() { # name ssh-port mgmt-mac trunk-mac tap sync-mac sync-tap (the disk as it is)
    local name=$1 port=$2 mac=$3 tmac=$4 tap=$5 smac=$6 stap=$7
    sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 1536 -smp 2 \
        -drive "file=$name.qcow2,if=virtio,format=qcow2" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${port}-:22" \
        -device "virtio-net-pci,netdev=n0,mac=$mac" \
        -netdev "tap,id=n1,ifname=$tap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n1,mac=$tmac" \
        -netdev "tap,id=n2,ifname=$stap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n2,mac=$smac" \
        -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 "$name.json")" \
        -display none -serial "file:$name.serial" -pidfile "$name.pid" -daemonize
}

at() { # node command...
    local port; case $1 in fw1) port=2231 ;; fw2) port=2232 ;; esac; shift
    # QEMU accepts the forwarded connection before the guest is up, so
    # ConnectTimeout alone does not bound a call: a hung one is retried.
    timeout "${AT_TIMEOUT:-90}" ssh -p "$port" -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
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
        [ -f flow.log ] && { echo "--- flow.log"; tail -5 flow.log; }
        for c in $VPN_CLIENTS; do
            echo "--- VPN client $c"; ns "$c" wg show wg0 2>/dev/null || true
        done
        for f in vpn-tcp.log vpn-udp.log vpna.ping natc.ping upgrade.log; do
            [ -f "$f" ] && { echo "--- $f"; tail -5 "$f"; }
        done
        [ -f "$VPN_RESULTS" ] && cat "$VPN_RESULTS"
        for n in fw1 fw2; do
            echo "--- $n"
            at "$n" 'sudo journalctl -b -u sparewalld --no-pager | tail -40
                timeout 20 sudo sparewall status
                sudo wg show swsync 2>&1; ip -br addr
                sudo conntrackd -C /run/sparewall/conntrackd/conntrackd.conf -s 2>&1 | head -30
                sudo journalctl -b -u sparewalld --no-pager | grep -iE "vrrp|conntrackd" | tail -15
                for u in keepalived conntrackd sparewall-kea; do echo "-- $u"; sudo journalctl -b -u $u --no-pager | tail -15; done
                echo "-- systemd and D-Bus"; sudo journalctl -b _PID=1 + _SYSTEMD_UNIT=dbus-broker.service --no-pager | grep -vE "sparewall-run@" | tail -30
                echo "-- helper jobs"; sudo journalctl -b -u "sparewall-run@*" --no-pager | tail -20
                echo "-- networkd"; sudo journalctl -b -u systemd-networkd --no-pager | grep -iE "swsync|wireguard|key" | tail -15
                echo "-- AVC"; sudo journalctl -b -k --no-pager | grep -oE "avc: +denied.*" | sed -E "s/pid=[0-9]+ //; s/ino=[0-9]+ //" | sort | uniq -c | tail -25
                ls -laZ /run/keepalived/' 2>/dev/null \
                || sudo tail -60 "$n.serial" || true
        done
    fi
    sudo pkill -f "$WORK/echo.py" 2>/dev/null || true
    sudo pkill -f "ping -D -i 0.2" 2>/dev/null || true
    [ -n "${REGISTRY:-}" ] && sudo podman rm -f "$REGISTRY" >/dev/null 2>&1 || true
    for n in fw1 fw2; do
        [ -f "$n.pid" ] && sudo kill "$(sudo cat "$n.pid")" 2>/dev/null || true
    done
}
trap cleanup EXIT

log "booting two nodes"
FW1=(fw1 2231 52:54:00:12:34:56 52:54:00:12:34:57 swtap1 52:54:00:12:34:58 swtap1s)
FW2=(fw2 2232 52:54:00:12:35:56 52:54:00:12:35:57 swtap2 52:54:00:12:35:58 swtap2s)
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "pairing"
k1=$(at fw1 'sudo sparewall status -o json' | jq -r .sync.sync_public_key)
k2=$(at fw2 'sudo sparewall status -o json' | jq -r .sync.sync_public_key)
vpn_keys
sed -e "s|@FW1_KEY@|$k1|" -e "s|@FW2_KEY@|$k2|" "$HERE/site-pair.yaml" | vpn_doc > pair.yaml
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
# After a configuration change Kea HA resynchronizes before serving again.
got_lease() { ns users busybox udhcpc -i eth0 -n -q -t 5 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1; }
wait_for 120 "a DHCP lease from the pair" got_lease
ns users ping -c 2 -W 2 192.0.2.1 >/dev/null || fail "gateway address unreachable"
client_ip() { ns users ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1; }
LEASE=$(client_ip)
LEASES=/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv
fw2_has_lease() { at fw2 "sudo grep -q '^$LEASE,02:00:00:00:00:20' $LEASES"; }
wait_for 60 "fw2 holds the lease of $LEASE (Kea HA)" fw2_has_lease

log "echo servers behind the servers VLAN"
# TCP (7000) and UDP (7001) echo servers in sw-guests. A TCP client sends
# a line every half second on one connection, counting the echoes; the
# UDP client sends a datagram every 0.3 s, logging each reply.
cat > echo.py <<'PY'
import socket, sys, threading, time
def serve(c):
    f = c.makefile("rwb", buffering=0)
    for line in f:
        f.write(line)
if sys.argv[1] == "server":
    # One thread per connection: the LAN and VPN clients run at once.
    s = socket.create_server(("0.0.0.0", 7000))
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
elif sys.argv[1] == "udpserver":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 7001))
    while True:
        d, a = s.recvfrom(64)
        s.sendto(d, a)
elif sys.argv[1] == "udpclient":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    n = 0
    while True:
        n += 1
        s.sendto(str(n).encode(), (sys.argv[2], 7001))
        try:
            s.recvfrom(64)
            print(f"[{time.time():.6f}] reply {n}", flush=True)
        except socket.timeout:
            print(f"[{time.time():.6f}] lost {n}", flush=True)
        time.sleep(0.3)
else:
    c = socket.create_connection((sys.argv[2], 7000), timeout=5)
    c.settimeout(float(sys.argv[3]) if len(sys.argv) > 3 else 30)
    f = c.makefile("rwb", buffering=0)
    n = 0
    while True:
        f.write(b"ping\n")
        if f.readline() != b"ping\n":
            print("broken", flush=True)
            sys.exit(1)
        n += 1
        print(n, flush=True)
        time.sleep(0.5)
PY
ns guests ip addr flush dev eth0
ns guests ip addr add 198.51.100.10/24 dev eth0
ns guests ip route replace default via 198.51.100.1
ns guests python3 "$WORK/echo.py" server &
ns guests python3 "$WORK/echo.py" udpserver &
sleep 1
vpn_setup

log "the LAN cannot reach the peer API, even with a permissive policy"
# A client on users routes to the sync-tunnel addresses through fw1 (issue #3).
ns users ip route replace 169.254.77.0/24 via 192.0.2.2
peer_api() { ns users timeout 3 bash -c "exec 3<>/dev/tcp/$1/8649" 2>/dev/null; }
at fw1 "sudo sparewall set 'policy.users->self.action=accept' --confirm 0"
wait_for 120 "fw1 in sync after opening users->self" in_sync fw1
ns users timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.2/22' 2>/dev/null \
    || fail "users->self accept did not open fw1 to the LAN"
for a in 169.254.77.1 169.254.77.2; do
    ! peer_api "$a" || fail "a LAN client reached the peer API at $a"
done
# A rollback restores the original policy on both nodes and stays (#4).
at fw1 'sudo sparewall rollback'
wait_for 120 "fw1 in sync after the rollback" in_sync fw1
wait_for 120 "fw2 in sync after the rollback" in_sync fw2
sleep 15
for n in fw1 fw2; do
    [ "$(at "$n" "sudo sparewall get 'policy.users->self.action'")" = drop ] \
        || fail "$n does not run the rolled-back policy"
done
! peer_api 169.254.77.1 || fail "a LAN client reached the peer API after the rollback"
ns users ip route del 169.254.77.0/24

log "cutting only the sync VLAN"
for t in swtap1s swtap2s; do sudo bridge vlan del dev "$t" vid 4000; done
state() { at "$1" 'sudo sparewall status -o json' | jq -r .sync.state; }
unreachable() { [ "$(state "$1")" = peer-unreachable ]; }
wait_for 120 "fw1 reports the peer down" unreachable fw1
wait_for 60 "fw2 reports the peer down" unreachable fw2
# VRRP runs on the other VLANs: nothing fails over.
[ "$(role fw1)" = MASTER ] && [ "$(role fw2)" = BACKUP ] \
    || fail "roles changed when only the sync VLAN was cut: fw1 $(role fw1), fw2 $(role fw2)"
for n in fw1 fw2; do
    lvl=$(at "$n" 'sudo sparewall status -o json' | jq -r .health.level)
    [ "$lvl" = degraded ] || fail "$n health is $lvl with the sync VLAN cut, not degraded"
done
if at fw1 'sudo sparewall set dhcp.users.lease_time=1800 --confirm 0' 2>/dev/null; then
    fail "a change was accepted with the peer unreachable and no --allow-diverge"
fi
at fw1 'sudo sparewall set dhcp.users.lease_time=1800 --confirm 0 --allow-diverge'
at fw2 'sudo sparewall set dhcp.users.lease_time=900 --confirm 0 --allow-diverge'
for t in swtap1s swtap2s; do sudo bridge vlan add dev "$t" vid 4000; done
diverged() { [ "$(state "$1")" = diverged ]; }
wait_for 120 "fw1 reports divergence" diverged fw1
wait_for 60 "fw2 reports divergence" diverged fw2
# Nothing merges by itself; an admin picks a side.
at fw2 'sudo sparewall sync --from fw1'
wait_for 120 "fw1 in sync after sync --from" in_sync fw1
wait_for 60 "fw2 in sync after sync --from" in_sync fw2
[ "$(at fw2 'sudo sparewall get dhcp.users.lease_time')" = 1800 ] \
    || fail "fw2 did not take fw1's side: $(at fw2 'sudo sparewall get dhcp.users.lease_time')"
[ "$(role fw1)" = MASTER ] || fail "fw1 is $(role fw1) after the sync VLAN returned"

# Losing a replication-only link locally (issue #6), on the master: health
# degrades, nothing fails over, and replication comes back.
level() { at "$1" 'sudo sparewall status -o json' | jq -r .health.level; }
sync_loss() { # description, command that breaks it on fw1, command that restores it
    log "sync loss on the master: $1"
    at fw1 "$2"
    wait_for 120 "fw1 reports the peer down ($1)" unreachable fw1
    [ "$(level fw1)" = degraded ] || {
        at fw1 'sudo sparewall health --verbose' || true
        fail "fw1 health is $(level fw1) with $1, not degraded"
    }
    at fw1 'sudo sparewall health --verbose' | grep -q '^ *replication *degraded' \
        || fail "the replication check does not report $1"
    sleep 10   # longer than keepalived's fall/rise hold-down
    [ "$(role fw1)" = MASTER ] && [ "$(role fw2)" = BACKUP ] \
        || fail "roles changed with $1: fw1 $(role fw1), fw2 $(role fw2)"
    ns users ping -c 2 -W 2 192.0.2.1 >/dev/null || fail "gateway unreachable with $1"
    at fw1 "$3"
    wait_for 180 "fw1 in sync after restoring $1" in_sync fw1
    wait_for 60 "fw2 in sync after restoring $1" in_sync fw2
    [ "$(role fw1)" = MASTER ] && [ "$(role fw2)" = BACKUP ] \
        || fail "roles changed after restoring $1: fw1 $(role fw1), fw2 $(role fw2)"
    [ "$(level fw1)" = ok ] || fail "fw1 health is $(level fw1) after restoring $1"
}
sync_loss "the sync port down" 'sudo ip link set syncp down' 'sudo ip link set syncp up'
sync_loss "the sync VLAN deleted" 'sudo ip link delete sync' \
    'sudo networkctl reconfigure syncp; sleep 3; ip link show sync >/dev/null 2>&1 || sudo networkctl reload'

log "a connection through the pair"
ns users python3 "$WORK/echo.py" client 198.51.100.10 > flow.log 2>&1 &
echoes() { tail -1 flow.log | grep -qE '^[0-9]+$' && echo "$(tail -1 flow.log)"; }
sleep 3
before=$(echoes) || fail "no echoes through fw1: $(cat flow.log)"
# Let conntrackd send the entry to fw2.
sleep 3
at fw2 'sudo conntrackd -C /run/sparewall/conntrackd/conntrackd.conf -e' | grep -q 'dport=7000' \
    || fail "fw2's external cache does not hold the connection"

vpn_before_loss
log "failover"
sudo kill "$(sudo cat fw1.pid)"; rm -f fw1.pid
vpn_moved "master loss"
wait_for 60 "fw2 master" is_master fw2
ns users ping -c 3 -W 2 192.0.2.1 >/dev/null || fail "gateway address unreachable after failover"
# The same connection keeps going through fw2.
sleep 10
grep -q broken flow.log && fail "the connection broke in the failover: $(tail -5 flow.log)"
after=$(echoes) || fail "the connection stalled: $(tail -5 flow.log)"
sleep 3
[ "$(echoes)" -gt "$after" ] && [ "$after" -gt "$before" ] \
    || fail "the connection stalled after the failover ($before, $after, $(echoes))"
wait_for 60 "fw2 reports the peer down" unreachable fw2
# The client keeps its address, now from fw2. (Without flushing it first:
# the connection above runs from it.)
wait_for 120 "a DHCP lease from fw2" got_lease
[ "$(client_ip)" = "$LEASE" ] || fail "the client got $(client_ip) from fw2, not its lease $LEASE"
vpn_after_move "master loss"
[ -n "${IMAGE:-}" ] || { vpn_summary; log "pair PASS (no IMAGE: rolling upgrade skipped)"; exit 0; }

log "fw1 returns and rejoins as the backup"
start "${FW1[@]}"
wait_for 300 "fw1 SSH" at fw1 true
wait_for 300 "fw1 in sync" in_sync fw1
wait_for 120 "fw2 in sync" in_sync fw2
is_backup() { [ "$(role "$1")" = BACKUP ]; }
wait_for 60 "fw1 backup" is_backup fw1
is_master fw2 || fail "fw2 gave up the gateway when fw1 returned (nopreempt)"

log "a derived image in a local registry"
# QEMU user networking reaches the host at 10.0.2.2.
REGISTRY=sw-registry
sudo podman run -d --name "$REGISTRY" -p 5000:5000 quay.io/libpod/registry:2.8.2 >/dev/null
printf 'FROM %s\nRUN echo upgraded > /usr/share/sparewall/upgrade-marker\n' "$IMAGE" \
    | sudo podman build -t localhost/sparewall:next -f - "$(mktemp -d)"
wait_for 30 "the registry" curl -sf http://127.0.0.1:5000/v2/
sudo podman push --tls-verify=false localhost/sparewall:next docker://127.0.0.1:5000/sparewall:next
NEXT=10.0.2.2:5000/sparewall:next
for n in fw1 fw2; do
    at "$n" 'sudo tee /etc/containers/registries.conf.d/50-test.conf >/dev/null' <<'TOML'
[[registry]]
location = "10.0.2.2:5000"
insecure = true
TOML
done

log "an unsigned image is refused"
if AT_TIMEOUT=600 at fw2 "sudo sparewall upgrade --image $NEXT"; then
    fail "the upgrade to an unsigned image went ahead"
fi
for n in fw1 fw2; do
    upgraded() { at "$1" 'test -e /usr/share/sparewall/upgrade-marker'; }
    ! upgraded "$n" || fail "$n runs the unsigned image"
    at "$n" 'sudo bootc status --format=json' | jq -e '.status.staged == null' >/dev/null \
        || fail "$n staged the unsigned image"
done
is_master fw2 || fail "fw2 is $(role fw2) after the refused upgrade"
wait_for 60 "fw1 in sync after the refused upgrade" in_sync fw1
for n in fw1 fw2; do
    # The image's policy rejects anything unsigned; trust this registry.
    at "$n" 'sudo jq ".transports.docker[\"10.0.2.2:5000\"] = [{\"type\": \"insecureAcceptAnything\"}]" /etc/containers/policy.json > /tmp/policy.json && sudo install -m 0644 /tmp/policy.json /etc/containers/policy.json'
done

log "rolling upgrade from fw2"
before=$(echoes) || fail "the connection is gone before the upgrade: $(tail -3 flow.log)"
# The command follows the upgrade until fw2 itself reboots.
AT_TIMEOUT=1800 vpn_through_upgrade at fw2 "sudo sparewall upgrade --image $NEXT" \
    || fail "the upgrade failed"
wait_for 900 "fw1 on the new image" upgraded fw1
wait_for 600 "fw2 on the new image" upgraded fw2
wait_for 300 "fw2 in sync" in_sync fw2
wait_for 120 "fw1 in sync" in_sync fw1
is_master fw1 || fail "fw1 is $(role fw1) after the upgrade, not MASTER"
at fw2 'sudo bootc status --format=json' | jq -e --arg i "$NEXT" '.status.booted.image.image.image == $i' >/dev/null \
    || fail "fw2 does not track $NEXT"
ns users ping -c 3 -W 2 192.0.2.1 >/dev/null || fail "gateway address unreachable after the upgrade"
grep -q broken flow.log && fail "the connection broke in the upgrade: $(tail -5 flow.log)"
after=$(echoes) || fail "the connection stalled in the upgrade: $(tail -5 flow.log)"
[ "$after" -gt "$before" ] || fail "the connection stalled in the upgrade ($before, $after)"
vpn_after_move "rolling upgrade"
vpn_summary
log "pair PASS (with a rolling upgrade)"
