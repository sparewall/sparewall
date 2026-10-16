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
# shellcheck source=vpn.sh
. "$HERE/vpn.sh"

# shellcheck source=pair-lib.sh
. "$HERE/pair-lib.sh"
pair_taps

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        [ -f flow.log ] && { echo "--- flow.log"; tail -5 flow.log; }
        [ -f fwd.log ] && { echo "--- fwd.log"; tail -5 fwd.log; }
        for c in $VPN_CLIENTS; do
            echo "--- VPN client $c"; ns "$c" wg show wg0 2>/dev/null || true
        done
        for f in vpn-tcp.log vpn-udp.log vpna.ping natc.ping upgrade.log; do
            [ -f "$f" ] && { echo "--- $f"; tail -5 "$f"; }
        done
        [ -f "$VPN_RESULTS" ] && cat "$VPN_RESULTS"
        dump_nodes
    fi
    selinux_reports
    sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
    sudo pkill -f "ping -D -i 0.2" 2>/dev/null || true
    [ -n "${REGISTRY:-}" ] && sudo podman rm -f "$REGISTRY" >/dev/null 2>&1 || true
    stop_pair
    [ $rc -ne 0 ] || ! declare -F selinux_gate >/dev/null || selinux_gate || exit 1
}
trap cleanup EXIT

log "booting two nodes"
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "pairing"
vpn_keys
pair_doc < "$HERE/site-pair.yaml" | vpn_doc > pair.yaml
pair_up

log "a change on fw1 reaches fw2"
at fw1 'sudo sparewall set dhcp.users.lease_time=3600 --confirm 0'
gen=$(at fw1 'sudo sparewall status -o json' | jq .sync.active)
fw2_gen() { [ "$(at fw2 'sudo sparewall status -o json' | jq .sync.active)" = "$gen" ]; }
wait_for 120 "fw2 at generation $gen" fw2_gen

# A change to the sync link goes to the peer first, through the current
# link; each node keeps it once the peer confirms over the new one (#25).
move_sync() { # fw1-address fw2-address
    log "moving the sync link to $1 and $2"
    at fw1 "sudo sparewall set networks.sync.addresses.fw1=$1/30 networks.sync.addresses.fw2=$2/30 --confirm 0"
    gen=$(at fw1 'sudo sparewall status -o json' | jq .sync.active)
    for n in fw1 fw2; do wait_for 240 "$n settled on generation $gen" settled "$n" "$gen"; done
    at fw2 "ip -br addr show sync" | grep -q "$2/30" || fail "fw2's sync address is not $2"
    at fw1 "sudo wg show swsync endpoints" | grep -q "$2:" || fail "fw1's tunnel does not reach $2"
}
move_sync 10.255.1.1 10.255.1.2
move_sync 10.255.0.1 10.255.0.2

# The admin never confirms: fw1 reverts at its deadline; fw2 confirmed the
# change over the new link but stays in doubt, finds fw1 again on the old
# link, and follows it back (review of #34).
log "an unconfirmed sync-link move reverts on both nodes"
before=$(at fw1 'sudo sparewall status -o json' | jq .sync.active)
at fw1 "sudo sparewall set networks.sync.addresses.fw1=10.255.1.1/30 networks.sync.addresses.fw2=10.255.1.2/30 --confirm 30 --no-prompt"
in_doubt() { at fw2 'sudo sparewall status -o json' | jq -e '.health.checks[] | select(.name == "applied") | .message | test("in doubt")' >/dev/null; }
wait_for 120 "fw2 holds the move in doubt" in_doubt
for n in fw1 fw2; do wait_for 420 "$n back on generation $before" settled "$n" "$before"; done
at fw2 "ip -br addr show sync" | grep -q "10.255.0.2/30" || fail "fw2 is not back on the old sync address"

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

log "the WAN: private node addresses, the public ones on the master (#54)"
# sw-isp is the ISP's gateway (203.0.113.254), with an outside address
# behind it answering with the source each connection came from.
wan_ns isp 203.0.113.254
ns isp ip addr add 198.18.0.1/32 dev lo
ns isp python3 "$HERE/echo.py" whoami &
public_route() { at "$1" 'ip route show default' | grep -q 'via 203.0.113.254 dev wan'; }
check_wan() { # master backup
    public_route "$1" || fail "$1 (master) has no default route via the ISP: $(at "$1" 'ip route show default')"
    ! public_route "$2" || fail "$2 (backup) has the public default route"
    local n src
    for n in "$1" "$2"; do
        src=$(egress "$n") || fail "$n cannot reach the outside"
        [ "$src" = 203.0.113.1 ] || fail "$n reached the outside as $src, not 203.0.113.1"
    done
}
wait_for 30 "fw1 reaches the outside" egress fw1
check_wan fw1 fw2

# Staging beside another gateway (#51): held, the pair runs and stays in
# sync but claims no gateway address and offers no lease; released, it
# takes over. Twice, so a hold after a release is covered too.
gateway_up() { ns users ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; }
gateway_down() { ! gateway_up; }
fw2_backup() { [ "$(role fw2)" = BACKUP ]; }
both_held() {
    [ "$(role fw1)" = FAULT ] && [ "$(role fw2)" = FAULT ] \
        && status fw1 | jq -e '.health.checks[] | select(.name == "held")' >/dev/null \
        && status fw2 | jq -e '.health.checks[] | select(.name == "held")' >/dev/null
}
for round in 1 2; do
    log "held (round $round): no gateway address, no lease"
    at fw1 'sudo sparewall set cluster.hold=true --confirm 0'
    wait_for 120 "both nodes held, in FAULT" both_held
    wait_for 30 "the gateway address gone" gateway_down
    ! public_route fw1 && ! public_route fw2 || fail "a held node has the public default route"
    wait_for 120 "fw1 in sync while held" in_sync fw1
    wait_for 60 "fw2 in sync while held" in_sync fw2
    ! got_lease || fail "DHCP offered a lease while held"
    log "released (round $round)"
    at fw1 'sudo sparewall set cluster.hold=false --confirm 0'
    wait_for 120 "fw1 master again" is_master fw1
    wait_for 30 "the gateway address back" gateway_up
    wait_for 120 "fw1 in sync after the release" in_sync fw1
    wait_for 60 "fw2 BACKUP after the release" fw2_backup
done
check_wan fw1 fw2
wait_for 120 "a DHCP lease again after the release" got_lease
[ "$(client_ip)" = "$LEASE" ] || fail "the client got $(client_ip) after the hold, not its lease $LEASE"

log "echo servers behind the servers VLAN"
# TCP (7000) and UDP (7001) echo servers in sw-guests. A TCP client sends
# a line every half second on one connection, counting the echoes; the
# UDP client sends a datagram every 0.3 s, logging each reply.
ns guests ip addr flush dev eth0
ns guests ip addr add 198.51.100.10/24 dev eth0
ns guests ip route replace default via 198.51.100.1
ns guests python3 "$HERE/echo.py" server &
ns guests python3 "$HERE/echo.py" udpserver &
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
ns users python3 "$HERE/echo.py" client 198.51.100.10 > flow.log 2>&1 &
echoes() { tail -1 flow.log | grep -qE '^[0-9]+$' && echo "$(tail -1 flow.log)"; }
sleep 3
before=$(echoes) || fail "no echoes through fw1: $(cat flow.log)"
# Let conntrackd send the entry to fw2.
sleep 3
at fw2 'sudo conntrackd -C /run/sparewall/conntrackd/conntrackd.conf -e' | grep -q 'dport=7000' \
    || fail "fw2's external cache does not hold the connection"

log "an extra gateway address: a forward in, SNAT out"
# From the WAN, a connection to 203.0.113.5 reaches the echo server in
# sw-guests (forwards.echo-in); it must survive the failover below.
wan_ns inet 203.0.113.60
ns inet python3 "$HERE/echo.py" client 203.0.113.5 > fwd.log 2>&1 &
fwd_echoes() { tail -1 fwd.log | grep -qE '^[0-9]+$' && echo "$(tail -1 fwd.log)"; }
sleep 3
fwd_before=$(fwd_echoes) || fail "no echoes through the forward on 203.0.113.5: $(cat fwd.log)"
# The servers network reaches the WAN as 203.0.113.5 (policy servers->wan).
ns inet python3 -c 'import socket
s = socket.create_server(("0.0.0.0", 7002))
c, a = s.accept()
c.sendall(a[0].encode() + b"\n")' &
sleep 1
seen=$(ns guests python3 -c 'import socket
c = socket.create_connection(("203.0.113.60", 7002), timeout=5)
print(c.makefile().readline().strip())') || fail "the servers network cannot reach the WAN"
[ "$seen" = 203.0.113.5 ] || fail "the servers network reached the WAN as $seen, not 203.0.113.5"

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
# And the one to the extra gateway address, now held by fw2.
grep -q broken fwd.log && fail "the forwarded connection broke in the failover: $(tail -5 fwd.log)"
fwd_after=$(fwd_echoes) || fail "the forwarded connection stalled: $(tail -5 fwd.log)"
[ "$fwd_after" -gt "$fwd_before" ] \
    || fail "the forwarded connection stalled after the failover ($fwd_before, $fwd_after)"
at fw2 'ip -br addr show wan' | grep -q '203.0.113.5/24' || fail "fw2 does not hold 203.0.113.5"
public_route fw2 || fail "fw2 has no default route via the ISP after the failover"
src=$(egress fw2) || fail "fw2 cannot reach the outside after the failover"
[ "$src" = 203.0.113.1 ] || fail "fw2 reached the outside as $src after the failover"
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
wait_for 60 "fw1 backup" is_backup fw1
is_master fw2 || fail "fw2 gave up the gateway when fw1 returned (nopreempt)"
check_wan fw2 fw1

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
