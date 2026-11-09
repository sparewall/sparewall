#!/bin/bash
# Two-node fault suite (design: "Testing", issue #13), alongside
# pair-test.sh. fw1's trunk is an active-backup bond of two NICs.
#
#   1. A bond member fails on the master: the bond moves to the other
#      member, health degrades, nothing fails over and a connection
#      through the pair keeps going. Then the other member.
#   2. The master loses its whole trunk: the gateway addresses and the
#      connection move to fw2; fw1 returns as the backup.
#   3. One service VLAN is cut on the master's side only (an asymmetric
#      failure): the roles over time are recorded.
#   4. Both nodes are destroyed, reinstalled and restored from their
#      backup bundles, then re-paired with their new sync keys.
#
# IPv6 (#215) is turned on between 1 and 2: a leased WAN by DHCPv6 and a
# delegated /64 on the users network. In 2 an IPv6 connection survives the
# failover and the ISP sees one client; in 3 the new master routes the
# peer's prefix while the ISP's server is down, and then the ISP
# delegates another.
#
#   tests/vm/pair-faults.sh WORKDIR
#       (WORKDIR/output/qcow2/disk.qcow2 from build-disk.sh)
set -euo pipefail
WORK=${1:?usage: pair-faults.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$WORK"
# shellcheck source=vpn.sh
. "$HERE/vpn.sh"
# shellcheck source=pair-lib.sh
. "$HERE/pair-lib.sh"
BOND=1
pair_taps
# shellcheck source=conformance.sh
. "$HERE/conformance.sh"
# shellcheck source=isp6.sh
. "$HERE/isp6.sh"

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        for f in flow.log flow6.log ra.txt vlan-cut.log restore-fw1.txt restore-fw2.txt isp-dhcp.log isp.leases; do
            [ -f "$f" ] && { echo "--- $f"; tail -20 "$f"; }
        done
        [ -z "${V6_DUMP:-}" ] || v6_dump
        dump_nodes
    fi
    selinux_reports
    sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
    sudo pkill -f "$WORK/isp.leases" 2>/dev/null || true
    isp6_stop
    [ -f rest-server.pid ] && kill "$(cat rest-server.pid)" 2>/dev/null || true
    stop_pair
    [ $rc -ne 0 ] || ! declare -F selinux_gate >/dev/null || selinux_gate || exit 1
}
trap cleanup EXIT
v6_dump() {
    set +e
    isp6_dump isp
    echo "--- users"; ns users ip -6 addr show dev eth0; ns users ip -6 route
    local n
    for n in fw1 fw2; do
        echo "--- $n"
        at "$n" 'ip -6 addr; ip -6 route; ip -br link
            networkctl status swwan swgw20 --no-pager -n 0
            sudo journalctl -b -u systemd-networkd --no-pager | grep -iE "dhcp6|ndisc|swgw|swwan|prefix" | tail -40
            sudo journalctl -b -u sparewalld --no-pager | grep -iE "ipv6|prefix|takeover|nft" | tail -20'
        status "$n" | jq -c '.ipv6, (.health.checks[] | select(.name == "ipv6"))'
    done
    set -e
} 2>&1

log "booting two nodes, fw1 with a bonded trunk"
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "pairing"
vpn_keys
pair_doc < "$HERE/site-pair.yaml" | vpn_doc \
    | sed "s|    trunk: { nic: \"${FW1[3]}\" }|    trunk:\n      bond:\n        members: [\"${FW1[3]}\", \"$FW1_BOND_MAC\"]\n        mode: active-backup\n        primary: \"${FW1[3]}\"|" \
    > pair.yaml
grep -q "mode: active-backup" pair.yaml || fail "the bond did not go into the document"
pair_up

# The WAN of a pair with one public address, leased by DHCP to one MAC
# (#54): the master runs the client on the lease link (the VRRP virtual
# MAC), and the backup's own traffic leaves through it. sw-isp leases
# exactly one address, 203.0.113.1, so the lease can only move.
log "the WAN: one lease for the pair"
wan_ns isp 203.0.113.254
ns isp ip addr add 198.18.0.1/32 dev lo
ns isp python3 "$HERE/echo.py" whoami &
ns isp dnsmasq --keep-in-foreground --conf-file=/dev/null --port=0 --user=root \
    --interface=eth0 --bind-interfaces --no-ping --log-dhcp \
    --dhcp-range=203.0.113.1,203.0.113.1,255.255.255.0,10m \
    --dhcp-option=option:router,203.0.113.254 \
    --dhcp-leasefile="$WORK/isp.leases" > isp-dhcp.log 2>&1 &
at fw1 'sudo sparewall merge -f - --confirm 0' <<'JSON'
{"networks": {"wan": {"dhcp_client": true, "vip": null, "extra_vips": null, "gateway": null}},
 "policy": {"servers->wan": {"nat": "masquerade"}},
 "forwards": {"echo-in": null}}
JSON
wait_for 120 "fw1 in sync on the leased WAN" in_sync fw1
wait_for 60 "fw2 in sync on the leased WAN" in_sync fw2
leased() { at "$1" 'ip -4 -br addr show dev swwan' | grep -q ' 203\.0\.113\.1/'; }
lease_on() { # master backup
    leased "$1" || return 1
    at "$2" 'ip -j link show dev swwan' | jq -e '.[0].flags | index("UP") | not' >/dev/null
}
check_lease() { # master backup
    wait_for 90 "the lease on $1, the lease link down on $2" lease_on "$1" "$2"
    local n src
    for n in "$1" "$2"; do
        src=$(egress "$n") || fail "$n cannot reach the outside"
        [ "$src" = 203.0.113.1 ] || fail "$n reached the outside as $src, not 203.0.113.1"
    done
    # One MAC, one client: the ISP holds a single lease.
    [ "$(grep -c . "$WORK/isp.leases")" = 1 ] || fail "the ISP holds more than one lease: $(cat "$WORK/isp.leases")"
    grep -q ' 00:00:5e:00:01:0a 203.0.113.1 ' "$WORK/isp.leases" \
        || fail "the lease is not the virtual MAC's: $(cat "$WORK/isp.leases")"
}
check_lease fw1 fw2

log "a connection through the pair"
dhcp_script
got_lease() { ns users busybox udhcpc -i eth0 -n -q -t 5 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1; }
ns users ip addr flush dev eth0
wait_for 120 "a DHCP lease from the pair" got_lease
ns guests ip addr flush dev eth0
ns guests ip addr add 198.51.100.10/24 dev eth0
ns guests ip route replace default via 198.51.100.1
ns guests python3 "$HERE/echo.py" server &
sleep 1
ns users python3 "$HERE/echo.py" client 198.51.100.10 > flow.log 2>&1 &
echoes() { local f=${1:-flow.log}; tail -1 "$f" | grep -qE '^[0-9]+$' && tail -1 "$f"; }
sleep 3
echoes >/dev/null || fail "no echoes through fw1: $(cat flow.log)"
# The connection is still going, and has made progress since $1.
flowing() { # previous count, description[, its log]
    local now f=${3:-flow.log}
    grep -q broken "$f" && fail "the connection broke ($2): $(tail -5 "$f")"
    sleep 3
    now=$(echoes "$f") || fail "the connection stalled ($2): $(tail -5 "$f")"
    [ "$now" -gt "$1" ] || fail "the connection stalled ($2): $1, then $now"
    echo "$now"
}
gateway() { ns users ping -c 2 -W 2 192.0.2.1 >/dev/null; }
check() { status "$1" | jq -r --arg c "$2" '.health.checks[] | select(.name == $c) | .level'; }

# --- 1. bond members
active() { at fw1 'cat /sys/class/net/trunk/bonding/active_slave'; }
# The QEMU netdev of the member with this name.
netdev() {
    local mac
    mac=$(at fw1 "ip -j link show dev $1" | jq -r '.[0].permaddr // .[0].address')
    case $mac in
    "${FW1[3]}") echo n1 ;;
    "$FW1_BOND_MAC") echo n3 ;;
    *) fail "member $1 has an unknown MAC $mac" ;;
    esac
}
[ "$(check fw1 bonds)" = ok ] || fail "fw1's bonds check is $(check fw1 bonds)"
count=$(echoes)
for round in first second; do
    log "the $round bond member fails on the master"
    member=$(active)
    nd=$(netdev "$member")
    monitor fw1 set_link "$nd" off
    moved() { [ "$(active)" != "$member" ]; }
    wait_for 30 "the bond leaves $member" moved
    bond_degraded() { [ "$(check fw1 bonds)" = degraded ]; }
    wait_for 60 "fw1 reports the bond degraded" bond_degraded
    [ "$(level fw1)" = degraded ] || fail "fw1 health is $(level fw1) with a bond member down"
    sleep 10   # longer than keepalived's fall/rise hold-down
    roles_are MASTER BACKUP "a bond member failed"
    gateway || fail "gateway unreachable with a bond member down"
    count=$(flowing "$count" "a bond member down")
    monitor fw1 set_link "$nd" on
    bond_ok() { [ "$(check fw1 bonds)" = ok ]; }
    wait_for 60 "fw1's bond whole again" bond_ok
    roles_are MASTER BACKUP "a bond member returned"
    count=$(flowing "$count" "a bond member returned")
done
[ "$(level fw1)" = ok ] || fail "fw1 health is $(level fw1) with the bond whole"

# --- IPv6 across the pair (#215)
# The master alone runs the DHCPv6 client, on the lease link, with a DUID
# from the WAN's virtual MAC and a fixed IAID, so the ISP sees one client
# whichever node asks. The users network's gateway is fe80::1 on the IPv6
# virtual MAC (vrid 20), up on the master only, routing a /64 of the
# delegated prefix. The failovers below check that it all moves.
log "IPv6: one DHCPv6 client for the pair, the gateway at fe80::1 (#215)"
isp6_start isp
kea6_start isp 2001:db8:100::
ns isp python3 "$HERE/echo.py" server &
at fw1 'sudo sparewall merge -f - --confirm 0' <<'JSON'
{"networks": {"wan": {"ipv6": {"mode": "dhcpv6"}},
              "users": {"ipv6": {"mode": "delegated", "subnet_id": 1}}},
 "policy": {"users->wan": {"action": "accept"}}}
JSON
V6_DUMP=1
wait_for 120 "fw1 in sync with IPv6" in_sync fw1
wait_for 60 "fw2 in sync with IPv6" in_sync fw2
VDUID=00:03:00:01:00:00:5e:00:01:0a # DUID-LL of the WAN's virtual MAC
wan6() { at "$1" 'ip -6 -br addr show dev swwan scope global' | grep -o '2001:db8:ffff::1[0-9a-f][0-9a-f]'; }
wait_for 120 "fw1's WAN address by DHCPv6" wan6 fw1
a6=$(wan6 fw1 | head -1)
# Kea's lease file:
# address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,...
clients6() { sudo awk -F, 'NR > 1 {print $2 " iaid " $8}' "$KEA6_LEASES" | sort -u; }
one_client6() {
    [ "$(clients6)" = "$VDUID iaid 10" ] \
        || fail "the ISP's DHCPv6 leases are not all the pair's DUID $VDUID with IAID 10: $(clients6)"
}
pd6() { sudo awk -F, -v d="$VDUID" -v p="$1" '$7 == 2 && $2 == d && $1 == p' "$KEA6_LEASES" | grep -q .; }
wait_for 60 "2001:db8:100::/56 delegated to the pair's DUID" pd6 2001:db8:100::
one_client6
# The ISP routes what it delegates to the link-local address the request
# came from, which is the virtual MAC's on either node.
swwan_ll() { at "$1" 'ip -6 -br addr show dev swwan scope link' | grep -o 'fe80::[0-9a-f:]*' | head -1; }
ll6=$(swwan_ll fw1)
[ -n "$ll6" ] || fail "fw1's swwan has no link-local address"
ns isp ip -6 route add 2001:db8:100::/48 via "$ll6" dev eth0
ns isp ip -6 route add 2001:db8:200::/48 via "$ll6" dev eth0

# The client: the flush above took its link-local address too.
ns users ip -6 addr add fe80::20/64 dev eth0 nodad 2>/dev/null || true
P6=2001:db8:100:1::
client6() { # the client's SLAAC address in prefix $1 (2001:db8:...:1::)
    # A solicitation, for an advertisement now rather than at the next
    # interval. Match on the prefix's four groups (ip compresses zero
    # groups, but this prefix's fourth group is not zero).
    ns users rdisc6 -1 eth0 >/dev/null 2>&1 || true
    ns users ip -6 -br addr show dev eth0 scope global -tentative \
        | grep -o "${1%::}:[0-9a-f:]*" | head -1 | grep .
}
wait_for 90 "the client's SLAAC address in $P6/64" client6 "$P6"
c6=$(client6 "$P6")
# An advertisement from fe80::1, sent from the IPv6 virtual MAC, with the
# prefix in it.
ra_from_gateway() { # prefix
    ns users rdisc6 -1 eth0 > ra.txt 2>&1 || return 1
    grep -q "from fe80::1\$" ra.txt && grep -qi "link-layer address: *00:00:5e:00:02:14" ra.txt \
        && grep -q "Prefix *: *$1/64" ra.txt
}
ra_from_gateway "$P6" || fail "no advertisement of $P6/64 from fe80::1 on 00:00:5e:00:02:14: $(cat ra.txt)"
ns users ip -6 route show default | grep -q 'via fe80::1 ' \
    || fail "the client's IPv6 default route is not fe80::1: $(ns users ip -6 route show default)"
ns users ping -6 -c 2 -W 2 2001:db8:ffff::1 >/dev/null || fail "the client cannot reach the ISP over IPv6"
ns users python3 "$HERE/echo.py" client 2001:db8:ffff::1 > flow6.log 2>&1 &
sleep 3
count6=$(echoes flow6.log) || fail "no IPv6 echoes through fw1: $(cat flow6.log)"
# The gateway link is up on the master only, and the backup has no WAN
# address: it sends nothing of IPv6's on either side.
gw_flags() { at "$1" 'ip -j link show dev swgw20' | jq -c '.[0].flags'; }
gw_up() { gw_flags "$1" | jq -e 'index("UP")' >/dev/null; }
gw_down() { gw_flags "$1" | jq -e 'index("UP") | not' >/dev/null; }
gw_tx() { at "$1" 'cat /sys/class/net/swgw20/statistics/tx_packets'; }
silent6() { # backup
    gw_down "$1" || fail "$1 (backup) has its IPv6 gateway link up: $(gw_flags "$1")"
    ! wan6 "$1" >/dev/null || fail "$1 (backup) holds a DHCPv6 address: $(wan6 "$1")"
    local tx; tx=$(gw_tx "$1")
    sleep 10
    [ "$(gw_tx "$1")" = "$tx" ] || fail "$1 (backup) sent from its IPv6 gateway link ($tx, then $(gw_tx "$1") packets)"
}
gw_up fw1 || fail "fw1 (master) has its IPv6 gateway link down: $(gw_flags fw1)"
silent6 fw2
healthy() { [ "$(level "$1")" = ok ]; }
wait_for 60 "fw1 healthy with IPv6" healthy fw1
[ "$(check fw1 ipv6)" = ok ] || fail "fw1's ipv6 check is $(check fw1 ipv6)"
[ "$(check fw2 ipv6)" = ok ] || fail "fw2's ipv6 check (the standby's) is $(check fw2 ipv6)"
count=$(flowing "$count" "IPv6 turned on")

# --- 2. the whole trunk
log "the master loses its whole trunk"
monitor fw1 set_link n1 off
monitor fw1 set_link n3 off
wait_for 60 "fw2 master" is_master fw2
gateway || fail "gateway unreachable after the trunk failover"
sleep 5
count=$(flowing "$count" "the trunk failover")
# The IPv6 connection too, from the same address, and fw2 advertises the
# same prefix from fe80::1, having asked the ISP as the same client.
count6=$(flowing "$count6" "the trunk failover, over IPv6" flow6.log)
ns users ip -6 -br addr show dev eth0 | grep -q "$c6" || fail "the client lost $c6 in the failover"
wait_for 30 "fw2 advertising $P6/64 from fe80::1" ra_from_gateway "$P6"
wait_for 60 "fw2's WAN address by DHCPv6" wan6 fw2
[ "$(wan6 fw2 | head -1)" = "$a6" ] || fail "fw2 was given $(wan6 fw2), not the pair's $a6"
[ "$(swwan_ll fw2)" = "$ll6" ] || fail "fw2's swwan is $(swwan_ll fw2), not $ll6 as fw1's was"
one_client6
[ "$(level fw1)" = failed ] || fail "fw1 health is $(level fw1) without its trunk"
monitor fw1 set_link n1 on
monitor fw1 set_link n3 on
wait_for 120 "fw1 back as the backup" is_backup fw1
is_master fw2 || fail "fw2 gave up the gateway when fw1's trunk returned (nopreempt)"
check_lease fw2 fw1
wait_for 120 "fw1 healthy" healthy fw1
count=$(flowing "$count" "fw1's trunk returned")
count6=$(flowing "$count6" "fw1's trunk returned, over IPv6" flow6.log)
silent6 fw1

# --- 3. one service VLAN cut on the master's side
# Every link stays up, so only the coordinators' ARP probes see it: fw2
# hears neither fw1 nor any host on the users network while fw1 does, so
# fw2 fails health and the gateway moves to fw1.
log "the users VLAN cut on fw2's side only"
# With the ISP's DHCPv6 server down: fw1 takes over the prefix fw2 last
# told it of (#215), and routes it until the ISP answers again, now with
# another prefix (as a new client, its old bindings gone).
kea6_stop
sudo bridge vlan del dev swtap2 vid 20
: > vlan-cut.log
moved=
for _ in $(seq 1 60); do
    if gateway; then gw=up; else gw=down; fi
    printf '%s fw1=%s fw2=%s gateway=%s fw2-reach=%s\n' "$(date +%T)" "$(role fw1)" "$(role fw2)" "$gw" \
        "$(check fw2 reach | sort -u | tr '\n' ' ')" | tee -a vlan-cut.log
    if [ "$gw" = up ] && is_master fw1; then moved=1; break; fi
    sleep 3
done
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### users VLAN cut on the master's side"
        echo '```'; cat vlan-cut.log; echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi
[ -n "$moved" ] || fail "the gateway did not move to fw1 within 180 s of the users VLAN cut on fw2"
status fw2 | jq -r '.health.checks[] | select(.name == "reach") | .message'
log "fw1 takes over the prefix, then the ISP renumbers it (#215)"
takeover() { at fw1 "ip -6 route show ${P6}/64 dev swgw20 proto static" | grep -q expires; }
takeover || fail "fw1 does not route the peer's $P6/64: $(at fw1 'ip -6 route show dev swgw20')"
ns users ping -6 -c 2 -W 2 -I "$c6" 2001:db8:ffff::1 >/dev/null \
    || fail "the client cannot reach the ISP from $c6 while fw1 holds the peer's prefix"
kea6_start isp 2001:db8:200::
P6B=2001:db8:200:1::
wait_for 150 "fw1 advertising $P6B/64 from fe80::1" ra_from_gateway "$P6B"
wait_for 60 "the client's address in $P6B/64" client6 "$P6B"
c6b=$(client6 "$P6B")
ns users ping -6 -c 2 -W 2 -I "$c6b" 2001:db8:ffff::1 >/dev/null || fail "the client cannot reach the ISP from $c6b"
one_client6
check fw2 reach | grep -qx failed || fail "fw2's reach check is not failed: $(check fw2 reach)"
sudo bridge vlan add dev swtap2 vid 20
reach_ok() { [ -z "$(check fw2 reach)" ] && healthy fw2; }
wait_for 120 "fw2 healthy again after the VLAN returned" reach_ok
wait_for 60 "fw2 back as the backup" is_backup fw2
is_master fw1 || fail "fw1 gave up the gateway when fw2's VLAN returned (nopreempt)"
check_lease fw1 fw2
settle() { in_sync fw1 && in_sync fw2; }
wait_for 120 "the pair in sync again" settle

# --- 4. both nodes destroyed and restored
log "backups of both nodes"
sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
start_rest_server
REPO=rest:http://10.0.2.2:8000/pair
PASSWORD="ci backup password"
at fw1 "printf %s '$PASSWORD' | sudo sparewall secret set backup-password"
at fw1 "sudo sparewall set backup.enabled=true backup.repository=$REPO --confirm 0"
gen=$(status fw1 | jq .sync.active)
for n in fw1 fw2; do wait_for 120 "$n settled on generation $gen" settled "$n" "$gen"; done
has_secret() { at fw2 'sudo sparewall secret list' | grep -q backup-password; }
wait_for 60 "the backup password on fw2" has_secret
LEASES=/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv
LEASE=$(ns users ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1)
for n in fw1 fw2; do
    at "$n" "sudo grep -q '^$LEASE,' $LEASES" || fail "$n does not hold the lease of $LEASE"
    at "$n" 'sudo sparewall backup' 2>&1 | grep -q snapshot || fail "$n's bundle was not sent"
    at "$n" 'sudo sparewall secret list -o json' | jq -c '[.[].name]' > "secrets-$n.json"
done
# The document as each node had it, without the sync keys (new installs
# get new ones).
unkeyed() { at "$1" 'sudo sparewall export -o json' | jq -S 'del(.cluster.sync_keys)'; }
unkeyed fw1 > before.json

log "destroying both nodes"
# Their reports go with them: take them now.
selinux_reports
stop_pair
for n in fw1 fw2; do rm -f "$n.qcow2"; done
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "restoring both nodes"
for n in fw1 fw2; do
    [ "$(role "$n")" = bootstrap ] || fail "the reinstalled $n is not in bootstrap mode"
    full_audit "at $n" "$n"
    at "$n" 'sudo systemctl stop sparewalld.socket sparewalld.service'
    at "$n" "printf '%s\n' '$PASSWORD' > /tmp/pw"
    at "$n" "sudo sparewall restore --repository $REPO --password-file /tmp/pw" 2>&1 | tee "restore-$n.txt"
    grep -qE '[0-9]+ secrets' "restore-$n.txt" || fail "$n's secrets were not restored"
    at "$n" "sudo grep -q '^$LEASE,' $LEASES" || fail "$n's leases were not restored"
    at "$n" 'sudo systemctl start sparewalld.socket sparewalld.service' || true
done
for n in fw1 fw2; do
    restored() { status "$1" | jq -e '.sync.active > 0' >/dev/null; }
    wait_for 120 "$n runs the restored generation" restored "$n"
    [ "$(unkeyed "$n")" = "$(cat before.json)" ] || {
        diff -u before.json <(unkeyed "$n") || true
        fail "$n's restored document differs"
    }
    [ "$(at "$n" 'sudo sparewall secret list -o json' | jq -c '[.[].name]')" = "$(cat "secrets-$n.json")" ] \
        || fail "$n's secrets differ after the restore"
done

log "re-pairing with the new sync keys"
k1=$(status fw1 | jq -r .sync.sync_public_key)
k2=$(status fw2 | jq -r .sync.sync_public_key)
for n in fw1 fw2; do
    at "$n" "sudo sparewall set cluster.sync_keys.fw1=$k1 cluster.sync_keys.fw2=$k2 --confirm 0 --allow-diverge"
done
wait_for 300 "fw1 in sync" in_sync fw1
wait_for 120 "fw2 in sync" in_sync fw2
roles_ok() { [ "$(role fw1)" != "$(role fw2)" ] && { is_master fw1 || is_master fw2; }; }
wait_for 120 "one master" roles_ok
gateway || fail "gateway unreachable after the restore"
# The client keeps its address.
ns users ip addr flush dev eth0
wait_for 120 "a DHCP lease after the restore" got_lease
got=$(ns users ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1)
[ "$got" = "$LEASE" ] || fail "the client got $got after the restore, not its lease $LEASE"

# The restored secrets work, not just their names: a new backup seals the
# secrets with the restored backup-password and opens the same restic
# repository with it.
for n in fw1 fw2; do
    at "$n" 'sudo sparewall backup' > "after-$n.txt" 2>&1 || fail "$n: backup after the restore failed: $(cat "after-$n.txt")"
    grep -q snapshot "after-$n.txt" || fail "$n: the post-restore bundle was not sent: $(cat "after-$n.txt")"
    ! grep -q 'no cluster secrets' "after-$n.txt" || fail "$n: the post-restore bundle left out the secrets"
done
log "pair faults PASS"
