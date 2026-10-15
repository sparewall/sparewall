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

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        for f in flow.log vlan-cut.log restore-fw1.txt restore-fw2.txt; do
            [ -f "$f" ] && { echo "--- $f"; tail -20 "$f"; }
        done
        dump_nodes
    fi
    sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
    [ -f rest-server.pid ] && kill "$(cat rest-server.pid)" 2>/dev/null || true
    stop_pair
}
trap cleanup EXIT

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
echoes() { tail -1 flow.log | grep -qE '^[0-9]+$' && tail -1 flow.log; }
sleep 3
echoes >/dev/null || fail "no echoes through fw1: $(cat flow.log)"
# The connection is still going, and has made progress since $1.
flowing() { # previous count, description
    local now
    grep -q broken flow.log && fail "the connection broke ($2): $(tail -5 flow.log)"
    sleep 3
    now=$(echoes) || fail "the connection stalled ($2): $(tail -5 flow.log)"
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

# --- 2. the whole trunk
log "the master loses its whole trunk"
monitor fw1 set_link n1 off
monitor fw1 set_link n3 off
wait_for 60 "fw2 master" is_master fw2
gateway || fail "gateway unreachable after the trunk failover"
sleep 5
count=$(flowing "$count" "the trunk failover")
[ "$(level fw1)" = failed ] || fail "fw1 health is $(level fw1) without its trunk"
monitor fw1 set_link n1 on
monitor fw1 set_link n3 on
wait_for 120 "fw1 back as the backup" is_backup fw1
is_master fw2 || fail "fw2 gave up the gateway when fw1's trunk returned (nopreempt)"
healthy() { [ "$(level "$1")" = ok ]; }
wait_for 120 "fw1 healthy" healthy fw1
count=$(flowing "$count" "fw1's trunk returned")

# --- 3. one service VLAN cut on the master's side
log "the users VLAN cut on fw2's side only"
sudo bridge vlan del dev swtap2 vid 20
: > vlan-cut.log
for _ in $(seq 1 30); do
    if gateway; then gw=up; else gw=down; fi
    printf '%s fw1=%s fw2=%s gateway=%s\n' "$(date +%T)" "$(role fw1)" "$(role fw2)" "$gw" | tee -a vlan-cut.log
    sleep 3
done
sudo bridge vlan add dev swtap2 vid 20
settle() { [ "$(role fw1)" != "$(role fw2)" ] && in_sync fw1 && in_sync fw2; }
wait_for 180 "one master again after the VLAN returned" settle
transitions=$(awk '{print $2, $3}' vlan-cut.log | uniq | wc -l)
echo "users VLAN cut: $transitions distinct role states in 90 s"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### users VLAN cut on the master's side"
        echo '```'; cat vlan-cut.log; echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi

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
stop_pair
for n in fw1 fw2; do rm -f "$n.qcow2"; done
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH" at fw1 true
wait_for 300 "fw2 SSH" at fw2 true

log "restoring both nodes"
for n in fw1 fw2; do
    [ "$(role "$n")" = bootstrap ] || fail "the reinstalled $n is not in bootstrap mode"
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
