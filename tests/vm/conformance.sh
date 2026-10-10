#!/bin/bash
# Policy conformance, DHCP and DNS across VLANs (design: milestones 1-2).
# Sourced by boot-test.sh with the VM running and $WORK, vm(), fail() set;
# the VM's second NIC is the trunk tap created by setup_trunk.
set -euo pipefail

ns() { local n=$1; shift; sudo ip netns exec "sw-$n" "$@"; }

setup_trunk() {
    sudo ip link add swbr type bridge vlan_filtering 1
    sudo ip link set swbr up
    sudo ip tuntap add swtap0 mode tap
    sudo ip link set swtap0 master swbr up
    sudo bridge vlan del dev swtap0 vid 1
    sudo bridge vlan add dev swtap0 vid 20
    sudo bridge vlan add dev swtap0 vid 30
    for c in users:20:02:00:00:00:00:20 guests:30:02:00:00:00:00:30; do
        local name=${c%%:*} rest=${c#*:}
        local vid=${rest%%:*} mac=${rest#*:}
        sudo ip netns add "sw-$name"
        sudo ip link add "v-$name" type veth peer name eth0 netns "sw-$name"
        sudo ip link set "v-$name" master swbr up
        sudo bridge vlan del dev "v-$name" vid 1
        sudo bridge vlan add dev "v-$name" vid "$vid" pvid untagged
        ns "$name" ip link set lo up
        ns "$name" ip link set eth0 address "$mac" up
    done
}

dhcp_script() {
    cat > "$WORK/udhcpc.sh" <<'SH'
#!/bin/sh
case "$1" in
bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "${router%% *}"
    echo "$ip" > "/tmp/lease-$interface-$(cat /proc/sys/kernel/hostname 2>/dev/null)"
    ;;
esac
SH
    chmod +x "$WORK/udhcpc.sh"
}

lease() {
    ns "$1" busybox udhcpc -i eth0 -n -q -t 10 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1 \
        || fail "no DHCP lease on $1"
    ns "$1" ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1
}

can() { ns "$1" ping -c 2 -W 2 "$2" >/dev/null 2>&1; }

run_conformance() {
    log "conformance: VLANs, DHCP, DNS and the zone policy"
    vm 'cat > /tmp/vlans.yaml' < "$HERE/site-vlans.yaml"
    vm 'sudo sparewall apply -f /tmp/vlans.yaml --confirm 0'
    local deadline=$((SECONDS + 180))
    until vm 'sudo sparewall health' >/dev/null 2>&1; do
        if [ $SECONDS -ge $deadline ]; then
            vm 'sudo sparewall health --verbose' || true
            vm 'for u in sparewall-kea sparewall-unbound; do sudo systemctl status --no-pager -l $u; sudo journalctl -b -u $u --no-pager | tail -40; done' || true
            vm 'sudo podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage ps -a; sudo systemctl cat sparewall-kea.service | head -60; sudo journalctl -b -k --no-pager | grep -oE "avc: +denied.*" | sort | uniq -c | tail -20' || true
            fail "health not ok after the VLAN apply"
        fi
        sleep 5
    done
    vm 'sudo sparewall health --verbose'

    dhcp_script
    local u g
    u=$(lease users); g=$(lease guests)
    log "leases: users $u, guests $g"
    [ "$u" = 192.0.2.20 ] || fail "reservation not honoured: users got $u"
    case "$g" in 198.51.100.1[0-4][0-9]|198.51.100.150) ;; *) fail "guests lease $g outside the pool" ;; esac

    can users 192.0.2.1 || fail "users cannot ping the gateway"
    can users "$g" || fail "users cannot reach guests"
    ! can guests "$u" || fail "guests reached users"
    ! can guests 198.51.100.1 || fail "guests could ping the firewall"

    local a
    a=$(ns users dig +short +time=3 +tries=3 @192.0.2.1 printer.home.arpa) || true
    [ "$a" = 192.0.2.9 ] || fail "local DNS record: got '$a'"
    a=$(ns users dig +short +time=3 +tries=3 @192.0.2.1 client20.home.arpa) || true
    [ "$a" = 192.0.2.20 ] || fail "reservation name: got '$a'"
    vm 'sudo nft list chain inet sparewall fwd_guests_users' | grep -q 'packets [1-9]' \
        || fail "the guests->users default drop counted nothing"
    log "conformance PASS"
}
