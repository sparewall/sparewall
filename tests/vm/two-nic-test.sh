#!/bin/bash
# Two-NIC nodes behind plain switches, with no VLANs at all (#177): the WAN
# on one port, and on the other one segment that is the LAN, the
# management network and, in a pair, the sync network. The nodes have no
# other NIC: they are managed over the LAN, from sw-tadmin, as a site's
# admin would.
#
#   1. A standalone node: management, DHCP and forwarding on the LAN NIC;
#      management.sources admits the admin's SSH and refuses another LAN
#      host's, which may still ping the node; a site-to-site tunnel to a
#      branch on the WAN (#148); IPv6 on the WAN by DHCPv6, with a
#      delegated prefix (#213), a /64 of which the LAN takes, with SLAAC
#      and DNS from the node's RAs, until the ISP delegates another
#      (#214).
#   2. A pair: pairing with the sync tunnel over the LAN, Kea's lease and
#      conntrack replication over it, and a failover that a connection
#      through the pair survives, after which the client renews its lease
#      from the new master.
#
#   tests/vm/two-nic-test.sh WORKDIR
#       (WORKDIR/output/qcow2/disk.qcow2 from build-disk.sh)
set -euo pipefail
WORK=${1:?usage: two-nic-test.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$WORK"

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ns() { local n=$1; shift; sudo ip netns exec "sw-$n" "$@"; }
wait_for() { # seconds description command...
    local deadline=$((SECONDS + $1)) what=$2
    shift 2
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || fail "timed out waiting for $what"
        sleep 3
    done
}

#        name  wan MAC            lan MAC            wan tap  lan tap  LAN address
FW1=(fw1 52:54:00:21:00:01 52:54:00:21:00:02 tnwan1 tnlan1 192.168.1.2)
FW2=(fw2 52:54:00:22:00:01 52:54:00:22:00:02 tnwan2 tnlan2 192.168.1.3)
ADMIN_MAC=52:54:00:12:34:10
LEASES=/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv

addr_of() { case $1 in fw1) echo "${FW1[5]}" ;; fw2) echo "${FW2[5]}" ;; esac; }

# Everything the admin does goes over the LAN, from sw-tadmin.
at() { # node command...
    local a; a=$(addr_of "$1"); shift
    timeout "${AT_TIMEOUT:-90}" sudo ip netns exec sw-tadmin \
        ssh -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o LogLevel=ERROR -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        "admin@$a" "$@"
}
status() { at "$1" 'sudo sparewall status -o json'; }
role() { status "$1" | jq -r .role; }
in_sync() { status "$1" | jq -e '.sync.state == "in-sync"'; }
is_master() { [ "$(role "$1")" = MASTER ]; }
healthy() { [ "$(status "$1" | jq -r .health.level)" = ok ]; }

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        for f in flow.log; do [ -f "$f" ] && { echo "--- $f"; tail -5 "$f"; }; done
        for n in fw1 fw2; do
            [ -f "$n.pid" ] || continue
            echo "--- $n"
            at "$n" 'sudo journalctl -b -u sparewalld --no-pager | tail -40
                timeout 20 sudo sparewall status; ip -br addr; ip -d link show type vlan
                sudo nft list chain inet sparewall input; sudo wg show swsync 2>&1' 2>/dev/null \
                || sudo tail -40 "$n.serial" || true
        done
    fi
    [ $rc -eq 0 ] || [ -z "${V6_DUMP:-}" ] || v6_dump
    sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
    stop_v6_isp
    stop_vm fw1
    stop_vm fw2
}
trap cleanup EXIT

# The ISP's IPv6 (#213): radvd and Kea's DHCPv6 server in sw-tisp. Kea's
# files are where Ubuntu's AppArmor profile for it allows.
KEA6_CONF=/etc/kea/sparewall-test-dhcp6.conf
KEA6_LEASES=/var/lib/kea/sparewall-test-leases6.csv
KEA6_LOG=/var/log/kea/sparewall-test-dhcp6.log
v6_dump() {
    set +e
    echo "--- radvd"; tail -n 5 radvd.log
    echo "--- tisp"; ns tisp ip -6 addr show dev eth0
    for f in kea6.out "$KEA6_LOG" "$KEA6_LEASES"; do echo "--- $f"; sudo tail -n 30 "$f"; done
    echo "--- fw1"
    at fw1 'ip -6 addr; ip -6 route; networkctl status wan0 lan0 --no-pager -n 0
        sudo journalctl -b -u systemd-networkd --no-pager | grep -iE "dhcp6|ndisc|ipv6|pd|prefix" | tail -40
        sudo nft list chain inet sparewall input'
    set -e
} 2>&1
stop_v6_isp() {
    [ -f "$WORK/radvd.pid" ] && sudo kill "$(sudo cat "$WORK/radvd.pid")" 2>/dev/null || true
    sudo pkill -f "kea-dhcp6 -c $KEA6_CONF" 2>/dev/null || true
}

stop_vm() { # node
    [ -f "$1.pid" ] || return 0
    sudo kill "$(sudo cat "$1.pid")" 2>/dev/null || true
    rm -f "$1.pid"
    sleep 2
}

# A VM with exactly two NICs, the WAN's and the LAN's, and its identity:
# the LAN NIC is the management NIC.
boot() { # name wan-mac lan-mac wan-tap lan-tap address
    cp output/qcow2/disk.qcow2 "$1.qcow2"
    cat > "$1.json" <<JSON
{"node": "$1", "ssh_keys": ["$(cat id_ed25519.pub)"], "management": {"nic": "$3", "address": "$6/24"}}
JSON
    sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 1536 -smp 2 \
        -drive "file=$1.qcow2,if=virtio,format=qcow2" \
        -netdev "tap,id=n0,ifname=$4,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n0,mac=$2" \
        -netdev "tap,id=n1,ifname=$5,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n1,mac=$3" \
        -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 "$1.json")" \
        -display none -serial "file:$1.serial" -pidfile "$1.pid" -daemonize
}

# A host on a bridge, in a namespace of its own.
host() { # name bridge mac [address/len]
    sudo ip netns add "sw-$1"
    sudo ip link add "v-$1" type veth peer name eth0 netns "sw-$1"
    sudo ip link set "v-$1" master "$2" up
    ns "$1" ip link set lo up
    ns "$1" ip link set eth0 address "$3" up
    [ -z "${4:-}" ] || ns "$1" ip addr add "$4" dev eth0
}

cat > "$WORK/udhcpc.sh" <<'SH'
#!/bin/sh
case "$1" in
bound|renew)
    ip -4 addr flush dev "$interface"   # only IPv4: IPv6 SLAAC needs the link-local address
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "${router%% *}"
    ;;
esac
SH
chmod +x "$WORK/udhcpc.sh"
lease() { # namespace
    ns "$1" busybox udhcpc -i eth0 -n -q -t 10 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1 \
        || fail "no DHCP lease on $1"
    ns "$1" ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1
}

log "two plain switches, no VLANs"
for b in tnwan tnlan; do
    sudo ip link add "$b" type bridge
    sudo ip link set "$b" up
done
for t in "${FW1[3]}" "${FW2[3]}"; do sudo ip tuntap add "$t" mode tap; sudo ip link set "$t" master tnwan up; done
for t in "${FW1[4]}" "${FW2[4]}"; do sudo ip tuntap add "$t" mode tap; sudo ip link set "$t" master tnlan up; done
# The ISP's gateway (203.0.113.6), with an outside address behind it: an
# echo server, and one that answers with the address a connection came
# from.
host tisp tnwan 02:00:00:00:21:06 203.0.113.6/29
ns tisp ip addr add 198.18.0.1/32 dev lo
ns tisp python3 "$HERE/echo.py" server &
ns tisp python3 "$HERE/echo.py" whoami &
# On the LAN: the admin (by its reservation's address), another host,
# and a DHCP client.
host tadmin tnlan "$ADMIN_MAC" 192.168.1.10/24
host tother tnlan 02:00:00:00:21:20 192.168.1.20/24
host tclient tnlan 02:00:00:00:21:30
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f id_ed25519
sleep 1

# --- 1. standalone -----------------------------------------------------------
log "a standalone two-NIC node, managed over its LAN port"
boot "${FW1[@]}"
wait_for 900 "fw1 SSH over the LAN" at fw1 true
cat > site.yaml <<EOF
schema: 1
cluster:
  nodes: [fw1]
management:
  network: lan
  sources: [192.168.1.10]
ports:
  fw1:
    wan0: { nic: "${FW1[1]}" }
    lan0: { nic: "${FW1[2]}" }
networks:
  wan:
    port: wan0
    role: wan
    addresses: { fw1: 203.0.113.2/29 }
    gateway: 203.0.113.6
  lan:
    port: lan0
    role: management
    addresses: { fw1: 192.168.1.2/24 }
zones:
  wan: { networks: [wan] }
  lan: { networks: [lan] }
policy:
  lan->wan: { action: accept, nat: masquerade }
  lan->self:
    action: drop
    rules:
      ping: { order: 100, proto: icmp, icmp_type: [echo-request], action: accept }
      dns: { order: 200, proto: udp, dport: 53, action: accept }
  wan->self: { action: drop }
dhcp:
  lan:
    pool: 192.168.1.100-192.168.1.199
    reservations:
      admin: { mac: "$ADMIN_MAC", address: 192.168.1.10, hostname: admin }
EOF
at fw1 'cat > /tmp/site.yaml' < site.yaml
# The management port is renamed (mgmt0 -> lan0), which may cut this
# session.
at fw1 'sudo sparewall apply -f /tmp/site.yaml --confirm 0' || true
sleep 5
wait_for 120 "fw1 SSH after the first apply" at fw1 true
wait_for 300 "fw1 healthy" healthy fw1
[ -z "$(at fw1 'ip -d -br link show type vlan')" ] || fail "fw1 has VLAN devices: $(at fw1 'ip -d -br link show type vlan')"

log "DHCP and forwarding on the LAN NIC"
c=$(lease tclient)
case $c in 192.168.1.1[0-9][0-9]) ;; *) fail "the client's lease $c is not from the pool" ;; esac
seen=$(ns tclient python3 "$HERE/echo.py" ask 198.18.0.1 7002) || fail "the client cannot reach the outside"
[ "$seen" = 203.0.113.2 ] || fail "the client reached the outside as $seen, not 203.0.113.2"

log "management.sources: the admin's SSH only; the rest of the LAN still pings the node"
ns tother ping -c 2 -W 2 192.168.1.2 >/dev/null || fail "another LAN host cannot ping the node (lan->self allows it)"
if ns tother timeout 5 bash -c 'exec 3<>/dev/tcp/192.168.1.2/22' 2>/dev/null; then
    fail "another LAN host reached the node's SSH"
fi
if ns tother timeout 5 bash -c 'exec 3<>/dev/tcp/192.168.1.2/443' 2>/dev/null; then
    fail "another LAN host reached the node's HTTPS"
fi
ns tadmin timeout 5 bash -c 'exec 3<>/dev/tcp/192.168.1.2/443' \
    || fail "the admin cannot reach the node's HTTPS"

log "a site-to-site tunnel to a branch (#148)"
# tsite, beside the ISP, is a branch office: fw1 routes its network,
# 10.20.0.0/24, through the tunnel and starts the tunnel itself; the
# branch is configured from what fw1 prints for it, without a keepalive,
# so it never sends first.
wg genkey > site.key
wg pubkey < site.key > site.pub
host tsite tnwan 02:00:00:00:21:07 203.0.113.5/29
ns tsite ip link add lan0 type dummy
ns tsite ip addr add 10.20.0.1/24 dev lan0
ns tsite ip link set lan0 up
jq -n --arg k "$(cat site.pub)" '{
    vpn: {branch: {listen_port: 51821, endpoint: "203.0.113.2", addresses: ["10.98.0.1/30"], zone: "branch",
        peers: {tsite: {public_key: $k, endpoint: "203.0.113.5:51821",
            addresses: ["10.98.0.2/32", "10.20.0.0/24"], keepalive: 10}}}},
    zones: {branch: {}},
    policy: {"lan->branch": {action: "accept"}, "branch->lan": {action: "accept"}}
}' | at fw1 'cat > /tmp/site-vpn.json'
at fw1 'sudo sparewall merge -f /tmp/site-vpn.json --confirm 0' >/dev/null
at fw1 'sudo sparewall vpn peer-config tsite' > tsite.conf
grep -qx 'Endpoint = 203.0.113.2:51821' tsite.conf || fail "the branch's config does not name fw1: $(cat tsite.conf)"
grep -qx 'AllowedIPs = 10.98.0.0/30, 192.168.1.0/24' tsite.conf \
    || fail "the branch's config does not route fw1's tunnel and LAN: $(grep AllowedIPs tsite.conf)"
(umask 077; sed -e "s|^PrivateKey = .*|PrivateKey = $(cat site.key)|" \
    -e '/^PersistentKeepalive/d' -e '/^Address/d' tsite.conf > tsite-wg.conf)
ns tsite ip link add wg0 type wireguard
ns tsite wg setconf wg0 "$PWD/tsite-wg.conf"
ns tsite ip addr add "$(sed -n 's/^Address = //p' tsite.conf)" dev wg0
ns tsite ip link set wg0 up
for n in 10.98.0.0/30 192.168.1.0/24; do ns tsite ip route add "$n" dev wg0; done
site_session() { [ "$(ns tsite wg show wg0 latest-handshakes | awk '{print $2}')" -gt 0 ]; }
wait_for 60 "fw1 starts the branch's tunnel" site_session
at fw1 'ip route show 10.20.0.0/24' | grep -q 'dev branch' || fail "fw1 does not route the branch's network through the tunnel"
# Both ways, without NAT between the sites.
ns tclient ping -c 2 -W 2 10.20.0.1 >/dev/null || fail "the LAN cannot reach the branch's network"
ns tsite ping -c 2 -W 2 -I 10.20.0.1 "$c" >/dev/null || fail "the branch's network cannot reach the LAN"
ns tsite python3 "$HERE/echo.py" whoami &
sleep 1
seen=$(ns tclient python3 "$HERE/echo.py" ask 10.20.0.1 7002) || fail "the LAN cannot connect to the branch"
[ "$seen" = "$c" ] || fail "the branch saw the LAN's connection from $seen, not $c"
wait_for 60 "fw1 healthy with the tunnel up" healthy fw1

log "a WireGuard client: the LAN's traffic leaves through a provider (#149)"
# tprov, beside the ISP, is a VPN provider: it gives fw1 10.64.0.2 and
# masquerades what comes through the tunnel out of its own address,
# 203.0.113.4, which is what the outside then sees. It stays for the pair.
wg genkey > prov.key
wg pubkey < prov.key > prov.pub
wg genkey > egress.key
wg pubkey < egress.key > egress.pub
host tprov tnwan 02:00:00:00:21:04 203.0.113.4/29
ns tprov ip route add default via 203.0.113.6
ns tprov sysctl -qw net.ipv4.ip_forward=1
ns tprov iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ns tprov ip link add wg0 type wireguard
ns tprov wg set wg0 listen-port 51820 private-key "$PWD/prov.key" \
    peer "$(cat egress.pub)" allowed-ips 10.64.0.2/32
ns tprov ip addr add 10.64.0.1/24 dev wg0
ns tprov ip link set wg0 up
# The client's document, for this node and the pair.
client_doc() {
    jq -n --arg k "$(cat prov.pub)" '{
        zones: {egress: {}},
        vpn_clients: {egress: {private_key: "secret:egress-key", addresses: ["10.64.0.2/32"],
            zone: "egress", peer: {public_key: $k, endpoint: "203.0.113.4:51820"},
            route: {networks: ["lan"]}}},
        policy: {"lan->egress": {action: "accept"}}
    }'
}
at fw1 'sudo sparewall secret set egress-key' < egress.key
client_doc | at fw1 'cat > /tmp/client.json'
at fw1 'sudo sparewall merge -f /tmp/client.json --confirm 0' >/dev/null
prov_session() { [ "$(ns tprov wg show wg0 latest-handshakes | awk '{print $2}')" -gt 0 ]; }
wait_for 60 "fw1 connects to the provider" prov_session
via_provider() { [ "$(ns tclient python3 "$HERE/echo.py" ask 198.18.0.1 7002)" = 203.0.113.4 ]; }
wait_for 30 "the LAN reaches the outside through the provider" via_provider
# fw1's own traffic keeps the WAN, and the branch keeps its tunnel.
at fw1 'ip route get 198.18.0.1' | grep -q 'dev wan' || fail "fw1's own traffic does not leave by the WAN: $(at fw1 'ip route get 198.18.0.1')"
ns tclient ping -c 2 -W 2 10.20.0.1 >/dev/null || fail "the LAN lost the branch to the provider's tunnel"
# The kill switch: without the tunnel the LAN's traffic goes nowhere,
# not out of the WAN; networkd brings it back.
at fw1 'sudo ip link del egress'
if seen=$(ns tclient python3 "$HERE/echo.py" ask 198.18.0.1 7002 2>/dev/null); then
    fail "with the tunnel gone the LAN reached the outside as $seen"
fi
at fw1 'sudo nft list chain inet sparewall forward' | grep 'vpn-client-egress:kill-switch' | grep -qv 'packets 0 ' \
    || fail "the kill switch did not drop the LAN's traffic"
at fw1 'sudo networkctl reload'
wait_for 60 "the LAN through the provider again" via_provider
wait_for 120 "fw1 healthy with the client" healthy fw1
ns tprov wg set wg0 peer "$(cat egress.pub)" remove
ns tprov wg set wg0 peer "$(cat egress.pub)" allowed-ips 10.64.0.2/32

log "IPv6 on the WAN: an address by DHCPv6, a delegated prefix, routes from RAs (#213)"
# tisp is also the ISP's IPv6 router. Its advertisements set the M and O
# flags and carry no prefix, so the WAN's address comes from DHCPv6 only;
# Kea gives it one from 2001:db8:ffff::/64 and delegates /56s out of
# 2001:db8:100::/48.
ns tisp sysctl -qw net.ipv6.conf.all.forwarding=1
ns tisp ip -6 addr add 2001:db8:ffff::1/64 dev eth0 nodad
cat > radvd.conf <<'EOF'
interface eth0 {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
};
EOF
ns tisp radvd -n -u root -C "$PWD/radvd.conf" -p "$PWD/radvd.pid" -m stderr > radvd.log 2>&1 &
# Ubuntu's AppArmor profile for kea-dhcp6 withholds dac_override, so
# root may not write into /run/kea (the _kea user's) and the like; this
# runner's Kea is a test fixture, not a service.
for f in /etc/apparmor.d/*kea-dhcp6*; do
    [ -f "$f" ] && sudo apparmor_parser -R "$f" 2>/dev/null || true
done
kea6_start() { # the /48 to delegate /56s from, as 2001:db8:N::
    sudo tee "$KEA6_CONF" > /dev/null <<EOF
{"Dhcp6": {
  "interfaces-config": {"interfaces": ["eth0"]},
  "lease-database": {"type": "memfile", "persist": true, "name": "$KEA6_LEASES"},
  "subnet6": [{"id": 1, "subnet": "2001:db8:ffff::/64", "interface": "eth0",
    "pools": [{"pool": "2001:db8:ffff::100-2001:db8:ffff::1ff"}],
    "pd-pools": [{"prefix": "$1", "prefix-len": 48, "delegated-len": 56}]}],
  "option-data": [{"name": "dns-servers", "data": "2001:db8:ffff::1"}],
  "loggers": [{"name": "kea-dhcp6", "severity": "INFO",
    "output_options": [{"output": "$KEA6_LOG"}]}]
}}
EOF
    sudo rm -f "$KEA6_LEASES"*
    ns tisp env KEA_PIDFILE_DIR=/run/kea KEA_LOCKFILE_DIR=/run/kea \
        kea-dhcp6 -c "$KEA6_CONF" > kea6.out 2>&1 &
}
kea6_start 2001:db8:100::
jq -n '{networks: {wan: {ipv6: {mode: "dhcpv6"}}},
        objects: {wan6: {type: "ipv6", dynamic: {network: "wan"}}}}' | at fw1 'cat > /tmp/v6.json'
at fw1 'sudo sparewall merge -f /tmp/v6.json --confirm 0' >/dev/null
wan6() { at fw1 'ip -6 -br addr show dev wan0 scope global' | grep -o '2001:db8:ffff::1[0-9a-f][0-9a-f]'; }
V6_DUMP=1
wait_for 120 "fw1's WAN address by DHCPv6" wan6
a=$(wan6 | head -1)
at fw1 'ip -6 route show default dev wan0' | grep -q 'via fe80::' \
    || fail "no IPv6 default route from the RAs: $(at fw1 'ip -6 route show default')"
# A /56 delegated to fw1, whose DUID is its WAN MAC (DUID-LL), so a
# reboot asks for the same lease and prefix. Kea's lease file:
# address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,...
duid="00:03:00:01:${FW1[1]}"
pd() { sudo awk -F, -v d="$duid" '$7 == 2 && $9 == 56 && $2 == d' "$KEA6_LEASES" | grep -q .; }
wait_for 60 "a /56 delegated to fw1's DUID $duid" pd
sudo awk -F, -v d="$duid" '$7 == 0 && $2 == d {print $1}' "$KEA6_LEASES" | grep -qx "$a" \
    || fail "fw1's address $a is not its DHCPv6 lease"
at fw1 'ping -6 -c 2 -W 2 2001:db8:ffff::1' >/dev/null || fail "fw1 cannot reach the ISP over IPv6"
at fw1 'sudo nft list set inet sparewall wan6' | grep -q "$a" \
    || fail "the wan6 object does not hold the WAN's address: $(at fw1 'sudo nft list set inet sparewall wan6')"
# The WAN zone reaches nothing on the node over IPv6 either (wan->self).
if ns tisp timeout 5 bash -c "exec 3<>/dev/tcp/$a/22" 2>/dev/null; then
    fail "the ISP reached fw1's SSH over IPv6"
fi
wait_for 60 "fw1 healthy with IPv6 on the WAN" healthy fw1

log "IPv6 inside: the LAN takes a /64 of the delegated prefix; SLAAC and DNS from the RAs (#214)"
# The ISP routes what it delegates to fw1.
ns tisp ip -6 route add 2001:db8:100::/48 via "$a" dev eth0
jq -n '{networks: {lan: {ipv6: {mode: "delegated", subnet_id: 1}}},
        dns: {enabled: true, domain: "home.arpa", records: {nas: "192.168.1.50"}}}' \
    | at fw1 'cat > /tmp/v6in.json'
at fw1 'sudo sparewall merge -f /tmp/v6in.json --confirm 0' >/dev/null
lan_prefix() { # fw1's current /64 on the LAN, as 2001:db8:...:1:: (it is ::1 there)
    at fw1 'ip -6 addr show dev lan0 scope global -deprecated' \
        | grep -o 'inet6 2001:db8:[0-9a-f:]*::1/64' | sed 's/^inet6 //; s|1/64$||' | head -1
}
wait_for 90 "a /64 of the delegated prefix on fw1's LAN" lan_prefix
p1=$(lan_prefix)
case $p1 in 2001:db8:100:1::) ;; *) fail "the LAN's prefix is $p1, not subnet 1 of 2001:db8:100::/56" ;; esac
client6() { # the client's SLAAC address in prefix $1
    ns tclient ip -6 -br addr show dev eth0 scope global | grep -o "${1}[0-9a-f:]*" | head -1 | grep .
}
wait_for 60 "the client's SLAAC address in $p1/64" client6 "$p1"
c6=$(client6 "$p1")
ll=$(at fw1 'ip -6 -br addr show dev lan0 scope link' | grep -o 'fe80::[0-9a-f:]*')
ns tclient rdisc6 -1 eth0 > ra.txt 2>&1 || true
grep -q "Recursive DNS server *: *$ll" ra.txt || fail "the RA names no DNS server $ll: $(cat ra.txt)"
grep -q "DNS search list *: *home.arpa" ra.txt || fail "the RA names no search domain: $(cat ra.txt)"
seen=$(ns tclient dig +short +time=3 +tries=2 "@$ll%eth0" nas.home.arpa A)
[ "$seen" = 192.168.1.50 ] || fail "the node's resolver over IPv6 answered '$seen' for nas.home.arpa"
ns tclient ping -6 -c 2 -W 2 2001:db8:ffff::1 >/dev/null || fail "the client cannot reach the ISP over IPv6"
# Nothing from the WAN reaches the client unasked (no wan->lan policy).
if ns tisp ping -6 -c 2 -W 2 "$c6" >/dev/null 2>&1; then
    fail "the ISP reached the client $c6 unasked"
fi

log "a new delegated prefix renumbers the LAN, and the client follows (#214)"
sudo pkill -f "kea-dhcp6 -c $KEA6_CONF" || true
sleep 1
kea6_start 2001:db8:200::
ns tisp ip -6 route add 2001:db8:200::/48 via "$a" dev eth0
at fw1 'sudo networkctl reconfigure wan0'
new_prefix() { local p; p=$(lan_prefix); [ -n "$p" ] && [ "$p" != "$p1" ]; }
wait_for 120 "a new prefix on fw1's LAN" new_prefix
p2=$(lan_prefix)
case $p2 in 2001:db8:200:1::) ;; *) fail "the LAN's new prefix is $p2, not subnet 1 of 2001:db8:200::/56" ;; esac
wait_for 60 "the client's address in $p2/64" client6 "$p2"
# The old prefix is withdrawn: gone, or deprecated so nothing new uses it.
old=$(ns tclient ip -6 addr show dev eth0 scope global | grep "inet6 $p1" || true)
[ -z "$old" ] || grep -q deprecated <<<"$old" || fail "the client still prefers the old prefix: $old"
ns tclient ping -6 -c 2 -W 2 2001:db8:ffff::1 >/dev/null || fail "the client cannot reach the ISP from the new prefix"
wait_for 60 "fw1 healthy with IPv6 inside" healthy fw1
V6_DUMP=
stop_v6_isp
stop_vm fw1

# --- 2. pair ---------------------------------------------------------------
log "a pair of two-NIC nodes, the sync tunnel over the LAN"
boot "${FW1[@]}"
boot "${FW2[@]}"
wait_for 900 "fw1 SSH over the LAN" at fw1 true
wait_for 900 "fw2 SSH over the LAN" at fw2 true
k1=$(status fw1 | jq -r .sync.sync_public_key)
k2=$(status fw2 | jq -r .sync.sync_public_key)
cat > pair.yaml <<EOF
schema: 1
cluster:
  nodes: [fw1, fw2]
  sync_network: lan
  sync_keys: { fw1: "$k1", fw2: "$k2" }
  vrrp:
    priority: { fw1: 110, fw2: 100 }
management:
  network: lan
  sources: [192.168.1.10]
ports:
  fw1:
    wan0: { nic: "${FW1[1]}" }
    lan0: { nic: "${FW1[2]}" }
  fw2:
    wan0: { nic: "${FW2[1]}" }
    lan0: { nic: "${FW2[2]}" }
networks:
  wan:
    port: wan0
    role: wan
    addresses: { fw1: 203.0.113.2/29, fw2: 203.0.113.3/29 }
    vip: 203.0.113.1/29
    vrid: 10
    gateway: 203.0.113.6
  lan:
    port: lan0
    role: management
    addresses: { fw1: 192.168.1.2/24, fw2: 192.168.1.3/24 }
    vip: 192.168.1.1/24
    vrid: 20
zones:
  wan: { networks: [wan] }
  lan: { networks: [lan] }
  egress: {}
vpn_clients:
  egress:
    private_key: secret:egress-key
    addresses: [10.64.0.2/32]
    zone: egress
    peer: { public_key: "$(cat prov.pub)", endpoint: "203.0.113.4:51820" }
    route: { networks: [lan] }
policy:
  lan->wan: { action: accept, nat: { snat: 203.0.113.1 } }
  lan->egress: { action: accept }
  lan->self:
    action: drop
    rules:
      ping: { order: 100, proto: icmp, icmp_type: [echo-request], action: accept }
      dns: { order: 200, proto: udp, dport: 53, action: accept }
  wan->self: { action: drop }
dhcp:
  lan:
    pool: 192.168.1.100-192.168.1.199
    reservations:
      admin: { mac: "$ADMIN_MAC", address: 192.168.1.10, hostname: admin }
EOF
# The client's key, set on fw1 alone: fw2 gets it as a cluster secret.
at fw1 'sudo sparewall secret set egress-key' < egress.key
for n in fw1 fw2; do
    at "$n" 'cat > /tmp/pair.yaml' < pair.yaml
    at "$n" 'sudo sparewall apply -f /tmp/pair.yaml --confirm 0' || true
done
sleep 5
wait_for 300 "fw1 in sync" in_sync fw1
wait_for 120 "fw2 in sync" in_sync fw2
wait_for 120 "fw1 master" is_master fw1
[ "$(role fw2)" = BACKUP ] || fail "fw2 is $(role fw2), not BACKUP"
at fw1 'sudo wg show swsync endpoints' | grep -q '192.168.1.3:' \
    || fail "fw1's sync tunnel does not go to fw2's LAN address: $(at fw1 'sudo wg show swsync endpoints')"

log "a lease replicated over the LAN (Kea HA in the tunnel)"
ns tclient ip addr flush dev eth0
LEASE=$(lease tclient)
fw2_has_lease() { at fw2 "sudo grep -q '^$LEASE,02:00:00:00:21:30' $LEASES"; }
wait_for 60 "fw2 holds the lease of $LEASE" fw2_has_lease

log "the WireGuard client on the master only (#149)"
wait_for 60 "fw1 connects to the provider" prov_session
[ "$(at fw2 'cat /sys/class/net/egress/operstate' 2>/dev/null)" != up ] || fail "fw2, the backup, has the provider's tunnel up"
at fw2 'ip -br link show egress' | grep -q 'DOWN' || fail "fw2's client link is not down: $(at fw2 'ip -br link show egress')"
wait_for 30 "the LAN reaches the outside through the provider" via_provider

log "a connection through the pair, replicated over the LAN"
ns tclient python3 "$HERE/echo.py" client 198.18.0.1 > flow.log 2>&1 &
echoes() { tail -1 flow.log | grep -qE '^[0-9]+$' && tail -1 flow.log; }
sleep 3
before=$(echoes) || fail "no echoes through fw1: $(cat flow.log)"
replicated() { at fw2 'sudo conntrackd -C /run/sparewall/conntrackd/conntrackd.conf -e' | grep -q 'dport=7000'; }
wait_for 30 "the connection in fw2's conntrackd cache" replicated

log "failover: fw1 goes; fw2 takes the gateway and the provider's tunnel, and the connection carries on"
# Both nodes are the same client, with the same tunnel address, whose
# translation the provider keeps: the new master takes the tunnel up and
# the replicated connection goes on through it.
t0=$(date +%s)
stop_vm fw1
wait_for 120 "fw2 master" is_master fw2
advanced() { local n; n=$(echoes) && [ "$n" -gt "$before" ]; }
wait_for 60 "the connection to carry on through fw2" advanced
grep -q broken flow.log && fail "the connection broke in the failover: $(tail -5 flow.log)"
moved() { [ "$(ns tprov wg show wg0 latest-handshakes | awk '{print $2}')" -ge "$t0" ]; }
wait_for 60 "fw2 connects to the provider" moved
echo "  the provider saw fw2 $(( $(ns tprov wg show wg0 latest-handshakes | awk '{print $2}') - t0 )) s after fw1 went"
wait_for 30 "the LAN reaches the outside through the provider from fw2" via_provider

log "the client renews its lease from fw2"
# Kea's standby serves once it finds its partner gone, which takes a
# while: asked until it answers.
same_lease() {
    ns tclient busybox udhcpc -i eth0 -n -q -t 3 -T 3 -s "$WORK/udhcpc.sh" >/dev/null 2>&1 || return 1
    [ "$(ns tclient ip -4 -br addr show dev eth0 | awk '{print $3}' | cut -d/ -f1)" = "$LEASE" ]
}
wait_for 180 "the client to renew $LEASE from fw2" same_lease
log "two-NIC PASS (standalone, and a pair with management and sync on the LAN)"
