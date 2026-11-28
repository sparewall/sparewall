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
    # IPv4 only: the client's link-local IPv6 address is what it reaches
    # its IPv6 gateway (fe80::1) from (#272).
    ip -4 addr flush dev "$interface"
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

# NAT reflection (forwards.reflect): inside clients reach the server in
# sw-srv (users VLAN) by the forward's outside address. One on another
# network keeps its own address; one on the server's network is
# source-NATed to the gateway address so the reply comes back through
# the firewall.
hairpin() {
    sudo ip netns add sw-srv
    sudo ip link add v-srv type veth peer name eth0 netns sw-srv
    sudo ip link set v-srv master swbr up
    sudo bridge vlan del dev v-srv vid 1
    sudo bridge vlan add dev v-srv vid 20 pvid untagged
    ns srv ip link set lo up
    ns srv ip addr add 192.0.2.30/24 dev eth0
    ns srv ip link set eth0 up
    ns srv ip route add default via 192.0.2.1
    ns srv python3 "$HERE/echo.py" whoami &
    sleep 1
    local seen
    seen=$(ns guests python3 "$HERE/echo.py" ask 10.0.2.15 8080) \
        || fail "guests cannot reach the forward by its outside address"
    [ "$seen" = "$g" ] || fail "the server saw guests as $seen, not $g"
    seen=$(ns users python3 "$HERE/echo.py" ask 10.0.2.15 8080) \
        || fail "users cannot reach the forward on its own network by its outside address"
    [ "$seen" = 192.0.2.1 ] || fail "the server saw users as $seen, not the gateway address"
    # Only the forward is opened: guests still cannot reach the server.
    ! ns guests python3 "$HERE/echo.py" ask 192.0.2.30 7002 2>/dev/null \
        || fail "guests reached the server directly"
    log "hairpin: guests seen as $g, users as 192.0.2.1"
}

# Kea's ping check: a host using a pool address without a lease (as after
# a restore, or beside the DHCP server it replaces) is not offered to the
# next client. Kea hands out guests addresses in order, so the one after
# $1 is next: the guests client squats on it, and a second client on the
# same VLAN must get another. Kea declines the squatted one before it
# offers another, so its declined record is what shows the check ran: an
# address skipped for any other reason has none (#71).
squatter() {
    local next=198.51.100.$(( ${1##*.} + 1 )) other
    ns guests ip addr add "$next/24" dev eth0
    sudo ip netns add sw-guests2
    sudo ip link add v-guests2 type veth peer name eth0 netns sw-guests2
    sudo ip link set v-guests2 master swbr up
    sudo bridge vlan del dev v-guests2 vid 1
    sudo bridge vlan add dev v-guests2 vid 30 pvid untagged
    ns guests2 ip link set lo up
    ns guests2 ip link set eth0 address 02:00:00:00:00:31 up
    other=$(lease guests2)
    log "ping check: $next squatted, the next client got $other"
    [ "$other" != "$next" ] || fail "Kea offered $next, which a host already uses"
    local leases=/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv
    # Its latest record (state 1 is declined), polled on the node.
    if ! vm "for i in \$(seq 60); do sudo awk -F, '\$1 == \"$next\" { s = \$10 } END { exit s != 1 }' $leases && exit; sleep 1; done; exit 1"; then
        vm "sudo grep '^198\.51\.100\.' $leases; sudo journalctl -b -u sparewall-kea --no-pager | grep -iE 'ping|decline|DHCP4_LEASE|DHCPSRV' | tail -40" || true
        fail "Kea did not mark the squatted $next declined"
    fi
    # One socket per interface: with one per address, Kea answers each
    # DISCOVER twice and skips addresses without a ping (#71).
    ! vm 'sudo journalctl -b -u sparewall-kea --no-pager | grep -q DHCPSRV_MULTIPLE_RAW_SOCKETS_PER_IFACE' \
        || fail "Kea opened more than one socket on an interface"
    ns guests ip addr del "$next/24" dev eth0
    sudo ip netns del sw-guests2
}

# DNS interception (#73): on users, a query for a server that isn't a
# resolver (an unused guests address, so it is routed through the
# firewall) gets the firewall's answer; guests, not intercepted, gets
# none, since guests->users drops it. Undone afterwards.
dns_intercept() {
    local a
    echo '{"dns": {"intercept": {"users": {}}}}' | vm 'cat > /tmp/intercept.json'
    vm 'sudo sparewall merge -f /tmp/intercept.json --confirm 0' >/dev/null
    a=$(ns users dig +short +time=3 +tries=3 @198.51.100.53 printer.home.arpa) || true
    [ "$a" = 192.0.2.9 ] || fail "an intercepted query for another server: got '$a'"
    # dig +short prints a timeout on stdout too: only addresses count.
    a=$(ns guests dig +short +time=2 +tries=1 @192.0.2.53 printer.home.arpa | grep -v '^;') || true
    [ -z "$a" ] || fail "guests, not intercepted, got an answer from 192.0.2.53: '$a'"
    vm 'sudo nft list chain inet sparewall prerouting_nat' | grep 'dns-intercept:users' | grep -q 'packets [1-9]' \
        || fail "the users interception counted nothing"
    vm 'sudo sparewall unset dns.intercept --confirm 0' >/dev/null
    log "DNS interception PASS"
}

# DNS filters (#74): a list served from this host (QEMU's user network
# puts it at 10.0.2.2) and a name blocked by hand, on users only. users
# gets NXDOMAIN for both; guests, unfiltered, gets the local records.
# Undone afterwards.
dns_filters() {
    local d srv status
    d=$(mktemp -d)
    printf '# a hosts file\n0.0.0.0 ads.home.arpa\n' > "$d/list.txt"
    python3 -m http.server 8099 --bind 127.0.0.1 --directory "$d" >/dev/null 2>&1 &
    srv=$!
    echo '{"dns": {"records": {"ads": "192.0.2.77", "games": "192.0.2.78"}, "filters": {"ads": {"networks": ["users"], "lists": ["http://10.0.2.2:8099/list.txt"], "block": ["games.home.arpa"]}}}}' \
        | vm 'cat > /tmp/filters.json'
    vm 'sudo sparewall merge -f /tmp/filters.json --confirm 0' >/dev/null
    status() { ns "$1" dig +time=2 +tries=1 "@$2" "$3" | grep -o 'status: [A-Z]*' | cut -d' ' -f2; }
    local deadline=$((SECONDS + 120))
    until [ "$(status users 192.0.2.1 ads.home.arpa)" = NXDOMAIN ]; do
        if [ $SECONDS -ge $deadline ]; then
            vm 'sudo ls -la /run/sparewall/dns /var/lib/sparewall/dns-filters; sudo journalctl -b -u sparewalld --no-pager | grep -i filter | tail -10' || true
            kill "$srv"
            fail "users still resolves ads.home.arpa, which the list blocks"
        fi
        sleep 3
    done
    kill "$srv"
    [ "$(status users 192.0.2.1 games.home.arpa)" = NXDOMAIN ] || fail "users resolves games.home.arpa, which the filter blocks"
    [ "$(ns users dig +short +time=2 +tries=2 @192.0.2.1 printer.home.arpa)" = 192.0.2.9 ] \
        || fail "users no longer resolves names the filter doesn't block"
    [ "$(ns guests dig +short +time=2 +tries=2 @198.51.100.1 ads.home.arpa)" = 192.0.2.77 ] \
        || fail "guests, unfiltered, does not resolve ads.home.arpa"
    echo '{"dns": {"filters": null, "records": {"ads": null, "games": null}}}' | vm 'cat > /tmp/filters.json'
    vm 'sudo sparewall merge -f /tmp/filters.json --confirm 0' >/dev/null
    rm -rf "$d"
    log "DNS filters PASS"
}

# Provider passthrough options (#143): a Kea class for busybox's udhcpc
# (its vendor class) and an option on the users network, each sent
# whether asked for or not, and an Unbound record. A key Sparewall sets
# is refused. Undone afterwards. (A positive time offset: udhcpc prints
# the option as unsigned.)
provider_options() {
    local env="$WORK/udhcpc-env"
    cat > "$WORK/udhcpc-po.sh" <<SH
#!/bin/sh
[ "\$1" = bound ] && echo "tftp=\$tftp timezone=\$timezone" > "$env"
exit 0
SH
    chmod +x "$WORK/udhcpc-po.sh"
    cat <<'JSON' | vm 'cat > /tmp/po.json'
{"provider_options": {
  "kea": {
    "client-classes": [{
      "name": "busybox",
      "test": "substring(option[60].hex,0,5) == 'udhcp'",
      "option-data": [{"name": "tftp-server-name", "data": "tftp.passthrough.test", "always-send": true}]
    }],
    "networks": {"users": {"option-data": [{"name": "time-offset", "data": "3600", "always-send": true}]}}
  },
  "unbound": {"server": {"local-data": "\"passthrough.test. IN A 192.0.2.66\""}}
}}
JSON
    vm 'sudo sparewall merge -f /tmp/po.json --confirm 0' >/dev/null
    rm -f "$env"
    ns users busybox udhcpc -i eth0 -n -q -t 10 -T 3 -s "$WORK/udhcpc-po.sh" >/dev/null 2>&1 \
        || fail "no DHCP lease on users with passthrough options"
    [ "$(cat "$env")" = "tftp=tftp.passthrough.test timezone=3600" ] \
        || fail "the passthrough options did not reach the client: $(cat "$env")"
    [ "$(ns users dig +short +time=2 +tries=2 @192.0.2.1 passthrough.test)" = 192.0.2.66 ] \
        || fail "Unbound's passthrough record does not resolve"
    local out
    if out=$(vm "sudo sparewall set 'provider_options.kea.hooks-libraries=[]' --dry-run" 2>&1); then
        fail "a passthrough key Sparewall sets was accepted"
    fi
    echo "$out" | grep -q 'provider_options.kea.hooks-libraries' \
        || fail "the refused key's error does not name its path: $out"
    echo '{"provider_options": null}' | vm 'cat > /tmp/po.json'
    vm 'sudo sparewall merge -f /tmp/po.json --confirm 0' >/dev/null
    log "provider options PASS"
}

# Forwarding over TLS (#356), through tests/vm/dot-stub.py on the test
# host, its certificate for dot.test from a CA of the test's own: names
# resolve through it as dot.test, with dns.tls_ca; a forwarder named
# otherwise isn't used, there's no fallback, and health says why.
dns_tls() {
    local d="$WORK/dot"
    mkdir -p "$d"
    (
        cd "$d"
        openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ci-dot-ca 2>/dev/null
        openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj /CN=dot.test 2>/dev/null
        printf 'subjectAltName=DNS:dot.test\n' > srv.ext
        openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 2 -extfile srv.ext 2>/dev/null
    )
    python3 "$HERE/dot-stub.py" "$d/srv.pem" "$d/srv.key" 8853 192.0.2.99 > "$d/stub.log" 2>&1 &
    echo $! > "$d/stub.pid"
    tls_doc() { # name the forwarder's certificate is for
        # The stub signs nothing, so its zone is insecure to the
        # validator; a private resolver's internal zone would be too.
        jq -n --arg name "$1" --rawfile ca "$d/ca.pem" '{dns: {
            tls_forwarders: {stub: {addresses: ["10.0.2.2"], name: $name, port: 8853}},
            tls_ca: $ca},
          provider_options: {unbound: {server: {"domain-insecure": "dot-probe.example.net"}}}}'
    }
    dns_tls_check() { vm 'sudo sparewall status -o json' | jq -c '.health.checks[] | select(.name == "dns-tls")'; }
    tls_doc dot.test | vm 'cat > /tmp/tls.json'
    vm 'sudo sparewall merge -f /tmp/tls.json --confirm 0' >/dev/null
    vm 'sudo grep -A3 "^forward-zone:" /run/sparewall/dns/unbound.conf' | grep -q 'forward-addr: 10.0.2.2@8853#dot.test' \
        || fail "Unbound does not forward over TLS: $(vm 'sudo grep -A4 "^forward-zone:" /run/sparewall/dns/unbound.conf')"
    local a deadline=$((SECONDS + 60))
    until a=$(ns users dig +short +time=3 +tries=1 @192.0.2.1 a.dot-probe.example.net A) && [ "$a" = 192.0.2.99 ]; do
        [ $SECONDS -lt $deadline ] || {
            cat "$d/stub.log" >&2 || true
            vm 'sudo journalctl -b -u sparewall-unbound --no-pager | tail -20' || true
            fail "no answer through the TLS forwarder: '$a'"
        }
        sleep 3
    done
    grep -q '^a.dot-probe.example.net. 1$' "$d/stub.log" || fail "the stub saw no query for the name: $(cat "$d/stub.log")"
    deadline=$((SECONDS + 60))
    until dns_tls_check | jq -e '.level == "ok"' >/dev/null; do
        [ $SECONDS -lt $deadline ] || fail "the dns-tls check is not ok: $(dns_tls_check)"
        sleep 3
    done
    log "a TLS forwarder whose certificate is for another name isn't used"
    tls_doc wrong.test | vm 'cat > /tmp/tls.json'
    vm 'sudo sparewall merge -f /tmp/tls.json --confirm 0' >/dev/null
    deadline=$((SECONDS + 60))
    until dns_tls_check | jq -e '.level == "degraded" and (.message | contains("TLS"))' >/dev/null; do
        [ $SECONDS -lt $deadline ] || fail "the dns-tls check is not degraded with a wrong name: $(dns_tls_check)"
        sleep 3
    done
    : > "$d/stub.log"
    a=$(ns users dig +time=3 +tries=1 @192.0.2.1 b.dot-probe.example.net A | grep -o 'status: [A-Z]*') || true
    [ "$a" = "status: SERVFAIL" ] || fail "with a wrong name, the query got '$a', not SERVFAIL"
    ! grep -q dot-probe "$d/stub.log" || fail "a query went to the forwarder its certificate does not match"
    echo '{"dns": {"tls_forwarders": null, "tls_ca": null}, "provider_options": null}' | vm 'cat > /tmp/tls.json'
    vm 'sudo sparewall merge -f /tmp/tls.json --confirm 0' >/dev/null
    kill "$(cat "$d/stub.pid")" 2>/dev/null || true
    deadline=$((SECONDS + 60))
    until [ -z "$(dns_tls_check)" ]; do
        [ $SECONDS -lt $deadline ] || fail "the dns-tls check stayed after the forwarders went: $(dns_tls_check)"
        sleep 3
    done
    log "DNS over TLS PASS"
}

# A reply to a client-mode NTP request from namespace $1 at $2.
ntp_answers() {
    ns "$1" timeout 6 python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"\x23" + bytes(47), (sys.argv[1], 123))
s.recvfrom(100)' "$2" 2>/dev/null
}

# chronyd under the drop-in's tighter sandbox (#360): NoNewPrivileges,
# which SELinux allows into chronyd_t, only the capabilities it needs,
# serving the networks in ntp.serve, and still so after an apply that
# changes them.
chrony_hardened() {
    log "chronyd: NoNewPrivileges in chronyd_t, two capabilities left, serving users"
    local want='CapabilityBoundingSet=cap_dac_override cap_setgid cap_setuid cap_net_bind_service cap_sys_time'
    [ "$(vm 'systemctl show chronyd -p NoNewPrivileges --value')" = yes ] \
        || fail "chronyd runs without NoNewPrivileges"
    [ "$(vm 'systemctl show chronyd -p CapabilityBoundingSet')" = "$want" ] \
        || fail "chronyd's bounding set: $(vm 'systemctl show chronyd -p CapabilityBoundingSet')"
    # shellcheck disable=SC2016 # the node expands \$(pgrep ...)
    chronyd_checks() {
        vm 'ps -eo label,comm' | grep -qE '^system_u:system_r:chronyd_t:s0 +chronyd$' \
            || fail "chronyd is not in chronyd_t: $(vm 'ps -eo label,comm' | grep chronyd)"
        # SYS_TIME and NET_BIND_SERVICE, once it is the chrony user.
        [ "$(vm 'grep ^CapEff: /proc/$(pgrep -x chronyd)/status' | awk '{print $2}')" = 0000000002000400 ] \
            || fail "chronyd's effective capabilities: $(vm 'grep ^Cap /proc/$(pgrep -x chronyd)/status')"
    }
    chronyd_checks
    local score
    score=$(vm 'sudo systemd-analyze security chronyd.service' | sed -n 's/.*exposure level for chronyd.service: \([0-9.]*\).*/\1/p')
    awk -v s="$score" 'BEGIN { exit !(s != "" && s <= 3.1) }' \
        || fail "chronyd's exposure is ${score:-unknown}, not 3.1 or better"
    local deadline=$((SECONDS + 60))
    until ntp_answers users 192.0.2.1; do
        [ $SECONDS -lt $deadline ] || {
            vm 'sudo journalctl -b -u chronyd --no-pager | tail -20' || true
            fail "chronyd does not serve time to users"
        }
        sleep 3
    done
    ! ntp_answers guests 198.51.100.1 || fail "chronyd served time to guests, which ntp.serve does not name"
    log "chronyd after an apply that serves guests too"
    echo '{"ntp": {"serve": ["users", "guests"]}}' | vm 'cat > /tmp/ntp.json'
    vm 'sudo sparewall merge -f /tmp/ntp.json --confirm 0' >/dev/null
    deadline=$((SECONDS + 60))
    until ntp_answers guests 198.51.100.1; do
        [ $SECONDS -lt $deadline ] || {
            vm 'systemctl status --no-pager chronyd; sudo journalctl -b -u chronyd --no-pager | tail -20' || true
            fail "chronyd does not serve guests after the apply"
        }
        sleep 3
    done
    [ "$(vm 'systemctl is-active chronyd')" = active ] || fail "chronyd is not active after the apply"
    chronyd_checks
    ntp_answers users 192.0.2.1 || fail "chronyd stopped serving users after the apply"
}

# Network Time Security (#357): an NTS server on the users VLAN, chronyd
# from the image under test in a container in sw-users' namespace, its
# certificate for nts.test from a CA of the test's own. The node finds
# nts.test in /etc/hosts. It authenticates as nts.test with ntp.nts_ca,
# and health says so; named otherwise, it doesn't, and health says that.
ntp_nts() {
    log "NTS: chrony authenticates the server as the name its certificate is for"
    local d="$WORK/nts"
    mkdir -p "$d/dump"
    (
        cd "$d"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ci-nts-ca 2>/dev/null
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj /CN=nts.test 2>/dev/null
        printf 'subjectAltName=DNS:nts.test\n' > srv.ext
        openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 2 -extfile srv.ext 2>/dev/null
        chmod 644 srv.key
        cat > server.conf <<'CONF'
local stratum 1
allow all
cmdport 0
ntsserverkey /nts/srv.key
ntsservercert /nts/srv.pem
ntsdumpdir /nts/dump
CONF
    )
    ns users ip addr add 192.0.2.40/24 dev eth0
    # -x: serve time, never set the runner's clock.
    sudo podman run -d --rm --name sw-nts --network ns:/run/netns/sw-users \
        -v "$d:/nts:Z" --entrypoint /usr/sbin/chronyd "$IMAGE" -d -x -u root -f /nts/server.conf >/dev/null
    vm 'printf "192.0.2.40 nts.test\n192.0.2.40 wrong.test\n" | sudo tee -a /etc/hosts >/dev/null'
    nts_doc() { # server name
        jq -n --arg s "$1" --rawfile ca "$d/ca.pem" '{ntp: {servers: [$s], nts: true, nts_ca: $ca}}'
    }
    nts_check() { vm 'sudo sparewall status -o json' | jq -c '.health.checks[] | select(.name == "ntp-nts")'; }
    nts_doc nts.test | vm 'cat > /tmp/nts.json'
    vm 'sudo sparewall merge -f /tmp/nts.json --confirm 0' >/dev/null
    vm 'sudo grep -x "server nts.test iburst nts" /run/chrony/sparewall.conf' >/dev/null \
        || fail "chrony's configuration has no NTS server: $(vm 'sudo cat /run/chrony/sparewall.conf')"
    local deadline=$((SECONDS + 150))
    until nts_check | jq -e '.level == "ok" and (.message | contains("192.0.2.40 authenticated"))' >/dev/null; do
        [ $SECONDS -lt $deadline ] || {
            sudo podman logs sw-nts 2>&1 | tail -20 || true
            vm 'sudo chronyc -n authdata; sudo chronyc -n ntpdata; sudo journalctl -b -u chronyd --no-pager | tail -20' || true
            fail "chrony did not authenticate nts.test: $(nts_check)"
        }
        sleep 5
    done
    # NTS cookies from the key exchange, and authenticated responses since.
    vm 'sudo chronyc -n -c authdata' | awk -F, '$1 == "192.0.2.40" && $2 == "NTS" && $9 > 0' | grep -q . \
        || fail "chronyc authdata shows no NTS cookies from 192.0.2.40: $(vm 'sudo chronyc -n -c authdata')"
    vm 'sudo chronyc -n ntpdata' | grep -q '^Authenticated *: Yes' \
        || fail "chrony's last response from 192.0.2.40 was not authenticated: $(vm 'sudo chronyc -n ntpdata')"
    log "NTS: a server whose certificate is for another name isn't authenticated"
    nts_doc wrong.test | vm 'cat > /tmp/nts.json'
    vm 'sudo sparewall merge -f /tmp/nts.json --confirm 0' >/dev/null
    deadline=$((SECONDS + 150))
    until nts_check | jq -e '.level == "degraded"' >/dev/null; do
        [ $SECONDS -lt $deadline ] || fail "the ntp-nts check is not degraded with a wrong name: $(nts_check)"
        sleep 5
    done
    echo '{"ntp": {"servers": null, "nts": null, "nts_ca": null}}' | vm 'cat > /tmp/nts.json'
    vm 'sudo sparewall merge -f /tmp/nts.json --confirm 0' >/dev/null
    vm 'sudo sed -i "/ nts.test$/d; / wrong.test$/d" /etc/hosts'
    sudo podman rm -f sw-nts >/dev/null 2>&1 || true
    ns users ip addr del 192.0.2.40/24 dev eth0
    deadline=$((SECONDS + 90))
    until [ -z "$(nts_check)" ]; do
        [ $SECONDS -lt $deadline ] || fail "the ntp-nts check stayed after NTS was turned off: $(nts_check)"
        sleep 5
    done
    log "NTS PASS"
}

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

    squatter "$g"

    can users 192.0.2.1 || fail "users cannot ping the gateway"
    can users "$g" || fail "users cannot reach guests"
    ! can guests "$u" || fail "guests reached users"
    ! can guests 198.51.100.1 || fail "guests could ping the firewall"

    hairpin

    local a
    a=$(ns users dig +short +time=3 +tries=3 @192.0.2.1 printer.home.arpa) || true
    [ "$a" = 192.0.2.9 ] || fail "local DNS record: got '$a'"
    a=$(ns users dig +short +time=3 +tries=3 @192.0.2.1 client20.home.arpa) || true
    [ "$a" = 192.0.2.20 ] || fail "reservation name: got '$a'"
    vm 'sudo nft list chain inet sparewall fwd_guests_users' | grep -q 'packets [1-9]' \
        || fail "the guests->users default drop counted nothing"
    # That drop is logged: ulogd (in ulogd_t, under NoNewPrivileges) hands
    # each hit to the coordinator, which writes it to the journal.
    vm 'systemctl is-active sparewall-ulogd' >/dev/null \
        || { vm 'sudo journalctl -b -u sparewall-ulogd --no-pager | tail -20' || true
             fail "sparewall-ulogd is not running"; }
    vm "sudo journalctl -b -u sparewalld TARGET=sparewall::rules F_RULE='guests->users:default' --no-pager -o cat | grep -q 'rule hit'" \
        || fail "the logged guests->users drop is not in the journal"
    # And through the API (#262): by rule, by pair, and by the users'
    # prefix it was bound for, but not by another.
    hits() { vm "sudo sparewall hits -o json -n 20 $*" | jq 'length'; }
    [ "$(hits "--rule 'guests->users:default'")" -gt 0 ] || fail "sparewall hits finds no guests->users drop"
    [ "$(hits "--pair 'guests->users'")" -gt 0 ] || fail "sparewall hits finds nothing for the pair"
    [ "$(hits "--pair 'guests->users' --addr 192.0.2.0/24")" -gt 0 ] \
        || fail "sparewall hits finds nothing bound for the users' prefix"
    [ "$(hits "--pair 'guests->users' --addr 203.0.113.0/24")" = 0 ] \
        || fail "sparewall hits matched an address the drop never had"
    # Last: each applies a change, and a reload resets the rule counters
    # the checks above read.
    chrony_hardened
    ntp_nts
    dns_intercept
    dns_filters
    provider_options
    dns_tls
    log "conformance PASS"
}

# A restic REST server on 127.0.0.1:8000 (10.0.2.2:8000 from the VMs),
# storing under $WORK/restic.
start_rest_server() {
    local v=${REST_SERVER:-0.14.0}
    local sum=${REST_SHA256:-4c9c95bc079a0334e81fad379b19dc5c3353c71c2c88d652cafce2081c2b1c66}
    if ! command -v rest-server >/dev/null; then
        local f=rest-server_${v}_linux_amd64.tar.gz
        curl -fsSLO "https://github.com/restic/rest-server/releases/download/v$v/$f"
        echo "$sum  $f" | sha256sum -c -
        tar -xzf "$f" --strip-components=1 "rest-server_${v}_linux_amd64/rest-server"
        # The release archive ships it without the execute bit.
        chmod +x rest-server
        PATH=$WORK:$PATH
    fi
    mkdir -p "$WORK/restic"
    rest-server --path "$WORK/restic" --listen 127.0.0.1:8000 --no-auth >"$WORK/rest-server.log" 2>&1 &
    echo $! > "$WORK/rest-server.pid"
    local deadline=$((SECONDS + 30))
    until curl -s -o /dev/null http://127.0.0.1:8000/; do
        [ $SECONDS -lt $deadline ] || fail "rest-server did not start: $(cat "$WORK/rest-server.log")"
        sleep 1
    done
}

# Rebuild the node's policy without dontaudit rules, so that the report
# below also sees denials the policy hides: hidden ones still fail once
# sparewalld_t is enforcing. It persists across reboots.
# $1 runs a command on a node.
full_audit() { # run-command node-name
    $1 'sudo semodule -DB' || fail "$2: cannot disable dontaudit rules"
}

# The coordinator's SELinux domain and its denials, for the job summary:
# what sparewalld_t and the daemons it configures were denied, and what
# any domain was denied on the coordinator's types (all enforcing, so
# blocked).
# Either means image/selinux lacks a rule: it is recorded in
# $WORK/selinux-denials and fails the suite (selinux_gate).
# $1 runs a command on a node.
selinux_report() { # run-command node-name
    local run=$1 node=$2 denials
    $run 'ps -eo label,comm' | grep -q 'sparewalld_t.*sparewalld' \
        || fail "$node: sparewalld does not run in sparewalld_t"
    # Kernel log and journald's audit transport: with auditd running, or
    # kauditd rate-limiting printk, either one alone misses records.
    # The coordinator, or a daemon it configures (keepalived and its
    # scripts, conntrackd, rsyslog but not journald, which shares its
    # domain, Prometheus in its container), bootupd (#111) or the guest
    # agent denied anything, or any domain denied the coordinator's own
    # files (a consumer of /run/sparewall, say). Not the checks of a domain
    # transition's environment scrubbing, nor dig's io_uring, which it
    # does without (#264), both of which the policy hides (dontaudit, off
    # here): they are denied by design.
    denials=$($run 'sudo journalctl -b -k --no-pager; sudo journalctl -b --no-pager _TRANSPORT=audit' \
        | grep -oE 'avc: +denied .*' \
        | grep -E 'scontext=[^ ]*:(sparewalld|sparewall_httpd|sparewall_capture|keepalived|keepalived_unconfined_script|conntrackd|bootupd|virt_qemu_ga|virt_qemu_ga_unconfined)_t:|tcontext=[^ ]*:(sparewalld|sparewall_httpd|sparewall_capture)_[a-z_]*:|comm="rsyslogd" .*scontext=[^ ]*:syslogd_t:|comm="prometheus" .*scontext=[^ ]*:container_t:' \
        | grep -vE 'denied +\{ (noatsecure|siginh|rlimitinh) \}' \
        | grep -vE 'denied +\{ create \} .*comm="dig" .*anonclass=\[io_uring\]' \
        | sed -E 's/ (pid|ino|dev)=[^ ]+//g; s/ permissive=[01]//' \
        | sort | uniq -c | sort -rn) || true
    echo "$node: $(printf '%s' "$denials" | grep -c . || true) distinct denials"
    printf '%s\n' "$denials"
    # keepalived signals init when it may not getpgid a running script
    # (the keepalived rule in sparewalld.te).
    if $run 'sudo journalctl -b --no-pager _PID=1' | grep -q 'Received SIG[A-Z]* from PID [0-9]* (keepalived)'; then
        echo "$node: keepalived signalled systemd" | tee -a "$WORK/selinux-denials"
    fi
    # bootc run by sparewall-run@ outside install_t: its probe for
    # mac_admin, a chcon to an undefined label, is denied (#110). In
    # install_t the probe succeeds, and the kernel logs the label as
    # unmapped, so only the denial counts.
    # (Counted, not grep -q, which would cut the pipe short.)
    local probes unlabelled
    probes=$($run 'sudo journalctl -b -k --no-pager; sudo journalctl -b --no-pager _TRANSPORT=audit' \
        | grep -cE 'avc: +denied +\{ mac_admin \} .*comm="chcon"' || true)
    [ "$probes" = 0 ] \
        || echo "$node: bootc ran outside install_t (its mac_admin probe was denied)" | tee -a "$WORK/selinux-denials"
    # Files in /boot as the policy labels them (sparewall-label-boot, #111).
    unlabelled=$($run 'sudo restorecon -Rnvx /boot' | grep -c 'Would relabel' || true)
    if [ "$unlabelled" != 0 ]; then
        echo "$node: $unlabelled files in /boot are mislabelled" | tee -a "$WORK/selinux-denials"
        $run 'findmnt /boot; systemctl status --no-pager sparewall-label-boot.service' || true
    fi
    # Nothing unlabelled under /sysroot (sparewall-label-sysroot, #152).
    unlabelled=$($run 'sudo find /sysroot -xdev -context "*:unlabeled_t:*" -printf "%p\n"' | grep -c . || true)
    if [ "$unlabelled" != 0 ]; then
        echo "$node: $unlabelled files under /sysroot are unlabelled" | tee -a "$WORK/selinux-denials"
        $run 'systemctl status --no-pager sparewall-label-sysroot.service' || true
    fi
    [ -z "$denials" ] || printf '%s\n' "$denials" | sed "s/^/$node: /" >> "$WORK/selinux-denials"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### SELinux: sparewalld_t, keepalived_t, conntrackd_t, bootupd_t on $node"
            echo '```'
            printf '%s\n' "${denials:-none}"
            echo '```'
        } >> "$GITHUB_STEP_SUMMARY"
    fi
}

# The node's own view: sparewalld watches the audit stream (the selinux
# check would say it cannot), has seen no denial, and takes an
# acknowledgement, recording who gave it. $1 runs a command on a node.
selinux_health() { # run-command node-name
    local c
    c=$($1 'sudo sparewall health -v -o json' | jq -c '.checks[] | select(.name == "selinux")')
    [ -n "$c" ] || fail "$2: no selinux health check"
    [ "$(jq -r .level <<<"$c")" = ok ] || fail "$2: selinux check: $c"
    $1 'sudo sparewall health ack selinux' >/dev/null || fail "$2: cannot acknowledge the selinux check"
    $1 'sudo sparewall health -v -o json' \
        | jq -e '.checks[] | select(.name == "selinux") | .message | test("since admin .*acknowledged 0 at")' >/dev/null \
        || fail "$2: the acknowledgement was not recorded"
}

# The escape hatch operations.md documents: a module that makes only
# sparewalld_t permissive, then its removal. $1 runs a command on a node.
permissive_drill() { # run-command node-name
    $1 "echo '(typepermissive sparewalld_t)' > /tmp/sparewalld-permissive.cil && sudo semodule -i /tmp/sparewalld-permissive.cil" \
        || fail "$2: cannot make sparewalld_t permissive"
    $1 'sudo semodule -l | grep -qx sparewalld-permissive' || fail "$2: the permissive module is not installed"
    $1 'sudo semodule -r sparewalld-permissive' || fail "$2: cannot make sparewalld_t enforcing again"
    ! $1 'sudo semodule -l | grep -qx sparewalld-permissive' || fail "$2: the permissive module is still installed"
}

# Fail if any report found a denial.
selinux_gate() {
    [ -s "$WORK/selinux-denials" ] || return 0
    echo "FAIL: SELinux denials or their effects; add rules to image/selinux/sparewalld.te:" >&2
    cat "$WORK/selinux-denials" >&2
    return 1
}
