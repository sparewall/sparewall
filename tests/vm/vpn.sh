#!/bin/bash
# Remote-access VPN across failover (issue #8), sourced by pair-test.sh.
#
# WireGuard keeps per-session state (ephemeral keys, receiver indices):
# the new master shares the static key but none of the old master's
# sessions, so a client's packets are dropped until the client makes a
# new handshake. These clients measure how long that takes:
#
#   vpna    active: pings, plus an inner TCP and an inner UDP flow
#   vpnb    idle, its session older than 120 s when the master goes
#   vpnc    idle, its session fresh (made just before)
#   natc    active, behind NAT (router sw-nat), PersistentKeepalive 25
#
# All four sit on the WAN VLAN 10 and connect to the gateway address
# 203.0.113.1:51820. Inner flows go to the echo servers in sw-guests
# (198.51.100.10: TCP 7000, UDP 7001).

VPN_SERVER=203.0.113.1
VPN_TARGET=198.51.100.10
VPN_RESULTS=$WORK/vpn-results.md
VPN_CLIENTS="vpna vpnb vpnc natc"

# Client keys, before pairing: the document lists their public keys.
vpn_keys() {
    local c
    for c in $VPN_CLIENTS; do
        wg genkey > "$WORK/$c.key"
        wg pubkey < "$WORK/$c.key" > "$WORK/$c.pub"
    done
}

# Substitute the client public keys into a document on stdin.
vpn_doc() {
    sed -e "s|@VPNA@|$(cat "$WORK/vpna.pub")|" -e "s|@VPNB@|$(cat "$WORK/vpnb.pub")|" \
        -e "s|@VPNC@|$(cat "$WORK/vpnc.pub")|" -e "s|@NATC@|$(cat "$WORK/natc.pub")|"
}

# A namespace on the WAN VLAN.
wan_ns() { # name address
    sudo ip netns add "sw-$1"
    sudo ip link add "v-$1" type veth peer name eth0 netns "sw-$1"
    sudo ip link set "v-$1" master swbr up
    sudo bridge vlan del dev "v-$1" vid 1
    sudo bridge vlan add dev "v-$1" vid 10 pvid untagged
    ns "$1" ip link set lo up
    ns "$1" ip addr add "$2/24" dev eth0
    ns "$1" ip link set eth0 up
}

wg_client() { # name tunnel-address [keepalive]
    local name=$1 addr=$2 ka=${3:-}
    ns "$name" ip link add wg0 type wireguard
    ns "$name" wg set wg0 private-key "$WORK/$name.key" \
        peer "$VPN_PUB" endpoint "$VPN_SERVER:51820" \
        allowed-ips 10.99.0.0/24,198.51.100.0/24 ${ka:+persistent-keepalive $ka}
    ns "$name" ip addr add "$addr/32" dev wg0
    ns "$name" ip link set wg0 up
    ns "$name" ip route add 10.99.0.0/24 dev wg0
    ns "$name" ip route add 198.51.100.0/24 dev wg0
}

# Time of the client's latest handshake (0 if none).
handshake() { ns "$1" wg show wg0 latest-handshakes | awk '{print $2}'; }

reach() { ns "$1" ping -c 1 -W 1 "$VPN_TARGET" >/dev/null 2>&1; }

vpn_setup() {
    log "remote-access VPN clients"
    server_key() { at "$1" 'sudo sparewall vpn client-config vpna' | sed -n 's/^PublicKey = //p'; }
    same_key() { [ -n "$(server_key fw1)" ] && [ "$(server_key fw1)" = "$(server_key fw2)" ]; }
    wait_for 120 "both nodes share the VPN server key" same_key
    VPN_PUB=$(server_key fw1)
    wan_ns vpna 203.0.113.50
    wan_ns vpnb 203.0.113.51
    # natc sits behind a masquerading router.
    wan_ns nat 203.0.113.53
    sudo ip netns add sw-natc
    sudo ip -n sw-nat link add in0 type veth peer name eth0 netns sw-natc
    ns nat ip addr add 172.16.0.1/24 dev in0
    ns nat ip link set in0 up
    ns nat sysctl -qw net.ipv4.ip_forward=1
    ns nat iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ns natc ip link set lo up
    ns natc ip addr add 172.16.0.2/24 dev eth0
    ns natc ip link set eth0 up
    ns natc ip route add default via 172.16.0.1
    wg_client vpna 10.99.0.10
    wg_client vpnb 10.99.0.11
    wg_client natc 10.99.0.13 25
    # vpnc is set up just before the master goes, for a fresh session.
    for c in vpna vpnb natc; do
        wait_for 30 "$c reaches $VPN_TARGET through the VPN" reach "$c"
    done
    VPNB_SINCE=$(handshake vpnb)
    # Inner flows from vpna (the echo servers run in sw-guests), and
    # timestamped pings from the active clients.
    ns vpna python3 "$WORK/echo.py" client "$VPN_TARGET" 120 > vpn-tcp.log 2>&1 &
    ns vpna python3 "$WORK/echo.py" udpclient "$VPN_TARGET" > vpn-udp.log 2>&1 &
    ns vpna ping -D -i 0.2 -W 1 "$VPN_TARGET" > vpna.ping 2>&1 &
    ns natc ping -D -i 0.2 -W 1 "$VPN_TARGET" > natc.ping 2>&1 &
    sleep 3
    vpn_tcp_count >/dev/null || fail "no inner TCP echoes: $(cat vpn-tcp.log)"
    grep -q reply vpn-udp.log || fail "no inner UDP echoes: $(cat vpn-udp.log)"
    printf '| Event | Client | Recovery (s) |\n| --- | --- | --- |\n' > "$VPN_RESULTS"
}

vpn_tcp_count() { tail -1 vpn-tcp.log | grep -E '^[0-9]+$'; }

# Make vpnb's session older than WireGuard's REKEY_AFTER_TIME (120 s),
# and give vpnc a fresh one, just before the master goes.
vpn_before_loss() {
    local age=$(( $(date +%s) - VPNB_SINCE ))
    if [ "$age" -lt 125 ]; then
        log "letting vpnb's session age ($age s) past 120 s"
        sleep $((125 - age))
    fi
    wan_ns vpnc 203.0.113.52
    wg_client vpnc 10.99.0.12
    wait_for 30 "vpnc reaches $VPN_TARGET through the VPN" reach vpnc
    VPN_LOSS_AT=$(date +%s.%N)
}

# Seconds until an idle client gets through, probing once a second.
idle_recovery() { # client
    local t0 t1 i
    t0=$(date +%s.%N)
    for i in $(seq 1 120); do
        if reach "$1"; then
            t1=$(date +%s.%N)
            awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", b - a }'
            return 0
        fi
    done
    echo "never"
}

# The longest gap between replies in a timestamped log since $2.
gap() { # file since
    python3 - "$1" "$2" <<'PY'
import re, sys
since = float(sys.argv[2])
ts = [float(m.group(1)) for line in open(sys.argv[1])
      if (m := re.match(r"\[(\d+\.\d+)\].*(bytes from|reply)", line))]
ts = [t for t in ts if t >= since]
if not ts:
    print("never")
else:
    gaps = [b - a for a, b in zip([since] + ts, ts)]
    print(f"{max(gaps):.1f}")
PY
}

record() { # event client seconds
    echo "| $1 | $2 | $3 |" >> "$VPN_RESULTS"
    echo "  $1: $2 recovered in $3 s"
}

# Check every client recovers within $bound s after the gateway moved,
# and the inner flows continue.
vpn_after_move() { # event since
    local event=$1 since=$2 bound=60 c s
    log "VPN after $event"
    # Idle clients first, in parallel: probing is what wakes them.
    for c in vpnb vpnc; do idle_recovery "$c" > "$c.recovery" & done
    wait
    sleep 20   # let the active clients' pings show their recovery
    for c in vpnb vpnc; do
        s=$(cat "$c.recovery")
        record "$event" "$c (idle)" "$s"
        [ "$s" != never ] || fail "$c never recovered after $event"
        awk -v s="$s" -v b="$bound" 'BEGIN { exit !(s <= b) }' || fail "$c took $s s after $event"
    done
    for c in vpna natc; do
        s=$(gap "$c.ping" "$since")
        record "$event" "$c (active, longest gap)" "$s"
        [ "$s" != never ] || fail "$c never recovered after $event"
        awk -v s="$s" -v b="$bound" 'BEGIN { exit !(s <= b) }' || fail "$c's pings stopped for $s s after $event"
    done
    # Inner flows, separately from the tunnel: the TCP connection
    # survived (conntrackd) and keeps echoing; UDP replies resumed.
    grep -q broken vpn-tcp.log && fail "the inner TCP connection broke after $event: $(tail -3 vpn-tcp.log)"
    local n1 n2
    n1=$(vpn_tcp_count) || fail "the inner TCP connection stalled after $event: $(tail -3 vpn-tcp.log)"
    sleep 3
    n2=$(vpn_tcp_count) || fail "the inner TCP connection stalled after $event"
    [ "$n2" -gt "$n1" ] || fail "the inner TCP connection stopped after $event ($n1, $n2)"
    s=$(gap vpn-udp.log "$since")
    record "$event" "vpna inner UDP (longest gap)" "$s"
    [ "$s" != never ] || fail "inner UDP never resumed after $event"
    sleep 2
    tail -5 vpn-udp.log | grep -q reply || fail "inner UDP is not flowing after $event: $(tail -3 vpn-udp.log)"
}

vpn_summary() {
    log "VPN recovery"
    cat "$VPN_RESULTS"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        { echo "### Remote-access VPN recovery"; cat "$VPN_RESULTS"; } >> "$GITHUB_STEP_SUMMARY"
    fi
}
