#!/bin/bash
# Remote-access VPN across failover (issue #8), sourced by pair-test.sh.
#
# WireGuard keeps per-session state (ephemeral keys, receiver indices):
# the new master shares the static key but none of the old master's
# sessions, so a client's packets are dropped until the client makes a
# new handshake. These clients measure how long that takes:
#
#   vpna    active: pings, plus an inner TCP and an inner UDP flow
#   vpnb    idle, its session older than 120 s when the gateway moves
#   vpnc    idle, its session fresh (at most 100 s old) when it moves
#   natc    active, behind NAT (router sw-nat), PersistentKeepalive 25
#   natk    idle behind NAT, PersistentKeepalive 25: it sends no data
#           until it has a new handshake, which only rekeying can start
#
# All sit on the WAN VLAN 10 and connect to the gateway address
# 203.0.113.1:51820. Inner flows go to the echo servers in sw-guests
# (198.51.100.10: TCP 7000, UDP 7001). Probing starts the moment the
# gateway moves (vpn_moved), so each session is in its intended age
# bucket; the results are checked later (vpn_after_move).

VPN_SERVER=203.0.113.1
VPN_TARGET=198.51.100.10
VPN_RESULTS=${WORK:-.}/vpn-results.md
VPN_CLIENTS="vpna vpnb vpnc natc natk"
# The longest any client may be cut off. A keepalive-only client waits
# for its session to reach REKEY_AFTER_TIME (120 s) and its next
# keepalive (25 s), plus handshake retries.
VPN_BOUND=60
VPN_KEEPALIVE_BOUND=180

# Client keys, before pairing: the document lists their public keys.
vpn_keys() {
    local c
    for c in $VPN_CLIENTS; do
        wg genkey > "$WORK/$c.key"
        wg pubkey < "$WORK/$c.key" > "$WORK/$c.pub"
    done
}

# Substitute the client public keys (@VPNA@...) into a document on stdin.
vpn_doc() {
    local args=() c
    for c in $VPN_CLIENTS; do
        args+=(-e "s|@${c^^}@|$(cat "$WORK/$c.pub")|")
    done
    sed "${args[@]}"
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

# A namespace behind the NAT router, on its own inside link.
nat_ns() { # name inside-link prefix (172.16.0: router .1, client .2)
    sudo ip netns add "sw-$1"
    sudo ip -n sw-nat link add "$2" type veth peer name eth0 netns "sw-$1"
    ns nat ip addr add "$3.1/24" dev "$2"
    ns nat ip link set "$2" up
    ns "$1" ip link set lo up
    ns "$1" ip addr add "$3.2/24" dev eth0
    ns "$1" ip link set eth0 up
    ns "$1" ip route add default via "$3.1"
}

wg_peer() { # name [keepalive]
    ns "$1" wg set wg0 peer "$VPN_PUB" endpoint "$VPN_SERVER:51820" \
        allowed-ips 10.99.0.0/24,198.51.100.0/24 ${2:+persistent-keepalive $2}
}

wg_client() { # name tunnel-address [keepalive]
    local name=$1 addr=$2 ka=${3:-}
    ns "$name" ip link add wg0 type wireguard
    ns "$name" wg set wg0 private-key "$WORK/$name.key"
    wg_peer "$name" "$ka"
    ns "$name" ip addr add "$addr/32" dev wg0
    ns "$name" ip link set wg0 up
    ns "$name" ip route add 10.99.0.0/24 dev wg0
    ns "$name" ip route add 198.51.100.0/24 dev wg0
}

# Time of the client's latest handshake (0 if none).
handshake() { ns "$1" wg show wg0 latest-handshakes | awk '{print $2}'; }

session_age() { echo $(( $(date +%s) - $(handshake "$1") )); }

# Wait until the client's current session is at least $2 seconds old
# (each probe that makes it rekey starts a new one).
age_session() { # client seconds
    local age
    age=$(session_age "$1")
    if [ "$age" -lt "$2" ]; then
        echo "  letting $1's session age ($age s) past $2 s"
        sleep $(($2 - age))
    fi
}

reach() { ns "$1" ping -c 1 -W 1 "$VPN_TARGET" >/dev/null 2>&1; }

# Put an idle client on a new session: forget the peer and its keys, then
# send.
fresh_session() { # client
    ns "$1" wg set wg0 peer "$VPN_PUB" remove
    wg_peer "$1"
    wait_for 30 "$1 reaches $VPN_TARGET on a new session" reach "$1"
}

vpn_setup() {
    log "remote-access VPN clients"
    server_key() { at "$1" 'sudo sparewall vpn client-config vpna' | sed -n 's/^PublicKey = //p'; }
    same_key() { [ -n "$(server_key fw1)" ] && [ "$(server_key fw1)" = "$(server_key fw2)" ]; }
    wait_for 120 "both nodes share the VPN server key" same_key
    VPN_PUB=$(server_key fw1)
    wan_ns vpna 203.0.113.50
    wan_ns vpnb 203.0.113.51
    # natc and natk sit behind a masquerading router.
    wan_ns nat 203.0.113.53
    ns nat sysctl -qw net.ipv4.ip_forward=1
    ns nat iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    nat_ns natc in0 172.16.0
    nat_ns natk in1 172.16.1
    wg_client vpna 10.99.0.10
    wg_client vpnb 10.99.0.11
    wg_client natc 10.99.0.13 25
    # natk never sends data: bringing it up sends a keepalive, which
    # starts its first handshake.
    wg_client natk 10.99.0.14 25
    # vpnc is set up just before the master goes, for a fresh session.
    for c in vpna vpnb natc; do
        wait_for 30 "$c reaches $VPN_TARGET through the VPN" reach "$c"
    done
    has_session() { [ "$(handshake "$1")" -gt 0 ]; }
    wait_for 30 "natk has a session from keepalives alone" has_session natk
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
    age_session vpnb 125
    wan_ns vpnc 203.0.113.52
    wg_client vpnc 10.99.0.12
    wait_for 30 "vpnc reaches $VPN_TARGET through the VPN" reach vpnc
}

# Run the rolling upgrade command ($@) in the background, keeping vpnc's
# session fresh until the handover, and start probing the moment it
# happens. vpnb's session is renewed by the probes after master loss, so
# it is aged again first. Returns the command's status.
vpn_through_upgrade() {
    age_session vpnb 125
    "$@" > upgrade.log 2>&1 &
    local up=$! t0=$SECONDS rc
    until grep -q '^\[failover\]' upgrade.log; do
        kill -0 "$up" 2>/dev/null || break
        [ $((SECONDS - t0)) -lt 1500 ] || fail "no handover in the upgrade: $(tail -5 upgrade.log)"
        if [ "$(session_age vpnc)" -gt 60 ]; then
            fresh_session vpnc
        fi
        sleep 0.2
    done
    if grep -q '^\[failover\]' upgrade.log; then
        vpn_moved "rolling upgrade"
    fi
    wait "$up"
    rc=$?
    cat upgrade.log
    return $rc
}

# The gateway just moved: check the idle sessions are in their age
# buckets, then probe the idle clients at once, in parallel.
vpn_moved() { # event
    local a
    VPN_MOVED_AT=$(date +%s.%N)
    a=$(session_age vpnb)
    [ "$a" -ge 120 ] || fail "vpnb's session is only $a s old at $1"
    a=$(session_age vpnc)
    [ "$a" -le 100 ] || fail "vpnc's session is already $a s old at $1"
    VPN_PROBES=()
    idle_recovery vpnb > vpnb.recovery &
    VPN_PROBES+=($!)
    idle_recovery vpnc > vpnc.recovery &
    VPN_PROBES+=($!)
    keepalive_recovery natk "$VPN_MOVED_AT" > natk.recovery &
    VPN_PROBES+=($!)
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

# Seconds until a client sending only keepalives has a new handshake
# (whole seconds: wg reports handshake times in seconds).
keepalive_recovery() { # client since
    local since=${2%.*} h i
    for i in $(seq 1 $((VPN_KEEPALIVE_BOUND + 30))); do
        h=$(handshake "$1")
        if [ "$h" -gt "$since" ]; then
            echo $((h - since))
            return 0
        fi
        sleep 1
    done
    echo "never"
}

# The longest gap between replies in a timestamped log from $2 until
# now (so replies that stopped for good count too).
gap() { # file since
    python3 - "$1" "$2" <<'PY'
import re, sys, time
since = float(sys.argv[2])
ts = [float(m.group(1)) for line in open(sys.argv[1])
      if (m := re.match(r"\[(\d+\.\d+)\].*(bytes from|reply)", line))]
ts = [t for t in ts if t >= since]
if not ts:
    print("never")
else:
    gaps = [b - a for a, b in zip([since] + ts, ts + [time.time()])]
    print(f"{max(gaps):.1f}")
PY
}

record() { # event client seconds
    echo "| $1 | $2 | $3 |" >> "$VPN_RESULTS"
    echo "  $1: $2 recovered in $3 s"
}

# Record a recovery time; fail if there was none or it exceeds the bound.
check_recovery() { # event client seconds bound
    record "$1" "$2" "$3"
    [ "$3" != never ] || fail "$2 never recovered after $1"
    awk -v s="$3" -v b="$4" 'BEGIN { exit !(s <= b) }' \
        || fail "$2 was cut off for $3 s after $1 (bound $4 s)"
}

# Check every client recovered within its bound after vpn_moved, and the
# inner flows continue.
vpn_after_move() { # event
    local event=$1 since=$VPN_MOVED_AT c s
    log "VPN after $event"
    wait "${VPN_PROBES[@]}"
    # Let the active clients' pings show their recovery.
    s=$(awk -v a="$since" -v b="$(date +%s.%N)" 'BEGIN { printf "%d", 30 - (b - a) }')
    [ "$s" -le 0 ] || sleep "$s"
    for c in vpnb vpnc; do
        check_recovery "$event" "$c (idle)" "$(cat "$c.recovery")" "$VPN_BOUND"
    done
    check_recovery "$event" "natk (idle, keepalives only)" "$(cat natk.recovery)" "$VPN_KEEPALIVE_BOUND"
    wait_for 30 "natk reaches $VPN_TARGET after $event" reach natk
    for c in vpna natc; do
        check_recovery "$event" "$c (active, longest gap)" "$(gap "$c.ping" "$since")" "$VPN_BOUND"
    done
    # Every client still talks to the gateway address: a reply from a
    # node's own address would have made it roam there.
    for c in $VPN_CLIENTS; do
        s=$(ns "$c" wg show wg0 endpoints | awk '{print $2}')
        [ "$s" = "$VPN_SERVER:51820" ] || fail "$c roamed to $s after $event"
    done
    # Inner flows, separately from the tunnel: the TCP connection
    # survived (conntrackd) and keeps echoing; UDP replies resumed.
    grep -q broken vpn-tcp.log && fail "the inner TCP connection broke after $event: $(tail -3 vpn-tcp.log)"
    local n1 n2
    n1=$(vpn_tcp_count) || fail "the inner TCP connection stalled after $event: $(tail -3 vpn-tcp.log)"
    sleep 3
    n2=$(vpn_tcp_count) || fail "the inner TCP connection stalled after $event"
    [ "$n2" -gt "$n1" ] || fail "the inner TCP connection stopped after $event ($n1, $n2)"
    check_recovery "$event" "vpna inner UDP (longest gap)" "$(gap vpn-udp.log "$since")" "$VPN_BOUND"
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
