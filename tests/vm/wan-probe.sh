#!/bin/bash
# Probe a node from the WAN (#363), sourced by the suites with ns(), at()
# and fail() set. Nothing the firewall serves inside, or manages itself
# by, may answer from the WAN: DNS, NTP, SSH, HTTPS (the web UI, the API
# and /metrics) and Prometheus. The ruleset drops DNS, DHCP and NTP from
# the WAN ahead of the policies (infra:wan-services), and its counter
# shows the probes reached the node, so a probe that went nowhere can't
# pass for one that was dropped.

# A reply to a client-mode NTP request at address:123, over either family.
WAN_PROBE_NTP='
import socket, sys
a = sys.argv[1]
s = socket.socket(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"\x23" + bytes(47), (a, 123))
try:
    s.recvfrom(100)
except socket.timeout:
    sys.exit(1)
'
# A TCP connection to address:port, over either family.
WAN_PROBE_TCP='
import socket, sys
socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4)
'

wan_probe() { # namespace on the WAN, address...: nothing answers at each
    local n=$1 a rc proto p
    shift
    for a in "$@"; do
        # dig exits 9 when no server answered at all; a REFUSED is an answer.
        for proto in +notcp +tcp; do
            rc=0
            ns "$n" dig "$proto" +time=2 +tries=1 +norecurse "@$a" . SOA >/dev/null 2>&1 || rc=$?
            [ "$rc" = 9 ] || fail "the WAN reached DNS ($proto) at $a (dig exited $rc)"
        done
        if ns "$n" timeout 6 python3 -c "$WAN_PROBE_NTP" "$a" 2>/dev/null; then
            fail "the WAN reached NTP at $a"
        fi
        for p in 22 443 9090; do
            if ns "$n" timeout 6 python3 -c "$WAN_PROBE_TCP" "$a" "$p" 2>/dev/null; then
                fail "the WAN reached TCP $p at $a"
            fi
        done
    done
}

wan_dhcp_probe() { # namespace on the WAN, node address...: no node offers a lease
    local n=$1 s
    shift
    cat > "$WORK/udhcpc-wan.sh" <<SH
#!/bin/sh
[ "\$1" = bound ] && echo "\$serverid" >> "$WORK/wan-offers"
exit 0
SH
    chmod +x "$WORK/udhcpc-wan.sh"
    rm -f "$WORK/wan-offers"
    ns "$n" busybox udhcpc -i eth0 -n -q -t 3 -T 2 -s "$WORK/udhcpc-wan.sh" >/dev/null 2>&1 || true
    [ -f "$WORK/wan-offers" ] || return 0
    for s in "$@"; do
        if grep -qx "$s" "$WORK/wan-offers"; then
            fail "a node at $s gave a DHCP lease on the WAN"
        fi
    done
}

wan_drops() { # node: packets infra:wan-services dropped so far
    at "$1" 'sudo nft list chain inet sparewall input' \
        | awk '/infra:wan-services/ { for (i = 1; i < NF; i++) if ($i == "packets") n += $(i + 1) } END { print n + 0 }'
}
