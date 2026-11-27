#!/bin/sh
# Probe a ruleset from the WAN side (#363), in an unprivileged user and
# network namespace:
#
#   unshare -rn sh wan-probe.sh RULESET WAN_IFACE "4/udp:53 6/tcp:53 ..."
#
# The node's namespace holds the WAN interface, one end of a veth pair
# whose other end is in a second namespace, the outside host. With the
# ruleset loaded, a listener on each probed port reports whether the
# outside host's packet or connection reached it: one line per probe,
# "4/udp:53 open" or "4/udp:53 closed".
set -eu
ruleset=$1 wan=$2 probes=$3

ip link set lo up
unshare -n sleep 60 &
outside=$!
trap 'kill "$outside" 2>/dev/null || true' EXIT
# The outside namespace exists once unshare has run sleep.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(readlink "/proc/$outside/ns/net")" != "$(readlink /proc/self/ns/net)" ] && break
    sleep 0.1
done
out() { nsenter -t "$outside" -n "$@"; }

ip link add "$wan" type veth peer name outside
ip link set outside netns "$outside"
ip addr add 198.51.100.1/24 dev "$wan"
ip addr add 2001:db8:ff::1/64 dev "$wan" nodad
ip link set "$wan" up
out ip link set lo up
out ip addr add 198.51.100.2/24 dev outside
out ip addr add 2001:db8:ff::2/64 dev outside nodad
out ip link set outside up

nft -f "$ruleset"

listen='
import socket, sys
fam, proto, port, label = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
af = socket.AF_INET if fam == "4" else socket.AF_INET6
s = socket.socket(af, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if fam == "6":
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("0.0.0.0" if fam == "4" else "::", port))
s.settimeout(3)
try:
    if proto == "udp":
        s.recvfrom(100)
    else:
        s.listen(1)
        s.accept()
    print(label, "open", flush=True)
except socket.timeout:
    print(label, "closed", flush=True)
'
send='
import socket, sys
fam, proto, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
af = socket.AF_INET if fam == "4" else socket.AF_INET6
to = ("198.51.100.1" if fam == "4" else "2001:db8:ff::1", port)
if proto == "udp":
    socket.socket(af, socket.SOCK_DGRAM).sendto(b"probe", to)
else:
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(to)
    except OSError:
        pass
'

pids=
for p in $probes; do
    fam=${p%%/*} rest=${p#*/}
    proto=${rest%%:*} port=${rest#*:}
    python3 -I -c "$listen" "$fam" "$proto" "$port" "$p" &
    pids="$pids $!"
done
sleep 0.5
for p in $probes; do
    fam=${p%%/*} rest=${p#*/}
    proto=${rest%%:*} port=${rest#*:}
    out python3 -I -c "$send" "$fam" "$proto" "$port"
done
# shellcheck disable=SC2086
wait $pids
