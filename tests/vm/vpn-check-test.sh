#!/bin/bash
# Checks the VPN recovery assertions without VMs: a recovery that never
# came, or came after the bound, must fail the pair test.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=vpn.sh
. "$HERE/vpn.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }

expect() { # pass|fail seconds bound
    local got=pass
    ( check_recovery test client "$2" "$3" ) >/dev/null 2>&1 || got=fail
    [ "$got" = "$1" ] || { echo "check_recovery $2 (bound $3): $got, expected $1" >&2; exit 1; }
}
expect pass 16.2 60
expect pass 60 60
expect fail 60.1 60
expect fail 75.0 60
expect fail never 60
expect pass 145 180

# gap() counts from the start, between replies and up to now.
now=$(date +%s.%N)
since=$(awk -v n="$now" 'BEGIN { printf "%.6f", n - 30 }')
log=$WORK/ping
awk -v s="$since" 'BEGIN {
    printf "[%.6f] 64 bytes from x\n", s + 5
    printf "[%.6f] 64 bytes from x\n", s + 25
}' > "$log"
g=$(gap "$log" "$since")
awk -v g="$g" 'BEGIN { exit !(g >= 19.9 && g <= 20.1) }' || { echo "gap between replies: $g, expected 20" >&2; exit 1; }
awk -v s="$since" 'BEGIN { printf "[%.6f] 64 bytes from x\n", s + 2 }' > "$log"
g=$(gap "$log" "$since")
awk -v g="$g" 'BEGIN { exit !(g >= 28) }' || { echo "gap after the last reply: $g, expected about 28" >&2; exit 1; }
[ "$(gap /dev/null "$since")" = never ] || { echo "no replies should be never" >&2; exit 1; }
# A fast upgrade: vpnb rekeyed 90 s ago (the master-loss probe) and the
# handover comes at once. vpnb must be aged past 120 s first.
(
    cd "$WORK"
    declare -A HS
    now=$(date +%s)
    HS[vpnb]=$((now - 90)) HS[vpnc]=$((now - 30)) HS[natk]=$now
    SHIFT=0
    # Sleeping ages every session; renewing one makes it new again.
    handshake() { echo $((HS[$1] - SHIFT)); }
    sleep() { SHIFT=$((SHIFT + ${1%.*})); }
    fresh_session() { HS[$1]=$(($(date +%s) + SHIFT)); }
    idle_recovery() { echo 1.0; }
    keepalive_recovery() { echo 1; }
    upgrade() { echo "[stage-peer] staging"; echo "[failover] stopping keepalived"; echo "[reboot] rebooting"; }
    vpn_through_upgrade upgrade >/dev/null
    [ "$(session_age vpnb)" -ge 120 ] || { echo "vpnb not aged before the upgrade" >&2; exit 1; }
    [ -n "${VPN_MOVED_AT:-}" ] || { echo "no probing at the handover" >&2; exit 1; }
) || exit 1
echo "vpn checks ok"
