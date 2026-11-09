#!/bin/bash
# The ISP's IPv6 (#213), sourced by the suites with $WORK set: radvd and
# Kea's DHCPv6 server in a namespace on the WAN. The advertisements set
# the M and O flags and carry no prefix, so a WAN's address comes from
# DHCPv6 only; Kea gives it one from 2001:db8:ffff::/64 and delegates
# /56s out of a /48. Kea's files are where Ubuntu's AppArmor profile for
# it allows.
KEA6_CONF=/etc/kea/sparewall-test-dhcp6.conf
KEA6_LEASES=/var/lib/kea/sparewall-test-leases6.csv
KEA6_LOG=/var/log/kea/sparewall-test-dhcp6.log

isp6_start() { # namespace (its eth0 the WAN side)
    ns "$1" sysctl -qw net.ipv6.conf.all.forwarding=1
    ns "$1" ip -6 addr add 2001:db8:ffff::1/64 dev eth0 nodad
    cat > "$WORK/radvd.conf" <<'EOF'
interface eth0 {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
};
EOF
    ns "$1" radvd -n -u root -C "$WORK/radvd.conf" -p "$WORK/radvd.pid" -m stderr > "$WORK/radvd.log" 2>&1 &
    # Ubuntu's AppArmor profile for kea-dhcp6 withholds dac_override, so
    # root may not write into /run/kea (the _kea user's) and the like;
    # this runner's Kea is a test fixture, not a service.
    local f
    for f in /etc/apparmor.d/*kea-dhcp6*; do
        [ -f "$f" ] && sudo apparmor_parser -R "$f" 2>/dev/null || true
    done
}

kea6_start() { # namespace, the /48 to delegate /56s from (2001:db8:N::)
    sudo tee "$KEA6_CONF" > /dev/null <<EOF
{"Dhcp6": {
  "interfaces-config": {"interfaces": ["eth0"]},
  "lease-database": {"type": "memfile", "persist": true, "name": "$KEA6_LEASES"},
  "renew-timer": 30, "rebind-timer": 45, "preferred-lifetime": 90, "valid-lifetime": 180,
  "subnet6": [{"id": 1, "subnet": "2001:db8:ffff::/64", "interface": "eth0",
    "pools": [{"pool": "2001:db8:ffff::100-2001:db8:ffff::1ff"}],
    "pd-pools": [{"prefix": "$2", "prefix-len": 48, "delegated-len": 56}]}],
  "option-data": [{"name": "dns-servers", "data": "2001:db8:ffff::1"}],
  "loggers": [{"name": "kea-dhcp6", "severity": "INFO",
    "output_options": [{"output": "$KEA6_LOG"}]}]
}}
EOF
    sudo rm -f "$KEA6_LEASES"*
    ns "$1" env KEA_PIDFILE_DIR=/run/kea KEA_LOCKFILE_DIR=/run/kea \
        kea-dhcp6 -c "$KEA6_CONF" > "$WORK/kea6.out" 2>&1 &
}

kea6_stop() {
    sudo pkill -f "kea-dhcp6 -c $KEA6_CONF" 2>/dev/null || true
    for _ in $(seq 1 10); do pgrep -f "kea-dhcp6 -c $KEA6_CONF" >/dev/null || return 0; sleep 1; done
}

isp6_stop() {
    [ -f "$WORK/radvd.pid" ] && sudo kill "$(sudo cat "$WORK/radvd.pid")" 2>/dev/null || true
    kea6_stop
}

# A withdrawn delegated prefix (#232): whether a client hears it announced
# with a preferred lifetime of 0, and whether its address there is
# deprecated.
deprecated_in_ra() { # namespace, prefix (2001:db8:...:1::)
    ns "$1" rdisc6 -1 eth0 2>/dev/null | awk -v p="Prefix *: *${2}/64" '
        $0 ~ p { inside = 1; next }
        inside && /Prefix/ { inside = 0 }
        inside && /Pref\. time/ { found = ($4 == 0); exit }
        END { exit !found }'
}
old_deprecated() { # namespace, prefix (2001:db8:...:1::)
    ns "$1" ip -6 addr show dev eth0 scope global | grep "inet6 ${2%::}:" | grep -q deprecated
}

# The ISP's side, for a failure's log.
isp6_dump() { # namespace
    echo "--- radvd"; tail -n 5 "$WORK/radvd.log"
    echo "--- $1"; ns "$1" ip -6 addr show dev eth0; ns "$1" ip -6 route; ns "$1" ip -6 neigh
    local f
    for f in "$WORK/kea6.out" "$KEA6_LOG" "$KEA6_LEASES"; do echo "--- $f"; sudo tail -n 30 "$f"; done
} 2>&1
