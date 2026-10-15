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

# The coordinator's SELinux domain and what it was denied, for the job
# summary. The domain is permissive, so nothing was blocked, but a denial
# means image/selinux lacks a rule: it is recorded in
# $WORK/selinux-denials and fails the suite (selinux_gate).
# $1 runs a command on a node.
selinux_report() { # run-command node-name
    local run=$1 node=$2 denials
    $run 'ps -eo label,comm' | grep -q 'sparewalld_t.*sparewalld' \
        || fail "$node: sparewalld does not run in sparewalld_t"
    # Kernel log and journald's audit transport: with auditd running, or
    # kauditd rate-limiting printk, either one alone misses records.
    denials=$($run 'sudo journalctl -b -k --no-pager; sudo journalctl -b --no-pager _TRANSPORT=audit' \
        | grep -oE 'avc: +denied .*scontext=[^ ]*:sparewalld_t:[^ ]*.*' \
        | sed -E 's/ (pid|ino|dev)=[^ ]+//g; s/ permissive=1//' \
        | sort | uniq -c | sort -rn) || true
    echo "$node: $(printf '%s' "$denials" | grep -c . || true) distinct sparewalld_t denials"
    printf '%s\n' "$denials"
    [ -z "$denials" ] || printf '%s\n' "$denials" | sed "s/^/$node: /" >> "$WORK/selinux-denials"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### SELinux: sparewalld_t on $node"
            echo '```'
            printf '%s\n' "${denials:-none}"
            echo '```'
        } >> "$GITHUB_STEP_SUMMARY"
    fi
}

# Fail if any report found a denial.
selinux_gate() {
    [ -s "$WORK/selinux-denials" ] || return 0
    echo "FAIL: sparewalld_t was denied; add rules to image/selinux/sparewalld.te:" >&2
    cat "$WORK/selinux-denials" >&2
    return 1
}
