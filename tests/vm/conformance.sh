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
    # scripts, conntrackd), or bootupd (#111) denied anything, or any
    # domain denied the coordinator's own files (a consumer of
    # /run/sparewall, say). Not the checks of a domain transition's
    # environment scrubbing, which the policy hides (dontaudit, off
    # here): they are denied by design.
    denials=$($run 'sudo journalctl -b -k --no-pager; sudo journalctl -b --no-pager _TRANSPORT=audit' \
        | grep -oE 'avc: +denied .*' \
        | grep -E 'scontext=[^ ]*:(sparewalld|keepalived|keepalived_unconfined_script|conntrackd|bootupd)_t:|tcontext=[^ ]*:sparewalld_[a-z_]*:' \
        | grep -vE 'denied +\{ (noatsecure|siginh|rlimitinh) \}' \
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
    # mac_admin, a chcon to an undefined label, is denied (#110).
    # (Counted, not grep -q, which would cut the pipe short.)
    local probes unlabelled
    probes=$($run 'sudo journalctl -b -k --no-pager; sudo journalctl -b --no-pager _TRANSPORT=audit' \
        | grep -c 'invalid_bootcinstall_testlabel_t' || true)
    [ "$probes" = 0 ] \
        || echo "$node: bootc ran outside install_t (its mac_admin probe was denied)" | tee -a "$WORK/selinux-denials"
    # Files in /boot as the policy labels them (sparewall-label-boot, #111).
    unlabelled=$($run 'sudo restorecon -Rnvx /boot' | grep -c 'Would relabel' || true)
    [ "$unlabelled" = 0 ] \
        || echo "$node: $unlabelled files in /boot are mislabelled" | tee -a "$WORK/selinux-denials"
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
