#!/bin/bash
# Two firewall VMs on a shared VLAN trunk, sourced by pair-test.sh and
# pair-faults.sh with $WORK (the current directory) and $HERE set.
#
# Each node has a management NIC on QEMU user networking (SSH forwarded
# from 127.0.0.1), a trunk tap on swbr carrying the service VLANs (WAN 10,
# users 20, servers 30), and a dedicated sync tap carrying VLAN 4000. A
# node may have a second trunk tap (a bond member). Each VM has a QEMU
# monitor socket, $name.mon.

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ns() { local n=$1; shift; sudo ip netns exec "sw-$n" "$@"; }

#        name ssh  management         trunk              tap    sync               sync tap
FW1=(fw1 2231 52:54:00:12:34:56 52:54:00:12:34:57 swtap1 52:54:00:12:34:58 swtap1s)
FW2=(fw2 2232 52:54:00:12:35:56 52:54:00:12:35:57 swtap2 52:54:00:12:35:58 swtap2s)
# A second trunk NIC for fw1, used when its trunk is a bond.
FW1_BOND_MAC=52:54:00:12:34:59
FW1_BOND_TAP=swtap1b

# The bridge and the users and guests clients (from boot-test.sh, or
# fresh), and the taps.
pair_taps() {
    if ! ip link show swbr >/dev/null 2>&1; then
        . "$HERE/conformance.sh"
        setup_trunk
    fi
    local t v
    for t in swtap1 swtap2 swtap1s swtap2s "$FW1_BOND_TAP"; do
        sudo ip tuntap add "$t" mode tap
        sudo ip link set "$t" master swbr up
        sudo bridge vlan del dev "$t" vid 1
        case $t in
        *s) sudo bridge vlan add dev "$t" vid 4000 ;;
        *) for v in 10 20 30; do sudo bridge vlan add dev "$t" vid $v; done ;;
        esac
    done
    [ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f id_ed25519
}

boot() { # name ssh-port mgmt-mac trunk-mac tap sync-mac sync-tap (a fresh disk)
    cp output/qcow2/disk.qcow2 "$1.qcow2"
    cat > "$1.json" <<JSON
{"node": "$1", "ssh_keys": ["$(cat id_ed25519.pub)"], "management": {"nic": "$3"}}
JSON
    start "$@"
}

# Start a node from the disk as it is. With BOND set for fw1, the VM also
# gets the second trunk NIC.
start() { # name ssh-port mgmt-mac trunk-mac tap sync-mac sync-tap
    local name=$1 port=$2 mac=$3 tmac=$4 tap=$5 smac=$6 stap=$7 extra=()
    if [ "$name" = fw1 ] && [ -n "${BOND:-}" ]; then
        extra=(-netdev "tap,id=n3,ifname=$FW1_BOND_TAP,script=no,downscript=no"
            -device "virtio-net-pci,netdev=n3,mac=$FW1_BOND_MAC")
    fi
    sudo qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 1536 -smp 2 \
        -drive "file=$name.qcow2,if=virtio,format=qcow2" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${port}-:22" \
        -device "virtio-net-pci,netdev=n0,mac=$mac" \
        -netdev "tap,id=n1,ifname=$tap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n1,mac=$tmac" \
        -netdev "tap,id=n2,ifname=$stap,script=no,downscript=no" \
        -device "virtio-net-pci,netdev=n2,mac=$smac" \
        "${extra[@]}" \
        -smbios "type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 "$name.json")" \
        -monitor "unix:$WORK/$name.mon,server=on,wait=off" \
        -display none -serial "file:$name.serial" -pidfile "$name.pid" -daemonize
}

# A QEMU monitor command, e.g. `monitor fw1 set_link n1 off`.
monitor() { # node command...
    local n=$1; shift
    echo "$*" | sudo socat - "UNIX-CONNECT:$WORK/$n.mon" >/dev/null
}

stop_vm() { # node
    [ -f "$1.pid" ] || return 0
    sudo kill "$(sudo cat "$1.pid")" 2>/dev/null || true
    rm -f "$1.pid"
    sleep 2
}

at() { # node command...
    local port; case $1 in fw1) port=2231 ;; fw2) port=2232 ;; esac; shift
    # QEMU accepts the forwarded connection before the guest is up, so
    # ConnectTimeout alone does not bound a call: a hung one is retried.
    timeout "${AT_TIMEOUT:-90}" ssh -p "$port" -i "$WORK/id_ed25519" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        admin@127.0.0.1 "$@"
}

wait_for() { # seconds description command...
    local deadline=$((SECONDS + $1)) what=$2; shift 2
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || fail "timed out: $what"
        sleep 5
    done
}

status() { at "$1" 'sudo sparewall status -o json'; }
in_sync() { status "$1" | jq -e '.sync.state == "in-sync"'; }
role() { status "$1" | jq -r .role; }
is_master() { [ "$(role "$1")" = MASTER ]; }
is_backup() { [ "$(role "$1")" = BACKUP ]; }
# The address a node reaches the outside (sw-isp's 198.18.0.1, answering
# with the source of each connection) as.
egress() { at "$1" 'timeout 5 bash -c "exec 3<>/dev/tcp/198.18.0.1/7002; head -1 <&3"'; }
state() { status "$1" | jq -r .sync.state; }
unreachable() { [ "$(state "$1")" = peer-unreachable ]; }
level() { status "$1" | jq -r .health.level; }
settled() { # node generation
    status "$1" | jq -e --argjson g "$2" \
        '.sync.state == "in-sync" and .sync.active == $g and .sync.pending == null' >/dev/null
}
roles_are() { # fw1-role fw2-role description
    [ "$(role fw1)" = "$1" ] && [ "$(role fw2)" = "$2" ] \
        || fail "$3: fw1 is $(role fw1), fw2 is $(role fw2)"
}

# The admin account's password field in shadow, and whether it takes a
# password (checked with crypt(3) here, as PAM checks it there).
shadow_hash() { at "$1" 'sudo getent shadow admin' </dev/null | cut -d: -f2; }
takes_password() { # hash password
    H="$1" P="$2" perl -e 'exit(crypt($ENV{P}, $ENV{H}) eq $ENV{H} ? 0 : 1)'
}

# The pair document on stdin, with both nodes' sync keys filled in.
pair_doc() {
    local k1 k2
    # ssh would read the document from stdin.
    k1=$(status fw1 </dev/null | jq -r .sync.sync_public_key)
    k2=$(status fw2 </dev/null | jq -r .sync.sync_public_key)
    sed -e "s|@FW1_KEY@|$k1|" -e "s|@FW2_KEY@|$k2|"
}

# Apply the document in pair.yaml on both nodes and wait for the pair:
# in sync, fw1 the master.
pair_up() {
    local n
    for n in fw1 fw2; do
        ! declare -F full_audit >/dev/null || full_audit "at $n" "$n"
        at "$n" 'cat > /tmp/pair.yaml' < pair.yaml
        at "$n" 'sudo sparewall apply -f /tmp/pair.yaml --confirm 0' || fail "pairing apply failed on $n"
    done
    wait_for 300 "fw1 in sync" in_sync fw1
    wait_for 120 "fw2 in sync" in_sync fw2
    wait_for 120 "fw1 master" is_master fw1
    [ "$(role fw2)" = BACKUP ] || fail "fw2 is $(role fw2), not BACKUP"
}

# On failure, what each node was doing. Callers add their own logs first.
dump_nodes() {
    local n
    for n in fw1 fw2; do
        echo "--- $n"
        at "$n" 'sudo journalctl -b -u sparewalld --no-pager | tail -40
            timeout 20 sudo sparewall status
            sudo wg show swsync 2>&1; ip -br addr
            sudo conntrackd -C /run/sparewall/conntrackd/conntrackd.conf -s 2>&1 | head -30
            sudo journalctl -b -u sparewalld --no-pager | grep -iE "vrrp|conntrackd" | tail -15
            for u in keepalived conntrackd sparewall-kea; do echo "-- $u"; sudo journalctl -b -u $u --no-pager | tail -15; done
            echo "-- systemd and D-Bus"; sudo journalctl -b _PID=1 + _SYSTEMD_UNIT=dbus-broker.service --no-pager | grep -vE "sparewall-run@" | tail -30
            echo "-- helper jobs"; sudo journalctl -b -u "sparewall-run@*" --no-pager | tail -20
            echo "-- networkd"; sudo journalctl -b -u systemd-networkd --no-pager | grep -iE "swsync|wireguard|key|bond" | tail -15
            echo "-- AVC"; sudo journalctl -b -k --no-pager | grep -oE "avc: +denied.*" | sed -E "s/pid=[0-9]+ //; s/ino=[0-9]+ //" | sort | uniq -c | tail -25
            ls -laZ /run/keepalived/' 2>/dev/null \
            || sudo tail -60 "$n.serial" || true
    done
}

# Each running node's sparewalld_t report (conformance.sh), whatever the
# outcome; a node that is down or not in the domain is only noted. The
# suites' cleanup fails a passing run that found denials (selinux_gate).
selinux_reports() {
    declare -F selinux_report >/dev/null || return 0
    local n
    for n in fw1 fw2; do
        [ -f "$n.pid" ] || continue
        (selinux_report "at $n" "$n") || echo "$n: no SELinux report"
    done
}

stop_pair() {
    stop_vm fw1
    stop_vm fw2
}
