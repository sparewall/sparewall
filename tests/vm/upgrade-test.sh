#!/bin/bash
# Upgrade from a published release to the candidate (#166): nodes
# installed from release FROM's own disk image, set up with that release's
# test document, upgraded by FROM's own `sparewall upgrade` to the
# candidate, then rolled back with `bootc rollback`.
#
#   single  one node: the standalone upgrade.
#   pair    two nodes: the rolling upgrade, through the window where the
#           standby runs the candidate and the master still runs FROM.
#           The gateway addresses move once, and a connection through
#           the pair carries over.
#
# The disk image comes from FROM's GitHub release, checked against its
# signed SHA256SUMS, and the node checks its own image's signature from
# ghcr.io/sparewall under its own policy, with no exception. The
# candidate (IMAGE, the image this run built) is served from a local
# registry with a policy exception, as in pair-test.sh.
#
#   IMAGE=localhost/sparewall:ci FROM=0.3.1 tests/vm/upgrade-test.sh single|pair WORKDIR
#
# Needs gh (with GH_TOKEN) and cosign. .github/upgrade-from.sh picks FROM.
set -euo pipefail
MODE=${1:?usage: upgrade-test.sh single|pair WORKDIR}
WORK=${2:?usage: upgrade-test.sh single|pair WORKDIR}
: "${IMAGE:?set IMAGE to the candidate image}" "${FROM:?set FROM to the release to upgrade from}"
case $MODE in single | pair) ;; *) echo "unknown mode $MODE" >&2; exit 2 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
cd "$WORK"
# shellcheck source=vpn.sh
. "$HERE/vpn.sh"
# shellcheck source=pair-lib.sh
. "$HERE/pair-lib.sh"
# shellcheck source=conformance.sh
. "$HERE/conformance.sh"
pair_taps

NODES=fw1
[ "$MODE" = single ] || NODES="fw1 fw2"
CANDIDATE=$(sudo podman run --rm --entrypoint sparewall "$IMAGE" --version)
CANDIDATE=${CANDIDATE#sparewall }

cleanup() {
    local rc=$?
    [ -z "${GW_WATCH:-}" ] || kill "$GW_WATCH" 2>/dev/null || true
    if [ $rc -ne 0 ]; then
        for f in upgrade.log gateway.log flow.log; do
            [ -f "$f" ] && { echo "--- $f"; tail -40 "$f"; }
        done
        if [ "$MODE" = pair ]; then dump_nodes; else
            at fw1 'sudo journalctl -b -u sparewalld --no-pager | tail -60; timeout 20 sudo sparewall status' \
                || sudo tail -60 fw1.serial || true
        fi
    fi
    sudo pkill -f "$HERE/echo.py" 2>/dev/null || true
    sudo podman rm -f sw-registry >/dev/null 2>&1 || true
    stop_pair
}
trap cleanup EXIT

version_is() { [ "$(at "$1" 'sparewall --version' </dev/null)" = "sparewall $2" ]; }
healthy() { [ "$(level "$1")" = ok ]; }
# A release before 0.3.0 reports its own SELinux denials (#159) until they
# are acknowledged: that, and only that, is acknowledged.
settle_health() { # node
    local bad
    bad=$(status "$1" | jq -r '[.health.checks[] | select(.level != "ok") | .name] | join(" ")')
    [ "$bad" != selinux ] || at "$1" 'sudo sparewall health ack selinux' >/dev/null
}

log "release $FROM's disk image, from its GitHub release"
mkdir -p release output/qcow2
q=sparewall-$FROM-x86_64.qcow2
gh release download "v$FROM" -R sparewall/sparewall -D release --clobber \
    -p "$q" -p "$q.part*" -p SHA256SUMS -p SHA256SUMS.sigstore.json
git -C "$REPO" show "v$FROM:cosign.pub" > release/cosign.pub
cosign verify-blob --key release/cosign.pub --bundle release/SHA256SUMS.sigstore.json release/SHA256SUMS \
    || fail "release $FROM's SHA256SUMS is not signed with its key"
[ -f "release/$q" ] || cat "release/$q".part[0-9][0-9] > "release/$q"
(cd release && grep "  $q\$" SHA256SUMS | sha256sum -c -) || fail "$q does not match SHA256SUMS"
mv "release/$q" output/qcow2/disk.qcow2

log "booting $NODES on $FROM"
boot "${FW1[@]}"
[ "$MODE" = single ] || boot "${FW2[@]}"
for n in $NODES; do
    wait_for 900 "$n SSH" at "$n" true
    version_is "$n" "$FROM" || fail "$n runs $(at "$n" 'sparewall --version'), not $FROM"
done
FROM_READS=$(at fw1 'sparewall schema show' | jq -r '."$id"' | sed -n 's|.*/v\([0-9]*\)\.json$|\1|p')

log "each node checks its image's signature under its own policy"
# bootc opens the image through the node's policy (sigstoreSigned for
# ghcr.io/sparewall): a rejected signature fails the check.
for n in $NODES; do
    ref=$(at "$n" 'sudo bootc status --format=json' | jq -r .status.booted.image.image.image)
    case $ref in ghcr.io/sparewall/sparewall:*) ;; *) fail "$n tracks $ref, not a published image" ;; esac
    at "$n" 'sudo bootc upgrade --check' > "$n-check.log" 2>&1 \
        || fail "$n cannot verify $ref: $(cat "$n-check.log")"
done

if [ "$MODE" = single ]; then
    log "the $FROM single-node document"
    git -C "$REPO" show "v$FROM:tests/vm/site.yaml" | at fw1 'cat > /tmp/site.yaml'
    # The port is renamed (mgmt0 -> uplink), which may cut this session.
    at fw1 'sudo sparewall apply -f /tmp/site.yaml --confirm 180 --no-prompt' || true
    sleep 5
    wait_for 120 "fw1 SSH after the first apply" at fw1 true
    at fw1 'sudo sparewall confirm'
    CHANGE=updates.channel
else
    log "pairing with the $FROM pair document"
    vpn_keys
    git -C "$REPO" show "v$FROM:tests/vm/site-pair.yaml" | pair_doc | vpn_doc > pair.yaml
    pair_up
    CHANGE=dhcp.users.lease_time
fi
for n in $NODES; do settle_health "$n"; wait_for 300 "$n healthy on $FROM" healthy "$n"; done

log "state to carry over: generations, secrets, tokens, users, the admin password"
if [ "$MODE" = single ]; then V=testing; else V=3600; fi
at fw1 "sudo sparewall set $CHANGE=$V --confirm 0"
printf 'from %s\n' "$FROM" | at fw1 'sudo sparewall passwd'
printf %s s3cret | at fw1 'sudo sparewall secret set ci-upgrade'
TOKEN=$(at fw1 'sudo sparewall token create ci-upgrade --role viewer -q')
USERS=
if at fw1 'sudo sparewall user --help' >/dev/null 2>&1; then
    USERS=1
    printf %s 'ci user pw' | at fw1 'sudo sparewall user add ci-upgrade --role operator' >/dev/null
fi
GEN=$(status fw1 | jq .sync.active)
if [ "$MODE" = pair ]; then
    for n in $NODES; do wait_for 120 "$n settled on generation $GEN" settled "$n" "$GEN"; done
    fw2_password() { [ "$(shadow_hash fw2)" = "$(shadow_hash fw1)" ]; }
    wait_for 60 "fw2 has fw1's admin password" fw2_password
fi
declare -A HISTORY HASH SYNCKEY
for n in $NODES; do
    HISTORY[$n]=$(at "$n" 'sudo sparewall history -o json' | jq -c '[.[].id] | sort')
    HASH[$n]=$(shadow_hash "$n")
    SYNCKEY[$n]=$(status "$n" | jq -r .sync.sync_public_key)
done
takes_password "${HASH[fw1]}" "from $FROM" || fail "fw1's admin password is not set"

carried_over() { # node
    local n=$1 ids
    ids=$(at "$n" 'sudo sparewall history -o json' | jq -c '[.[].id] | sort')
    jq -e -n --argjson a "${HISTORY[$n]}" --argjson b "$ids" '$a - $b == []' >/dev/null \
        || fail "$n lost generations: had ${HISTORY[$n]}, has $ids"
    [ "$(shadow_hash "$n")" = "${HASH[$n]}" ] || fail "$n's admin password changed"
    [ "$(status "$n" | jq -r .sync.sync_public_key)" = "${SYNCKEY[$n]}" ] || fail "$n's sync key changed"
    at "$n" 'sudo sparewall secret list' | grep -qw ci-upgrade || fail "$n lost the secret ci-upgrade"
    [ "$MODE" = single ] || at "$n" 'sudo sparewall secret list' | grep -qw psk-vpna \
        || fail "$n lost the cluster secret psk-vpna"
    [ -z "$USERS" ] || at "$n" 'sudo sparewall user list' | grep -qw ci-upgrade \
        || fail "$n lost the user ci-upgrade"
}

if [ "$MODE" = pair ]; then
    log "a connection through the pair, and the gateway's MAC as the users network sees it"
    ns users ip addr flush dev eth0
    ns users ip addr add 192.0.2.250/24 dev eth0
    ns users ip route replace default via 192.0.2.1
    ns guests ip addr flush dev eth0
    ns guests ip addr add 198.51.100.10/24 dev eth0
    ns guests ip route replace default via 198.51.100.1
    ns guests python3 "$HERE/echo.py" server &
    sleep 1
    ns users python3 "$HERE/echo.py" client 198.51.100.10 > flow.log 2>&1 &
    echoes() { tail -1 flow.log | grep -qE '^[0-9]+$' && tail -1 flow.log; }
    sleep 3
    before=$(echoes) || fail "no echoes through the pair: $(cat flow.log)"
    # Each change of the MAC behind 192.0.2.1 is a move of the gateway.
    (
        last=
        while :; do
            m=$(ns users ip -j neigh show 192.0.2.1 dev eth0 2>/dev/null | jq -r '.[0].lladdr // empty' 2>/dev/null) || m=
            if [ -n "$m" ] && [ "$m" != "$last" ]; then echo "$(date +%T) $m" >> gateway.log; last=$m; fi
            sleep 0.5
        done
    ) &
    GW_WATCH=$!
    wait_for 30 "the gateway's MAC" test -s gateway.log
    [ "$(awk '{print $2}' gateway.log)" = "${FW1[3]}" ] || fail "the gateway is not fw1's: $(cat gateway.log)"
fi

log "the candidate ($CANDIDATE) and its provider images in a local registry"
# QEMU user networking reaches the host at 10.0.2.2.
sudo podman run -d --name sw-registry -p 5000:5000 quay.io/libpod/registry:2.8.2 >/dev/null
wait_for 30 "the registry" curl -sf http://127.0.0.1:5000/v2/
sudo podman push --tls-verify=false "$IMAGE" docker://127.0.0.1:5000/sparewall:candidate
NEXT=10.0.2.2:5000/sparewall:candidate
# Staging pulls the candidate's bound provider images
# (ghcr.io/sparewall/kea:sha-…), which a pull request builds but never
# pushes, and a pair reaches nothing outside through its test WAN: the
# nodes get them from the same registry, as a mirror of ghcr.io/sparewall.
PROVIDERS=$(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
    'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done')
[ -n "$PROVIDERS" ] || fail "the candidate names no bound images"
for ref in $PROVIDERS; do
    case $ref in ghcr.io/sparewall/*) ;; *) fail "a bound image outside ghcr.io/sparewall: $ref" ;; esac
    sudo podman image exists "$ref" || sudo podman pull "$ref"
    sudo podman push --tls-verify=false "$ref" "docker://127.0.0.1:5000/${ref#ghcr.io/}"
done
# The provider repositories accept anything once the release's own
# signature has been checked above; ghcr.io/sparewall/sparewall does not.
repos=$(for ref in $PROVIDERS; do echo "${ref%:*}"; done | sort -u | jq -R . | jq -cs .)
for n in $NODES; do
    at "$n" 'sudo tee /etc/containers/registries.conf.d/50-test.conf >/dev/null' <<'TOML'
[[registry]]
location = "10.0.2.2:5000"
insecure = true

[[registry]]
location = "ghcr.io/sparewall"
[[registry.mirror]]
location = "10.0.2.2:5000/sparewall"
insecure = true
pull-from-mirror = "all"
TOML
    at "$n" "sudo jq --argjson repos '$repos' '.transports.docker[\"10.0.2.2:5000\"] = [{\"type\": \"insecureAcceptAnything\"}]
        | reduce \$repos[] as \$r (.; .transports.docker[\$r] = [{\"type\": \"insecureAcceptAnything\"}])' \
        /etc/containers/policy.json > /tmp/policy.json && sudo install -m 0644 /tmp/policy.json /etc/containers/policy.json"
    at "$n" 'sudo jq -c ".transports.docker | keys" /etc/containers/policy.json'
done

log "$FROM's sparewall upgrade, to $CANDIDATE"
# The command follows the upgrade until its own node reboots, which may
# cut the session: the outcome is checked on the nodes.
AT_TIMEOUT=1800 at fw1 "sudo sparewall upgrade --image $NEXT" > upgrade.log 2>&1 \
    || echo "(the upgrade command ended with $?)" >> upgrade.log
cat upgrade.log
for n in $NODES; do
    wait_for 900 "$n on $CANDIDATE" version_is "$n" "$CANDIDATE"
done
if [ "$MODE" = pair ]; then
    wait_for 300 "fw1 in sync" in_sync fw1
    wait_for 120 "fw2 in sync" in_sync fw2
    # A node just back may sit in FAULT until its health script passes.
    wait_for 120 "fw1 BACKUP after the upgrade" is_backup fw1
    roles_are BACKUP MASTER "after the upgrade"
fi
for n in $NODES; do
    wait_for 300 "$n healthy on $CANDIDATE" healthy "$n"
    at "$n" 'sudo bootc status --format=json' | jq -e --arg i "$NEXT" '.status.booted.image.image.image == $i' >/dev/null \
        || fail "$n does not run $NEXT"
    carried_over "$n"
done
# Each node has a machine ID of its own, whatever the release it came from
# shipped (0.3.2's media gave every install the same one, #196).
if [ "$MODE" = pair ]; then
    [ "$(at fw1 'cat /etc/machine-id')" != "$(at fw2 'cat /etc/machine-id')" ] \
        || fail "fw1 and fw2 share a machine ID after the upgrade"
fi
at fw1 "SPAREWALL_TOKEN=$TOKEN sparewall status" >/dev/null \
    || fail "the token made on $FROM is refused"

if [ "$MODE" = pair ]; then
    log "the gateway moved once, and the connection carried over"
    cat gateway.log
    [ "$(wc -l < gateway.log)" = 2 ] && [ "$(awk 'NR == 2 {print $2}' gateway.log)" = "${FW2[3]}" ] \
        || fail "the gateway did not move once, from fw1 to fw2"
    grep -q broken flow.log && fail "the connection broke in the upgrade: $(tail -5 flow.log)"
    sleep 3
    after=$(echoes) || fail "the connection stalled in the upgrade: $(tail -5 flow.log)"
    [ "$after" -gt "$before" ] || fail "the connection stalled in the upgrade ($before, $after)"
fi

log "each node notices a newer image on its channel (#188)"
# A label-only image on another tag, which says it is a newer version.
printf 'FROM %s\nLABEL org.sparewall.version=99.0.0\n' "$IMAGE" \
    | sudo podman build -q -t localhost/sparewall:newer -f - "$(mktemp -d)" >/dev/null
sudo podman push -q --tls-verify=false localhost/sparewall:newer docker://127.0.0.1:5000/sparewall:newer
# Changing the channel makes each node check within a minute or two,
# instead of hours. In a pair, the change reaches both nodes.
M=fw1
[ "$MODE" = single ] || M=fw2
at "$M" 'sudo sparewall set updates.channel=newer --confirm 0'
sees_newer() { status "$1" | jq -e '.update.available == "newer" and .update.version == "99.0.0"' >/dev/null; }
for n in $NODES; do
    wait_for 240 "$n sees 99.0.0" sees_newer "$n"
    at "$n" "sudo journalctl -b -u sparewalld MESSAGE_ID=c8f95979678447529aa9b5914a38a3a0 -o cat --no-pager" \
        | grep -qx "99.0.0 is available on 10.0.2.2:5000/sparewall:newer (running $CANDIDATE)" \
        || fail "$n did not log the update with its MESSAGE_ID"
    healthy "$n" || fail "$n is not healthy with an update available: $(status "$n" | jq -c .health)"
done
[ "$MODE" = single ] || roles_are BACKUP MASTER "with an update available"

log "a change on $CANDIDATE, confirmed"
if [ "$MODE" = single ]; then V=stable; else V=1800; fi
at "$M" "sudo sparewall set $CHANGE=$V --confirm 120 --no-prompt"
at "$M" 'sudo sparewall confirm'
GEN=$(status "$M" | jq .sync.active)
[ "$(status "$M" | jq .sync.confirmed)" = "$GEN" ] || fail "generation $GEN is not confirmed on $M"
for n in $NODES; do
    [ "$MODE" = single ] || wait_for 120 "$n settled on generation $GEN" settled "$n" "$GEN"
    [ "$(at "$n" "sudo sparewall get $CHANGE")" = "$V" ] || fail "$n does not run the change"
done

# The newest schema revision each side reads (#168), from the $id of its
# JSON Schema (https://sparewall.org/schema/vN.json).
reads() { at "$1" 'sparewall schema show' | jq -r '."$id"' | sed -n 's|.*/v\([0-9]*\)\.json$|\1|p'; }
CAND_READS=$(reads fw1)
NEWER=
# A field only the candidate reads: a document that uses it needs
# revision 3 (updates.check, #188), which an older release cannot read.
[ "${FROM_READS:-0}" -lt 3 ] && [ "${CAND_READS:-0}" -ge 3 ] && NEWER=updates.check=false

if [ "$MODE" = single ] && [ -n "$NEWER" ]; then
    log "a change that needs schema revision 3, which $FROM cannot read (#13)"
    at fw1 "sudo sparewall set $NEWER --confirm 0"
    GEN3=$(status fw1 | jq .sync.active)
    [ "$GEN3" -gt "$GEN" ] || fail "the revision 3 change made no generation"
    at fw1 'sudo sparewall history -o json' | jq -e --argjson g "$GEN3" '.generations[] | select(.id == $g) | .schema == 3' >/dev/null \
        || fail "generation $GEN3 is not recorded as schema revision 3"
fi

# The node rolled back: the only node, or the pair's standby (fw1), which
# then runs $FROM beside a master on the candidate.
log "bootc rollback on fw1, back to $FROM"
at fw1 'sudo bootc rollback' || fail "bootc rollback failed"
at fw1 'sudo systemctl reboot' || true
sleep 10
wait_for 900 "fw1 back on $FROM" version_is fw1 "$FROM"
if [ "$MODE" = single ] && [ -n "$NEWER" ]; then
    log "$FROM cannot read generation $GEN3: it runs generation $GEN and says so"
    gen_check() { status fw1 | jq -r '.health.checks[] | select(.name == "generation") | .level + " " + .message'; }
    unreadable() { gen_check | grep -q "^failed generation $GEN3 cannot be read.*revision 3.*running generation $GEN"; }
    wait_for 300 "fw1 to report generation $GEN3 unreadable" unreadable
    [ "$(at fw1 "sudo sparewall get $CHANGE")" = "$V" ] || fail "fw1 does not run generation $GEN in place of $GEN3"
    log "rolling the configuration back to generation $GEN, which $FROM reads"
    at fw1 "sudo sparewall rollback $GEN" || fail "rollback to generation $GEN failed: $(gen_check)"
    at fw1 'sudo sparewall confirm' >/dev/null 2>&1 || true
fi
settle_health fw1
wait_for 300 "fw1 healthy on $FROM" healthy fw1
[ "$(at fw1 "sudo sparewall get $CHANGE")" = "$V" ] || fail "fw1 lost the configuration in the rollback"
carried_over fw1
if [ "$MODE" = pair ]; then
    wait_for 300 "fw1 in sync on $FROM" in_sync fw1
    wait_for 120 "fw2 in sync with fw1 on $FROM" in_sync fw2
    wait_for 120 "fw1 BACKUP after its rollback" is_backup fw1
    roles_are BACKUP MASTER "after fw1's rollback"
    [ "$(wc -l < gateway.log)" = 2 ] || fail "the gateway moved in fw1's rollback: $(cat gateway.log)"
    grep -q broken flow.log && fail "the connection broke in the rollback: $(tail -5 flow.log)"
fi
if [ "$MODE" = pair ] && [ -n "$NEWER" ]; then
    log "mixed versions: fw2 refuses a change that $FROM on fw1 cannot read (#13)"
    before=$(status fw2 | jq .sync.active)
    out=$(at fw2 "sudo sparewall set $NEWER --confirm 0" 2>&1) && fail "fw2 took a revision 3 change beside $FROM: $out"
    grep -q "upgrade fw1 first" <<<"$out" || fail "fw2 refused the change, but not for the peer's schema: $out"
    [ "$(status fw2 | jq .sync.active)" = "$before" ] || fail "the refused change made a generation on fw2"
    [ "$(status fw1 | jq .sync.active)" = "$before" ] || fail "the refused change reached fw1"
fi
log "upgrade $MODE PASS ($FROM -> $CANDIDATE, and back)"
