#!/bin/bash
# The sandboxing score of the image's own units (design: "Coordinator
# sandboxing ... tracked with systemd-analyze security in CI"). A unit
# with a limit fails when its exposure rises above it; lower a limit
# when a unit's sandbox tightens. The others are reported only.
#
#   tests/ci/sandbox-exposure.sh
set -euo pipefail
cd "$(dirname "$0")/../../image/files/usr/lib/systemd/system"

# unit => highest allowed exposure, in tenths (4.5 is 45)
declare -A LIMIT=(
    [sparewalld.service]=45
    [sparewall-ulogd.service]=60
)
# Unsandboxed by design: sparewall-early runs before udev to install the
# live generation and load the firewall; sparewall-run@ runs the commands
# the coordinator's sandbox forbids (podman, bootc).
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
echo "| Unit | Exposure | Limit |" >> "$summary"
echo "| --- | --- | --- |" >> "$summary"
rc=0
for u in *.service; do
    score=$(systemd-analyze security --offline=yes "$u" 2>/dev/null \
        | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')
    [ -n "$score" ] || { echo "$u: no score" >&2; rc=1; continue; }
    tenths=$(echo "$score" | tr -d .)
    limit=${LIMIT[$u]:-}
    echo "| $u | $score | ${limit:+$((limit / 10)).$((limit % 10))} |" >> "$summary"
    if [ -n "$limit" ] && [ "$tenths" -gt "$limit" ]; then
        echo "$u: exposure $score is above its limit $((limit / 10)).$((limit % 10))" >&2
        rc=1
    else
        echo "$u: $score"
    fi
done
exit $rc
