#!/bin/bash
# The releases a candidate must upgrade from (tests/vm/upgrade-test.sh,
# docs/operations.md "Upgrades"): the newest release before it, and the
# newest release of the minor series before the candidate's, when that is
# another one. A release here is a published, non-prerelease vX.Y.Z tag,
# read one per line from stdin:
#
#   gh release list --exclude-drafts --exclude-pre-releases \
#       --json tagName --jq '.[].tagName' | .github/upgrade-from.sh VERSION
#
# VERSION is the candidate's (.github/version.sh): only its X.Y.Z counts,
# so 0.3.2, 0.3.2-dev.4+g… and 0.4.0-rc1 each look below themselves.
set -euo pipefail
v=${1:?usage: upgrade-from.sh VERSION < release tags}
core=${v%%[-+]*}
[[ $core =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a version: $v" >&2; exit 1; }
series=${core%.*}
below() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }
latest= minor=
while read -r tag; do
    r=${tag#v}
    [[ $r =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    below "$r" "$core" || continue
    if [ -z "$latest" ] || below "$latest" "$r"; then latest=$r; fi
    if [ "${r%.*}" != "$series" ] && { [ -z "$minor" ] || below "$minor" "$r"; }; then minor=$r; fi
done
[ -z "$latest" ] || echo "$latest"
[ -z "$minor" ] || [ "$minor" = "$latest" ] || echo "$minor"
