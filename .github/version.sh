#!/bin/bash
# The version a build reports (SPAREWALL_VERSION, read by sparewall-core,
# and the image's org.sparewall.version label): the tag's on a
# v* tag; otherwise a prerelease of the next version, N commits after the
# last v* tag, so that builds sort as semver says (#170):
#
#   after v0.3.1        0.3.2-dev.N+gabc123456789   (before 0.3.2-rc1 and 0.3.2)
#   after v0.4.0-rc1    0.4.0-rc1.dev.N+gabc123456789 (before 0.4.0-rc2)
#
# or Cargo's version and the commit if no tag is reachable. Describing
# needs the history: check out with fetch-depth 0.
#
# A rebuild of a release (#187: the same source on newer base images) sets
# REBUILD=N on its tag and is X.Y.Z+rN: semver build metadata, which
# precedence ignores, so nodes compare it as the same version, rebuilt.
set -euo pipefail
case ${GITHUB_REF:-} in
refs/tags/v*)
    v=${GITHUB_REF_NAME#v}
    if [ -n "${REBUILD:-}" ]; then
        [[ $REBUILD =~ ^[1-9][0-9]*$ ]] || { echo "REBUILD must be a number from 1: $REBUILD" >&2; exit 1; }
        [[ $v != *-* ]] || { echo "only a release is rebuilt, not $v" >&2; exit 1; }
        echo "$v+r$REBUILD"
    else
        echo "$v"
    fi
    ;;
*)
    if d=$(git describe --tags --long --abbrev=12 --match 'v[0-9]*' 2>/dev/null); then
        # vX.Y.Z[-PRE]-N-gSHA
        d=${d#v}
        sha=${d##*-g}
        d=${d%-g*}
        n=${d##*-}
        base=${d%-*}
        if [ "$n" = 0 ]; then
            echo "$base"
        elif [[ $base == *-* ]]; then
            echo "$base.dev.$n+g$sha"
        else
            IFS=. read -r major minor patch <<<"$base"
            echo "$major.$minor.$((patch + 1))-dev.$n+g$sha"
        fi
    else
        v=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../Cargo.toml" | head -1)
        echo "$v-dev+g$(git rev-parse --short=12 HEAD)"
    fi
    ;;
esac
