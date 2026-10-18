#!/bin/bash
# The version a build reports (SPAREWALL_VERSION, read by sparewall-core):
# the tag's on a v* tag; otherwise git describe from the last v* tag
# (0.1.0-beta1-5-gabc1234), or Cargo's version and the commit if no tag is
# reachable. Describing needs the history: check out with fetch-depth 0.
set -euo pipefail
case ${GITHUB_REF:-} in
refs/tags/v*) echo "${GITHUB_REF_NAME#v}" ;;
*)
    if d=$(git describe --tags --match 'v[0-9]*' 2>/dev/null); then
        echo "${d#v}"
    else
        v=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../Cargo.toml" | head -1)
        echo "$v-dev+g$(git rev-parse --short=12 HEAD)"
    fi
    ;;
esac
