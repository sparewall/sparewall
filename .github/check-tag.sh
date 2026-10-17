#!/bin/bash
# Check a v* tag before anything is built from it (docs/releasing.md): it
# names a version, and a release is an annotated tag signed with a key in
# .github/release-signers.asc. A prerelease (a hyphen: v0.2.0-rc1) need not
# be signed, so a maintainer can sign the release tag on the commit of the
# last prerelease.
#
#   .github/check-tag.sh TAG
set -euo pipefail
tag=${1:?usage: check-tag.sh TAG}
n='(0|[1-9][0-9]*)'
if ! [[ $tag =~ ^v$n\.$n\.$n(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "$tag is not v<major>.<minor>.<patch>[-<prerelease>]" >&2
    exit 1
fi
case $tag in *-*)
    echo "$tag is a prerelease: no signature required"
    exit 0
esac
# actions/checkout may leave a lightweight copy of the tag: fetch the real one.
git fetch -q --force origin "refs/tags/$tag:refs/tags/$tag"
if [ "$(git cat-file -t "refs/tags/$tag")" != tag ]; then
    echo "$tag is not an annotated tag; a release tag must be signed (git tag -s)" >&2
    exit 1
fi
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
gpg -q --batch --import "$(dirname "$0")/release-signers.asc"
if ! git verify-tag "$tag"; then
    echo "$tag is not signed by a key in .github/release-signers.asc" >&2
    exit 1
fi
