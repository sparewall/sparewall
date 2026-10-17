#!/bin/bash
# Check a v* tag before anything is built from it (docs/releasing.md):
#   - it names a version;
#   - it is the commit this workflow builds ($GITHUB_SHA), and that commit
#     is on main, so the workflow and this script were reviewed there;
#   - a release (no hyphen) is an annotated tag signed with a key in
#     .github/release-signers.asc as main has it now, never as the tag
#     has it, so a tag cannot bring its own key and revoking a key on main
#     takes effect at once.
# A prerelease (a hyphen: v0.2.0-rc1) need not be signed, so a maintainer
# can sign the release tag on the commit of the last prerelease.
#
#   GITHUB_SHA=COMMIT .github/check-tag.sh TAG
set -euo pipefail
tag=${1:?usage: check-tag.sh TAG}
sha=${GITHUB_SHA:?GITHUB_SHA must name the commit being built}
die() { echo "$tag: $*" >&2; exit 1; }
n='(0|[1-9][0-9]*)'
[[ $tag =~ ^v$n\.$n\.$n(-[0-9A-Za-z.-]+)?$ ]] \
    || die "not v<major>.<minor>.<patch>[-<prerelease>]"

# actions/checkout may leave a lightweight copy of the tag, and a shallow
# history: fetch the real tag and all of main.
[ "$(git rev-parse --is-shallow-repository)" = false ] || git fetch -q --unshallow origin
git fetch -q --force origin "refs/tags/$tag:refs/tags/$tag" "+refs/heads/main:refs/remotes/origin/main"
[ "$(git rev-parse "refs/tags/$tag^{commit}")" = "$sha" ] \
    || die "the tag is not the commit being built ($sha)"
git merge-base --is-ancestor "$sha" refs/remotes/origin/main \
    || die "$sha is not on main; release from a commit on main"

case $tag in *-*)
    echo "$tag is a prerelease: no signature required"
    exit 0
esac
[ "$(git cat-file -t "refs/tags/$tag")" = tag ] \
    || die "not an annotated tag; a release tag must be signed (git tag -s)"
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
git show refs/remotes/origin/main:.github/release-signers.asc | gpg -q --batch --import
git verify-tag "$tag" || die "not signed by a key in main's .github/release-signers.asc"
