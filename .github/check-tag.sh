#!/bin/bash
# Check a v* tag before anything is built from it (docs/releasing.md):
#   - it names a version;
#   - it is the commit this workflow builds ($GITHUB_SHA), and that commit
#     is on main, so the workflow and this script were reviewed there;
#   - a release (no hyphen) is an annotated tag signed with a GPG key on
#     the GitHub account of one of RELEASE_SIGNERS (user names, which the
#     workflow takes from the collaborators with push access), fetched now,
#     so a tag cannot bring its own key and a key revoked on GitHub stops
#     counting.
# A prerelease (a hyphen: v0.2.0-rc1) need not be signed, so a maintainer
# can sign the release tag on the commit of the last prerelease.
#
#   GITHUB_SHA=COMMIT RELEASE_SIGNERS="user ..." .github/check-tag.sh TAG
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
[ -n "${RELEASE_SIGNERS:-}" ] || die "no RELEASE_SIGNERS"
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
for u in $RELEASE_SIGNERS; do
    keys=$(curl -fsSL "${KEYS_URL:-https://github.com}/$u.gpg") || die "cannot fetch $u's GPG keys"
    # An account without keys gets an armored note, which gpg "imports".
    gpg --batch --with-colons --show-keys <<<"$keys" 2>/dev/null | grep -q '^pub:' \
        || die "$u has no GPG keys on GitHub"
    gpg -q --batch --import <<<"$keys"
done
git verify-tag "$tag" || die "not signed by a GPG key of $RELEASE_SIGNERS"
