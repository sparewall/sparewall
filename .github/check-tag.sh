#!/bin/bash
# Check a v* tag before anything is built from it (docs/releasing.md):
#   - it names a version;
#   - it is the commit this workflow builds ($GITHUB_SHA), and that commit
#     is on main, so the workflow and this script were reviewed there;
#   - a release (no hyphen) is an annotated tag signed with a GPG key on
#     the GitHub account of a maintainer of the repository, whoever has
#     the maintain or admin role, directly or through a team. The account
#     is the tagger's: the one GitHub matches to the tagger's email, which
#     only an account that has verified that email gets. Its role and
#     keys are asked of GitHub now, so the roles are the one list of who
#     may release, a tag cannot bring its own key, and a key revoked on
#     GitHub stops counting. (The workflow's token cannot list the
#     repository's collaborators, only ask about one.)
# A prerelease (a hyphen: v0.2.0-rc1) need not be signed, so a maintainer
# can sign the release tag on the commit of the last prerelease.
#
#   GITHUB_SHA=COMMIT GITHUB_REPOSITORY=OWNER/REPO GH_TOKEN=… .github/check-tag.sh TAG
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
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must name the repository}
# The tagger's account, for the tag object fetched above.
# shellcheck disable=SC2016 # the query's $variables are GraphQL's
who=$(gh api graphql -f owner="${repo%/*}" -f name="${repo#*/}" -f ref="refs/tags/$tag" -f query='
    query($owner: String!, $name: String!, $ref: String!) {
      repository(owner: $owner, name: $name) {
        ref(qualifiedName: $ref) { target { oid ... on Tag { tagger { user { login } } } } }
      }
    }' --jq '.data.repository.ref.target | "\(.oid) \(.tagger.user.login // "")"') \
    || die "cannot ask GitHub who tagged it"
read -r oid signer <<<"$who"
[ "$oid" = "$(git rev-parse "refs/tags/$tag")" ] || die "GitHub has another tag object ($oid)"
tagger=$(git for-each-ref --format='%(taggeremail)' "refs/tags/$tag")
[ -n "$signer" ] || die "its tagger $tagger is not a verified email of any GitHub account"
maintain=$(gh api "repos/$repo/collaborators/$signer/permission" --jq .user.permissions.maintain) \
    || die "cannot ask GitHub for $signer's role"
[ "$maintain" = true ] || die "tagged by $signer, who is not a maintainer (the maintain or admin role)"
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
keys=$(curl -fsSL "${KEYS_URL:-https://github.com}/$signer.gpg") || die "cannot fetch $signer's GPG keys"
# An account without keys gets an armored note, which gpg "imports".
gpg --batch --with-colons --show-keys <<<"$keys" 2>/dev/null | grep -q '^pub:' \
    || die "$signer has no GPG keys on GitHub"
gpg -q --batch --import <<<"$keys"
git verify-tag "$tag" || die "not signed by a GPG key of $signer, its tagger"
