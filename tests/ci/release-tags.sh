#!/bin/bash
# The release tag rules (docs/releasing.md): .github/check-tag.sh against a
# throwaway repository and keys, served from a directory in place of
# github.com, and .github/version.sh for a tag.
#
#   tests/ci/release-tags.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
check=$repo/.github/check-tag.sh

# A maintainer, a stranger, and the maintainer's next key; "GitHub" has
# the first two accounts' keys.
for k in maintainer stranger rotated; do
    mkdir -m 700 "$t/$k"
    GNUPGHOME=$t/$k gpg -q --batch --passphrase '' \
        --quick-gen-key "$k <$k@example.com>" ed25519 sign never
done
key() { GNUPGHOME=$t/$1 gpg -q --armor --export; }
mkdir "$t/github"
key maintainer > "$t/github/maintainer.gpg"
key stranger > "$t/github/stranger.gpg"

git init -q --bare -b main "$t/origin.git"
git init -q -b main "$t/work"
cd "$t/work"
git config user.name test
git config user.email test@example.com
git remote add origin "$t/origin.git"
git commit -q --allow-empty -m release
main=$(git rev-parse HEAD)
git switch -q -c elsewhere
git commit -q --allow-empty -m "not on main"
elsewhere=$(git rev-parse HEAD)
git switch -q main
git push -q origin main

sign() { GNUPGHOME=$t/$1 git -c "user.signingkey=$1@example.com" tag -s "$2" -m "$2" "${3:-HEAD}"; }
sign maintainer v1.0.0
sign stranger v1.0.1
git tag -a v1.0.2 -m unsigned
git tag v1.0.3
git tag v1.1.0-rc1
sign stranger v1.1.0-rc2
git tag v1.1
sign maintainer v2.0.0 "$elsewhere"
git tag v2.0.1-rc1 "$elsewhere"
git push -q origin --tags

# A clone shallow at the tag, as actions/checkout leaves it.
signers=maintainer
expect() { # exit-status tag message [commit being built]
    local got=0 sha=${4:-$main}
    rm -rf "$t/ci"
    git clone -q --depth 1 --branch "$2" "file://$t/origin.git" "$t/ci" 2>/dev/null
    (cd "$t/ci" && env -u GNUPGHOME GITHUB_SHA="$sha" RELEASE_SIGNERS="$signers" \
        KEYS_URL="file://$t/github" "$check" "$2") >"$t/out" 2>&1 || got=$?
    [ "$got" = "$1" ] || fail "check-tag.sh $2: exit $got, want $1: $(cat "$t/out")"
    grep -q -- "$3" "$t/out" || fail "check-tag.sh $2: no '$3' in: $(cat "$t/out")"
}
expect 0 v1.0.0 'Good signature'                       # signed by a signer
expect 1 v1.0.1 'not signed by a GPG key'              # signed by someone else
expect 1 v1.0.2 'not signed by a GPG key'              # annotated, unsigned
expect 1 v1.0.3 'not an annotated tag'                 # lightweight
expect 0 v1.1.0-rc1 'no signature required'            # a prerelease need not be signed
expect 0 v1.1.0-rc2 'no signature required'
expect 1 v1.1 'not v<major>'                           # not a version
expect 1 v2.0.0 'is not on main' "$elsewhere"          # signed, but not on main
expect 1 v2.0.1-rc1 'is not on main' "$elsewhere"
expect 1 v1.0.0 'not the commit being built' "$elsewhere"

signers="nobody maintainer"                           # an account that cannot be fetched
expect 1 v1.0.0 "cannot fetch nobody's GPG keys"
signers="maintainer stranger"                         # more than one signer
expect 0 v1.0.1 'Good signature'
signers=
expect 1 v1.0.0 'no RELEASE_SIGNERS'
signers=maintainer
key rotated > "$t/github/maintainer.gpg"              # the old key revoked on GitHub
expect 1 v1.0.0 'not signed by a GPG key'
printf '%s\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----' \
    "Note: This user hasn't uploaded any GPG keys." '' '=twTO' \
    '-----END PGP PUBLIC KEY BLOCK-----' > "$t/github/maintainer.gpg" # as GitHub has it
expect 1 v1.0.0 'has no GPG keys'
key maintainer > "$t/github/maintainer.gpg"

# A lightweight local copy over a signed tag is replaced by the real one.
rm -rf "$t/ci"
git clone -q "file://$t/origin.git" "$t/ci" 2>/dev/null
(cd "$t/ci" && git tag -f v1.0.0 >/dev/null && env -u GNUPGHOME GITHUB_SHA="$main" \
    RELEASE_SIGNERS=maintainer KEYS_URL="file://$t/github" "$check" v1.0.0 >/dev/null 2>&1) \
    || fail "check-tag.sh v1.0.0: a lightweight local copy was not replaced"

[ "$(GITHUB_REF=refs/tags/v1.2.3-rc1 GITHUB_REF_NAME=v1.2.3-rc1 "$repo/.github/version.sh")" = 1.2.3-rc1 ] \
    || fail "version.sh does not take the version from the tag"
echo "release tag checks: ok"
