#!/bin/bash
# The release tag rules (docs/releasing.md): .github/check-tag.sh against a
# throwaway repository and keys, and .github/version.sh for a tag.
#
#   tests/ci/release-tags.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
check=$repo/.github/check-tag.sh

# The project's signers parse.
mkdir -m 700 "$t/gpg-repo"
GNUPGHOME=$t/gpg-repo gpg -q --batch --import "$repo/.github/release-signers.asc" \
    || fail "release-signers.asc does not import"

# A maintainer's key, which main trusts, and a stranger's.
for k in maintainer stranger; do
    mkdir -m 700 "$t/$k"
    GNUPGHOME=$t/$k gpg -q --batch --passphrase '' \
        --quick-gen-key "$k <$k@example.com>" ed25519 sign never
done
key() { GNUPGHOME=$t/$1 gpg -q --armor --export; }

git init -q --bare "$t/origin.git"
git init -q -b main "$t/work"
cd "$t/work"
git config user.name test
git config user.email test@example.com
git remote add origin "$t/origin.git"
mkdir .github
key maintainer > .github/release-signers.asc
git add .github
git commit -q -m release
main=$(git rev-parse HEAD)
git push -q origin main

# Off main: a commit that adds the stranger's key to the signers.
git switch -q -c rogue
key stranger >> .github/release-signers.asc
git commit -q -am "trust me"
rogue=$(git rev-parse HEAD)
git switch -q main

sign() { GNUPGHOME=$t/$1 git -c "user.signingkey=$1@example.com" tag -s "$2" -m "$2" "${3:-HEAD}"; }
sign maintainer v1.0.0
sign stranger v1.0.1
git tag -a v1.0.2 -m unsigned
git tag v1.0.3
git tag v1.1.0-rc1
sign stranger v1.1.0-rc2
git tag v1.1
sign stranger v2.0.0 "$rogue"  # signed with the key its own commit adds
sign maintainer v2.0.1 "$rogue" # a good signature, but not on main
git tag v2.0.2-rc1 "$rogue"

# On main: the stranger's key trusted for a commit, then revoked. Only
# main's current signers count, not those of the commit tagged.
key stranger >> .github/release-signers.asc
git commit -q -am "trust the stranger"
trusted=$(git rev-parse HEAD)
sign stranger v3.0.0
key maintainer > .github/release-signers.asc
git commit -q -am "revoke the stranger"
git push -q origin main --tags

# A clone shallow at the tag, as actions/checkout leaves it.
expect() { # exit-status tag message [commit being built]
    local got=0 sha=${4:-$main}
    rm -rf "$t/ci"
    git clone -q --depth 1 --branch "$2" "file://$t/origin.git" "$t/ci" 2>/dev/null
    (cd "$t/ci" && env -u GNUPGHOME GITHUB_SHA="$sha" "$check" "$2") >"$t/out" 2>&1 || got=$?
    [ "$got" = "$1" ] || fail "check-tag.sh $2: exit $got, want $1: $(cat "$t/out")"
    grep -q -- "$3" "$t/out" || fail "check-tag.sh $2: no '$3' in: $(cat "$t/out")"
}
expect 0 v1.0.0 'Good signature'                    # signed by a maintainer
expect 1 v1.0.1 'not signed by a key'               # signed by someone else
expect 1 v1.0.2 'not signed by a key'               # annotated, unsigned
expect 1 v1.0.3 'not an annotated tag'              # lightweight
expect 0 v1.1.0-rc1 'no signature required'         # a prerelease need not be signed
expect 0 v1.1.0-rc2 'no signature required'
expect 1 v1.1 'not v<major>'                        # not a version
expect 1 v2.0.0 'is not on main' "$rogue"           # its own commit cannot add its signer
expect 1 v2.0.1 'is not on main' "$rogue"
expect 1 v2.0.2-rc1 'is not on main' "$rogue"
expect 1 v1.0.0 'not the commit being built' "$rogue"
expect 1 v3.0.0 'not signed by a key' "$trusted" # revoked on main since

# A lightweight copy over a signed tag is replaced by the real one.
rm -rf "$t/ci"
git clone -q "file://$t/origin.git" "$t/ci" 2>/dev/null
(cd "$t/ci" && git tag -f v1.0.0 >/dev/null && env -u GNUPGHOME GITHUB_SHA="$main" "$check" v1.0.0 >/dev/null 2>&1) \
    || fail "check-tag.sh v1.0.0: a lightweight local copy was not replaced"

[ "$(GITHUB_REF=refs/tags/v1.2.3-rc1 GITHUB_REF_NAME=v1.2.3-rc1 "$repo/.github/version.sh")" = 1.2.3-rc1 ] \
    || fail "version.sh does not take the version from the tag"
echo "release tag checks: ok"
