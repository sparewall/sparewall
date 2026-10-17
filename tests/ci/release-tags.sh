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

# The project's signers parse.
GNUPGHOME=$t/gpg-repo
mkdir -m 700 "$GNUPGHOME"
GNUPGHOME=$GNUPGHOME gpg -q --batch --import "$repo/.github/release-signers.asc" \
    || fail "release-signers.asc does not import"

# A maintainer key and a stranger's; the check trusts only the first.
for k in maintainer stranger; do
    mkdir -m 700 "$t/$k"
    GNUPGHOME=$t/$k gpg -q --batch --passphrase '' \
        --quick-gen-key "$k <$k@example.com>" ed25519 sign never
done
mkdir "$t/bin"
cp "$repo/.github/check-tag.sh" "$t/bin/"
GNUPGHOME=$t/maintainer gpg -q --armor --export > "$t/bin/release-signers.asc"

git init -q --bare "$t/origin.git"
git init -q "$t/work"
cd "$t/work"
git config user.name test
git config user.email test@example.com
git commit -q --allow-empty -m release
git remote add origin "$t/origin.git"
sign() { GNUPGHOME=$t/$1 git -c "user.signingkey=$1@example.com" tag -s "$2" -m "$2"; }
sign maintainer v1.0.0
sign stranger v1.0.1
git tag -a v1.0.2 -m unsigned
git tag v1.0.3
git tag v1.1.0-rc1
sign stranger v1.1.0-rc2
git tag v1.1
git push -q origin --tags

expect() { # exit-status tag
    local got=0
    env -u GNUPGHOME "$t/bin/check-tag.sh" "$2" >/dev/null 2>&1 || got=$?
    [ "$got" = "$1" ] || fail "check-tag.sh $2: exit $got, want $1"
}
expect 0 v1.0.0     # signed by a maintainer
expect 1 v1.0.1     # signed by someone else
expect 1 v1.0.2     # annotated, unsigned
expect 1 v1.0.3     # lightweight
expect 0 v1.1.0-rc1 # a prerelease need not be signed
expect 0 v1.1.0-rc2
expect 1 v1.1       # not a version

# A lightweight copy over a signed tag (as actions/checkout can leave)
# is replaced by the real one.
git tag -f v1.0.0 >/dev/null
expect 0 v1.0.0

[ "$(GITHUB_REF=refs/tags/v1.2.3-rc1 GITHUB_REF_NAME=v1.2.3-rc1 "$repo/.github/version.sh")" = 1.2.3-rc1 ] \
    || fail "version.sh does not take the version from the tag"
echo "release tag checks: ok"
