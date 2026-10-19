#!/bin/bash
# .github/homebrew-formula.sh: a block for each CLI tarball a release has,
# none for one it lacks, and no formula at all without any.
set -euo pipefail
gen=$(cd "$(dirname "$0")/../.." && pwd)/.github/homebrew-formula.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$tmp/all" <<'SUMS'
1111  sparewall-0.2.0-x86_64-linux.tar.gz
2222  sparewall-0.2.0-aarch64-darwin.tar.gz
3333  sparewall-0.2.0-x86_64-darwin.tar.gz
4444  sparewall-0.2.0-x86_64.iso
SUMS
f=$("$gen" 0.2.0 "$tmp/all")
grep -q '^  version "0.2.0"$' <<<"$f" || fail "no version"
for want in "1111" "2222" "3333"; do
    grep -q "sha256 \"$want\"" <<<"$f" || fail "no sha256 $want"
done
grep -q 'sha256 "4444"' <<<"$f" && fail "the ISO is in the formula"
grep -q 'releases/download/v0.2.0/sparewall-0.2.0-aarch64-darwin.tar.gz"' <<<"$f" || fail "no default URL"
if command -v ruby >/dev/null; then
    ruby -c <<<"$f" >/dev/null || fail "not valid Ruby"
fi

# A release from before the macOS builds: Linux only.
grep linux "$tmp/all" > "$tmp/linux"
f=$("$gen" 0.2.0 "$tmp/linux" https://example.test/d)
grep -q on_macos <<<"$f" && fail "an on_macos block without a macOS tarball"
grep -q 'url "https://example.test/d/sparewall-0.2.0-x86_64-linux.tar.gz"' <<<"$f" || fail "BASE_URL ignored"

grep iso "$tmp/all" > "$tmp/none"
if "$gen" 0.2.0 "$tmp/none" >/dev/null 2>&1; then
    fail "a formula without any CLI tarball"
fi
echo "ok: homebrew formula"
