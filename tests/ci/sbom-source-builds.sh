#!/bin/bash
# .github/sbom-source-builds.sh adds the source-built packages to an image
# SBOM, with the Containerfile's versions and checksums, and running it
# twice changes nothing.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$tmp/sbom.json" <<'JSON'
{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
 "documentDescribes": ["SPDXRef-DocumentRoot-Image-x"],
 "packages": [{"name": "bash", "SPDXID": "SPDXRef-Package-rpm-bash"}],
 "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
   "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-x"}]}
JSON
.github/sbom-source-builds.sh "$tmp/sbom.json" image/Containerfile
cp "$tmp/sbom.json" "$tmp/once.json"
.github/sbom-source-builds.sh "$tmp/sbom.json" image/Containerfile
cmp -s "$tmp/sbom.json" "$tmp/once.json" || fail "a second run changed the SBOM"

v() { sed -n "s/^ARG $1=//p" image/Containerfile; }
q() { jq -r "$1" "$tmp/sbom.json"; }
[ "$(q '.packages | length')" = 3 ] || fail "expected bash plus two packages"
[ "$(q '.packages[] | select(.name == "ulogd") | .versionInfo')" = "$(v ULOGD_VERSION)" ] \
    || fail "ulogd's version"
[ "$(q '.packages[] | select(.name == "libnetfilter_log") | .checksums[0].checksumValue')" = "$(v NFLOG_SHA256)" ] \
    || fail "libnetfilter_log's checksum"
[ "$(q '[.packages[] | select(.licenseDeclared == "GPL-2.0-only")] | length')" = 2 ] \
    || fail "licenses"
[ "$(q '[.relationships[] | select(.spdxElementId == "SPDXRef-DocumentRoot-Image-x" and .relationshipType == "CONTAINS")] | length')" = 2 ] \
    || fail "the image contains both"
[ "$(q '[.relationships[] | select(.relationshipType == "STATIC_LINK")] | length')" = 1 ] \
    || fail "ulogd links libnetfilter_log"
echo "sbom source builds: ok"
