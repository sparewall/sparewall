#!/bin/bash
# Add the packages image/Containerfile builds from source (ulogd and the
# libnetfilter_log linked into it) to an SPDX JSON SBOM of the image, in
# place: syft lists what the RPM database and language manifests show,
# and these are in neither. Each version and checksum is read from the
# Containerfile's ARGs, so the SBOM follows the build.
#
#   .github/sbom-source-builds.sh sbom.spdx.json [image/Containerfile]
set -euo pipefail
sbom=${1:?usage: sbom-source-builds.sh SBOM [CONTAINERFILE]}
cf=${2:-image/Containerfile}

arg() { # NAME: the default value of ARG NAME in the Containerfile
    local v
    v=$(sed -n "s/^ARG $1=\\(.*\\)\$/\\1/p" "$cf" | head -1)
    [ -n "$v" ] || { echo "sbom-source-builds: no ARG $1 in $cf" >&2; exit 1; }
    printf '%s' "$v"
}

nflog_v=$(arg NFLOG_VERSION) nflog_sum=$(arg NFLOG_SHA256)
ulogd_v=$(arg ULOGD_VERSION) ulogd_sum=$(arg ULOGD_SHA256)

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
jq --arg nv "$nflog_v" --arg ns "$nflog_sum" --arg uv "$ulogd_v" --arg us "$ulogd_sum" '
  def pkg($name; $v; $sum; $url; $license):
    # SPDX IDs allow letters, digits, "." and "-" only.
    { name: $name,
      SPDXID: "SPDXRef-Package-source-\($name | gsub("[^A-Za-z0-9.-]"; "-"))",
      versionInfo: $v,
      supplier: "Organization: netfilter.org",
      downloadLocation: $url,
      filesAnalyzed: false,
      checksums: [{algorithm: "SHA256", checksumValue: $sum}],
      # As the main source file states it (src/ulogd.c: version 2 only;
      # src/libnetfilter_log.c: version 2 or later). COPYING is the GPL
      # version 2 in both.
      licenseConcluded: $license,
      licenseDeclared: $license,
      copyrightText: "NOASSERTION",
      comment: "Built from source in image/Containerfile (the ulogd stage); the checksum is of the source archive. Its COPYING, the GNU GPL version 2, ships in /usr/share/licenses.",
      externalRefs: [{referenceCategory: "PACKAGE-MANAGER", referenceType: "purl",
        referenceLocator: "pkg:generic/netfilter/\($name)@\($v)?download_url=\($url | @uri)"}] };
  (.documentDescribes // [] | .[0]) as $root
  | ($root // ([.relationships[]? | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement][0])) as $top
  | [pkg("libnetfilter_log"; $nv; $ns;
        "https://netfilter.org/pub/libnetfilter_log/libnetfilter_log-\($nv).tar.bz2";
        "GPL-2.0-or-later"),
     pkg("ulogd"; $uv; $us; "https://netfilter.org/pub/ulogd/ulogd-\($uv).tar.xz";
        "GPL-2.0-only")] as $new
  | .packages = ([.packages[]? | select(.SPDXID | startswith("SPDXRef-Package-source-") | not)] + $new)
  | .relationships = ([.relationships[]? | select(.relatedSpdxElement | startswith("SPDXRef-Package-source-") | not)]
      + (if $top then [$new[] | {spdxElementId: $top, relationshipType: "CONTAINS", relatedSpdxElement: .SPDXID}] else [] end)
      + [{spdxElementId: "SPDXRef-Package-source-ulogd", relationshipType: "STATIC_LINK",
          relatedSpdxElement: "SPDXRef-Package-source-libnetfilter-log"}])
' "$sbom" > "$tmp"
cat "$tmp" > "$sbom"
