#!/bin/bash
# Check that a node would accept an image: copy it under the image's own
# containers policy and registries.d, with this repository's cosign.pub,
# as `bootc switch --enforce-container-sigpolicy` and bound image pulls do.
set -euo pipefail
ref=$1
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
jq --arg key "$root/cosign.pub" \
  '(.transports.docker[][] | select(.type == "sigstoreSigned")).keyPath = $key' \
  "$root/image/files/etc/containers/policy.json" > "$tmp/policy.json"
skopeo copy --quiet --policy "$tmp/policy.json" \
  --registries.d "$root/image/files/etc/containers/registries.d" \
  "docker://$ref" "dir:$tmp/image"
echo "$ref: accepted by the node's signature policy"
