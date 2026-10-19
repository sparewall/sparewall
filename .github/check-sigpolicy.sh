#!/bin/bash
# Check that a node would accept an image: copy it under the image's own
# containers policy and registries.d, with this repository's cosign.pub,
# as `bootc switch --enforce-container-sigpolicy` and bound image pulls do.
#
# tests/ci/signing.sh points the same policy at a disposable registry and
# key: SIGPOLICY_SCOPE replaces ghcr.io/sparewall, SIGPOLICY_KEY the key,
# and SIGPOLICY_TLS_VERIFY=false allows its plain-HTTP registry.
set -euo pipefail
ref=$1
root=$(cd "$(dirname "$0")/.." && pwd)
scope=${SIGPOLICY_SCOPE:-ghcr.io/sparewall}
key=${SIGPOLICY_KEY:-$root/cosign.pub}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
jq --arg scope "$scope" --arg key "$key" '
  .transports.docker |= with_entries(
    if .key == "ghcr.io/sparewall" then .key = $scope else . end)
  | (.transports.docker[][] | select(.type == "sigstoreSigned")).keyPath = $key' \
  "$root/image/files/etc/containers/policy.json" > "$tmp/policy.json"
mkdir "$tmp/registries.d"
sed "s|ghcr.io/sparewall:|$scope:|" \
  "$root/image/files/etc/containers/registries.d/sparewall.yaml" \
  > "$tmp/registries.d/sparewall.yaml"
# Anonymous, as a node pulls the public images: a runner's default auth
# file may be root's, left by an earlier `sudo podman login`.
echo '{}' > "$tmp/auth.json"
skopeo copy --quiet --src-authfile "$tmp/auth.json" \
  --src-tls-verify="${SIGPOLICY_TLS_VERIFY:-true}" --policy "$tmp/policy.json" \
  --registries.d "$tmp/registries.d" \
  "docker://$ref" "dir:$tmp/image"
echo "$ref: accepted by the node's signature policy"
