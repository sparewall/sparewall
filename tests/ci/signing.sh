#!/bin/bash
# The release signing path, before merge: a disposable registry and key,
# .github/sign-image.sh, and the node's own policy (check-sigpolicy.sh).
# A signature in cosign 3's default format must be refused, as a node
# refuses it, so the check is known to bite.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
port=${SIGNING_REGISTRY_PORT:-5000}
reg=localhost:$port
name=sw-signing-registry
cleanup() { podman rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

podman run -d --rm --name "$name" -p "$port:5000" quay.io/libpod/registry:2.8.2 >/dev/null
for _ in $(seq 30); do curl -sf "http://$reg/v2/" >/dev/null && break; sleep 1; done
# The registry is plain HTTP: skopeo is told so, and cosign
# (go-containerregistry) uses HTTP for localhost by itself.

(cd "$tmp" && COSIGN_PASSWORD='' cosign generate-key-pair >/dev/null)
export COSIGN_PRIVATE_KEY COSIGN_PASSWORD=''
COSIGN_PRIVATE_KEY=$(cat "$tmp/cosign.key")
export SIGPOLICY_SCOPE=$reg/sparewall SIGPOLICY_KEY=$tmp/cosign.pub SIGPOLICY_TLS_VERIFY=false
export SIGN_TLOG_UPLOAD=false

push() {
  skopeo copy --quiet --dest-tls-verify=false docker://quay.io/libpod/registry:2.8.2 "docker://$reg/sparewall/$1:t"
  echo "$reg/sparewall/$1@$(skopeo inspect --tls-verify=false --format '{{.Digest}}' "docker://$reg/sparewall/$1:t")"
}

ref=$(push legacy)
"$root/.github/sign-image.sh" "$ref"
cosign verify --key "$tmp/cosign.pub" --insecure-ignore-tlog=true "$ref" >/dev/null
"$root/.github/check-sigpolicy.sh" "$reg/sparewall/legacy:t"

ref=$(push referrer)
# cosign 3's default: a bundle stored as an OCI referrer (with no
# transparency log, which the default mode only allows by signing config).
cosign signing-config create --out "$tmp/no-tlog.json"
cosign sign --yes --key env://COSIGN_PRIVATE_KEY --signing-config "$tmp/no-tlog.json" "$ref"
if "$root/.github/check-sigpolicy.sh" "$ref" 2>"$tmp/err"; then
  echo "a default cosign 3 signature passed the node policy check" >&2
  exit 1
fi
grep -q 'A signature was required, but no signature exists' "$tmp/err" || { cat "$tmp/err" >&2; exit 1; }
echo "default-format signature refused, as on a node"
echo "ok: signing path"
