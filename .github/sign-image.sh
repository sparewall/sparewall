#!/bin/bash
# Sign an image, by digest, so that a node accepts it, and prove it with
# the client a node uses (check-sigpolicy.sh).
#
# cosign 3 stores a signature by default as an OCI referrer in the new
# bundle format, which containers/image (bootc, podman) does not read: it
# finds sigstore signatures only by the sha256-<digest>.sig tag. So the
# signature is made in the legacy format, which nodes can check.
# SIGN_TLOG_UPLOAD=false keeps a test's disposable key out of the public
# transparency log.
set -euo pipefail
ref=$1
cosign sign --yes --key env://COSIGN_PRIVATE_KEY \
  --new-bundle-format=false --use-signing-config=false \
  --tlog-upload="${SIGN_TLOG_UPLOAD:-true}" "$ref"
"$(dirname "$0")/check-sigpolicy.sh" "$ref"
