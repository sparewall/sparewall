#!/bin/bash
# Build WORKDIR/output/qcow2/disk.qcow2 from a Sparewall image with
# bootc-image-builder, unless it is already there.
#
#   tests/vm/build-disk.sh IMAGE WORKDIR
set -euo pipefail
IMAGE=${1:?usage: build-disk.sh IMAGE WORKDIR}
WORK=${2:?usage: build-disk.sh IMAGE WORKDIR}
BIB=${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}
mkdir -p "$WORK/output"
cd "$WORK"
if [ ! -f output/qcow2/disk.qcow2 ]; then
    # bootc copies the logically bound provider images into the new system
    # from the host's container storage, so they must be there first.
    for ref in $(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
            'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done'); do
        sudo podman image exists "$ref" || sudo podman pull "$ref"
    done
    auth=()
    if sudo test -f /run/containers/0/auth.json; then
        auth=(-v /run/containers/0/auth.json:/run/containers/0/auth.json:ro)
    fi
    sudo podman run --rm --privileged \
        --security-opt label=type:unconfined_t \
        "${auth[@]}" \
        -v "$WORK/output:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        "$BIB" --type qcow2 --rootfs xfs "$IMAGE"
fi
sudo chown -R "$(id -u):$(id -g)" output
