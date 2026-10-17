#!/bin/bash
# Build the release's installer and disk images from a published image
# with bootc-image-builder (design: "Build, sign, publish"):
#
#   sparewall-VERSION-x86_64.iso        unattended installer for physical
#                                       machines, to the first fixed disk
#                                       if it is blank (installer.toml)
#   sparewall-VERSION-x86_64.raw.zst    a disk image to write to a disk
#   sparewall-VERSION-x86_64.qcow2      a disk image for VMs
#
# A file over GitHub's 2 GiB asset limit is split into .partNN pieces.
#
#   image/installers.sh IMAGE VERSION OUTDIR
#
# Needs root (podman), qemu-img, zstd and xorriso.
set -euo pipefail
IMAGE=${1:?usage: installers.sh IMAGE VERSION OUTDIR}
VERSION=${2:?usage: installers.sh IMAGE VERSION OUTDIR}
OUT=${3:?usage: installers.sh IMAGE VERSION OUTDIR}
BIB=${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}
LIMIT=$((2 * 1024 * 1024 * 1024 - 1))
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/build"
OUT=$(cd "$OUT" && pwd)

# bootc copies the logically bound provider images into the new system
# from the host's container storage, so they must be there first.
for ref in $(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
        'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done'); do
    sudo podman image exists "$ref" || sudo podman pull "$ref"
done
bib() { # [config.toml] -- bootc-image-builder arguments
    local config=$1; shift 2
    sudo podman run --rm --privileged \
        --security-opt label=type:unconfined_t \
        -v "$OUT/build:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        ${config:+-v "$config:/config.toml:ro"} \
        "$BIB" "$@" --rootfs xfs "$IMAGE"
}
bib '' -- --type qcow2 --type raw
# The kickstart is for the installer only, so the ISO is a separate build.
bib "$HERE/installer.toml" -- --type anaconda-iso
sudo chown -R "$(id -u):$(id -g)" "$OUT/build"
"$HERE/embed-bound-images.sh" "$IMAGE" "$OUT/build/bootiso/install.iso"

base=$OUT/sparewall-$VERSION-x86_64
mv "$OUT/build/bootiso/install.iso" "$base.iso"
zstd -q -T0 -19 --rm "$OUT/build/image/disk.raw" -o "$base.raw.zst"
qemu-img convert -c -O qcow2 "$OUT/build/qcow2/disk.qcow2" "$base.qcow2"
rm -rf "$OUT/build"

for f in "$base.iso" "$base.raw.zst" "$base.qcow2"; do
    if [ "$(stat -c %s "$f")" -gt "$LIMIT" ]; then
        split -b 2000M -d --additional-suffix= "$f" "$f.part"
        rm "$f"
    fi
done
ls -la "$OUT"
