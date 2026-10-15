#!/bin/bash
# Add the image's logically bound provider images to an installer ISO
# built by bootc-image-builder, under /bound-images: one docker-archive
# per image and images.list ("FILE REFERENCE" lines). bootc pulls bound
# images from their registry during the install unless they are already
# in the target's image store; the kickstart's %pre-install
# (installer.toml) copies them there, so an offline install has them.
#
#   image/embed-bound-images.sh IMAGE ISO
#
# The images must be in the host's container storage (as for
# bootc-image-builder). Needs root (podman) and xorriso.
set -euo pipefail
IMAGE=${1:?usage: embed-bound-images.sh IMAGE ISO}
ISO=${2:?usage: embed-bound-images.sh IMAGE ISO}
dir=$(mktemp -d "$(dirname "$ISO")/bound.XXXXXX")
trap 'sudo rm -rf -- "$dir"' EXIT

mapfile -t refs < <(sudo podman run --rm --entrypoint sh "$IMAGE" -c \
    'for f in /usr/lib/bootc/bound-images.d/*; do sed -n "s/^Image=//p" "$f"; done')
[ ${#refs[@]} -gt 0 ] || { echo "no bound images in $IMAGE" >&2; exit 1; }
mkdir "$dir/bound-images"
i=0
for ref in "${refs[@]}"; do
    i=$((i + 1))
    sudo podman save --format docker-archive -o "$dir/bound-images/$i.tar" "$ref"
    echo "$i.tar $ref" >> "$dir/bound-images/images.list"
done
sudo chown -R "$(id -u):$(id -g)" "$dir/bound-images"
# replay keeps the ISO's boot records (BIOS, EFI and the hybrid MBR).
xorriso -indev "$ISO" -outdev "$dir/out.iso" -boot_image any replay \
    -map "$dir/bound-images" /bound-images -commit >/dev/null 2>&1 \
    || { echo "xorriso could not add the bound images to $ISO" >&2; exit 1; }
mv "$dir/out.iso" "$ISO"
echo "added ${#refs[@]} bound images to $ISO: ${refs[*]}"
