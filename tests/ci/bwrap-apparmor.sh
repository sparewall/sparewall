#!/bin/bash
# Let bootc-image-builder's osbuild use bubblewrap on this runner (#370).
#
# Ubuntu 26.04 ships an AppArmor profile for /usr/bin/bwrap,
# bwrap-userns-restrict. It attaches by path, so it also confines the
# bwrap inside bootc-image-builder's container, privileged and unconfined
# though the container is, and stacks bwrap's children under a profile
# with no capabilities. osbuild runs each stage under bwrap, so its
# container-deploy stage can't mount the container storage it deploys
# from ("mount: /run/osbuild/containers/storage: permission denied"),
# and no disk or installer is built. The runner is thrown away after the
# job, so the profile is unloaded for the job's length. Where there is no
# such profile (Ubuntu 24.04), this does nothing.
set -euo pipefail
profile=/etc/apparmor.d/bwrap-userns-restrict
if [ -f "$profile" ] && sudo grep -q '^bwrap ' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
    sudo apparmor_parser -R "$profile"
    echo "Unloaded the AppArmor profile in $profile for bootc-image-builder's osbuild."
fi
