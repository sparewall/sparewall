# Releasing

For maintainers. A release is a tested commit on `main`, tagged.

1. Pick a commit on `main` whose image workflow passed (build, boot,
   publish; pair faults; offline install).
2. Tag it and push the tag:
   ```shell
   git tag -s v0.1.0 -m "Sparewall 0.1.0"
   git push origin v0.1.0
   ```
   A tag with a hyphen (`v0.2.0-rc1`) is a prerelease. Before it builds
   anything, the image workflow checks that the tag is on a commit on
   `main`, and that a release tag (no hyphen) is signed with a GPG key on
   the GitHub account of whoever pushed it, who has push access or could
   not have pushed. The keys are fetched from GitHub
   (`https://github.com/USER.gpg`) at that moment: add your signing key to your account, and a key you remove
   stops counting. A prerelease need not be signed, so the usual path is
   an unsigned `-rcN` that anyone with push access can tag, then the
   release signed and pushed by a maintainer on the same commit once the last rc
   proves out:
   ```shell
   git tag -s v0.2.0 -m "Sparewall 0.2.0" v0.2.0-rc2^{}
   ```

   The check catches mistakes, not someone with push access: it runs in
   the workflow of the commit being tagged, so a tag on an unreviewed
   commit could carry a workflow that skips it (and push access can
   already reach the repository's secrets). While only the maintainer can
   push, that is enough. Push access also makes someone a release signer,
   so before giving it to anyone else, add a tag
   ruleset limiting who may create `v*` tags, and move the signing key
   into a `release` environment that needs a maintainer's approval.
3. The image workflow runs again for the tag: it rebuilds the image, runs
   every VM suite, including upgrades to it from earlier releases
   (`tests/vm/upgrade-test.sh`, from the releases
   `.github/upgrade-from.sh` names, see [operations](operations.md#upgrades)), publishes the image as `sha-<commit>` (and `testing`),
   then the **release assets** job drafts a GitHub release with:
   - `sparewall-VERSION-x86_64.iso`: the unattended installer (to the
     first fixed disk, if it is blank);
   - `sparewall-VERSION-x86_64.raw.zst` and `.qcow2`: disk images;
   - `sparewall-VERSION-ARCH-linux.tar.gz` and
     `sparewall-VERSION-ARCH-darwin.tar.gz`: the CLI, for Linux (static)
     and macOS, each on x86_64 and aarch64;
   - SPDX SBOMs of the image and of the CLI (from the dependency list
     cargo-auditable embeds in the binary);
   - `SHA256SUMS`, signed with the project key
     (`SHA256SUMS.sigstore.json`).

   The draft's notes are for its readers: the pull requests merged since
   the last release (GitHub's generated list), how to install or
   upgrade, and how to verify the downloads. The run summary says what
   publishing will do.

   Files over GitHub's 2 GiB limit are split into `.partNN` pieces;
   `SHA256SUMS` lists each piece and the joined file.
4. Review the draft, edit its notes, and publish it. Publishing runs the
   release workflow: it tags the tested image `VERSION` and, unless it is a
   prerelease, `stable`, so nodes following the stable channel see it.
   It then checks each tag as a node would, under the image's own
   signature policy (`.github/check-sigpolicy.sh`).

Images are signed in cosign's legacy format, the `sha256-DIGEST.sig`
tag, because that is the only one bootc and podman read; cosign's newer
OCI-referrer bundles go unseen and a node refuses the image. `cosign
verify` needs `--new-bundle-format=false` to check it: by default cosign 3
reads only the referrers, where the SBOM attestation is. Releases up
to 0.1.1 were signed only in the newer format: the **Re-sign** workflow
(run it from the Actions tab with the release tag) signs a release's OS
and provider images again by digest, without moving any tag.
CI's **image signing path** job runs the same scripts against a
throwaway registry and key on every pull request
(`tests/ci/signing.sh`), and checks that a default-format signature is
refused.

Publishing a release (not a prerelease) also updates the Homebrew tap,
[`sparewall/homebrew-tap`](https://github.com/sparewall/homebrew-tap):
the release workflow writes `Formula/sparewall.rb` from the release's
signed `SHA256SUMS` (`.github/homebrew-formula.sh`) and pushes it, so
`brew upgrade` follows. It pushes over SSH with the
`HOMEBREW_TAP_DEPLOY_KEY` secret, the private half of a write deploy key
on the tap (the organization must allow deploy keys); without the secret
it warns and leaves the tap alone. It never moves the
tap back to an older version. The image workflow's macOS CLI job
installs the formula it would write, from a local tap, on every run.

A failed suite stops at step 3 with no release. Delete the tag, fix
`main`, and tag again.

## A demo node

To try a build by hand before tagging it (the web UI especially),
`tests/vm/demo.sh` runs one node in a VM under libvirt's user session,
with a configuration that gives every page something to show. It needs
libvirt, qemu, passt, swtpm and virt-install; only the disk build needs
root.

```shell
tests/vm/demo.sh disk          # base disk from :testing (or name an image)
tests/vm/demo.sh up            # https://localhost:8443/, users and passwords printed
tests/vm/demo.sh reset         # a fresh install from the base disk
tests/vm/demo.sh destroy
```

The web UI and SSH are forwarded from localhost only. The VM's WAN is
NATed to this machine's network; its LAN trunk has nothing on it.

## Versions

The binaries report the version the build is given in
`SPAREWALL_VERSION` (`.github/version.sh`): on a tag, the tag's, so
`v0.2.0-rc1` builds `sparewall 0.2.0-rc1` whatever `Cargo.toml` says;
between tags, `git describe` from the last one (`0.2.0-rc1-4-gabc1234`).
The release job refuses an image or CLI that reports anything else. A
local `cargo build` reports the `Cargo.toml` version, which is not bumped
per release.
