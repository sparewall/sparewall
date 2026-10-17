# Releasing

For maintainers. A release is a tested commit on `main`, tagged.

1. Pick a commit on `main` whose image workflow passed (build, boot,
   publish; pair faults; offline install).
2. Tag it and push the tag:
   ```shell
   git tag -s v0.1.0 -m "Sparewall 0.1.0"
   git push origin v0.1.0
   ```
   A tag with a hyphen (`v0.2.0-rc1`) is a prerelease. A release tag (no
   hyphen) must be signed with a key in `.github/release-signers.asc`;
   the image workflow checks that before it builds anything. A
   prerelease need not be signed, so the usual path is an unsigned
   `-rcN` that anyone with push access can tag, then the release signed
   by a maintainer on the same commit once the last rc proves out:
   ```shell
   git tag -s v0.2.0 -m "Sparewall 0.2.0" v0.2.0-rc2^{}
   ```
   To add a maintainer, append their public key (`gpg --armor --export`)
   to `.github/release-signers.asc` in a reviewed pull request.
3. The image workflow runs again for the tag: it rebuilds the image, runs
   every VM suite, publishes the image as `sha-<commit>` (and `testing`),
   then the **release assets** job drafts a GitHub release with:
   - `sparewall-VERSION-x86_64.iso`: the unattended installer (to the
     first fixed disk, if it is blank);
   - `sparewall-VERSION-x86_64.raw.zst` and `.qcow2`: disk images;
   - `sparewall-VERSION-x86_64-linux.tar.gz`: the static CLI;
   - SPDX SBOMs of the image and of the CLI (from the dependency list
     cargo-auditable embeds in the binary);
   - `SHA256SUMS`, signed with the project key
     (`SHA256SUMS.sigstore.json`).

   Files over GitHub's 2 GiB limit are split into `.partNN` pieces;
   `SHA256SUMS` lists each piece and the joined file.
4. Review the draft, edit its notes, and publish it. Publishing runs the
   release workflow: it tags the tested image `VERSION` and, unless it is a
   prerelease, `stable`, so nodes following the stable channel see it.

A failed suite stops at step 3 with no release. Delete the tag, fix
`main`, and tag again.

## Versions

The binaries report the version the build is given in
`SPAREWALL_VERSION` (`.github/version.sh`): on a tag, the tag's, so
`v0.2.0-rc1` builds `sparewall 0.2.0-rc1` whatever `Cargo.toml` says;
between tags, `git describe` from the last one (`0.2.0-rc1-4-gabc1234`).
The release job refuses an image or CLI that reports anything else. A
local `cargo build` reports the `Cargo.toml` version, which is not bumped
per release.
