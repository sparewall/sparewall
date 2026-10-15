# Releasing

For maintainers. A release is a tested commit on `main`, tagged.

1. Pick a commit on `main` whose image workflow passed (build, boot,
   publish; pair faults; offline install).
2. Tag it and push the tag:
   ```shell
   git tag -s v0.1.0 -m "Sparewall 0.1.0"
   git push origin v0.1.0
   ```
   A tag with a hyphen (`v0.2.0-rc1`) is a prerelease.
3. The image workflow runs again for the tag: it rebuilds the image, runs
   every VM suite, publishes the image as `sha-<commit>` (and `testing`),
   then the **release assets** job drafts a GitHub release with:
   - `sparewall-VERSION-x86_64.iso`: the unattended installer (it erases
     the first fixed disk);
   - `sparewall-VERSION-x86_64.raw.zst` and `.qcow2`: disk images;
   - `sparewall-VERSION-x86_64-linux.tar.gz`: the static CLI;
   - SPDX SBOMs of the image and of the CLI (from the dependency list
     cargo-auditable embeds in the binary);
   - `SHA256SUMS`, signed with the project key
     (`SHA256SUMS.sigstore.json`).

   Files over GitHub's 2 GiB limit are split into `.partNN` pieces.
4. Review the draft, edit its notes, and publish it. Publishing runs the
   release workflow: it tags the tested image `VERSION` and, unless it is a
   prerelease, `stable`, so nodes following the stable channel see it.

A failed suite stops at step 3 with no release. Delete the tag, fix
`main`, and tag again.
