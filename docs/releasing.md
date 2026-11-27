# Releasing

For maintainers. A release is a tested commit on `main`, tagged; a
backport to an older series is one on its release branch (see
[Release branches](#release-branches)).

1. Pick a commit on `main` whose image workflow passed (build, boot,
   publish; pair faults; offline install).
2. Tag it and push the tag:
   ```shell
   git tag -s v0.1.0 -m "Sparewall 0.1.0"
   git push origin v0.1.0
   ```
   A tag with a hyphen (`v0.2.0-rc1`) is a prerelease. Before it builds
   anything, the image workflow checks that the tag's commit is on a
   branch whose rules require a pull request and refuse a force push
   (`main`, or a `release/X.Y` branch: the repository's ruleset covers
   both, and the check asks GitHub for the rules in force), and that a
   release tag (no hyphen) is signed with a GPG key on
   the GitHub account of one of the repository's maintainers: whoever has
   the maintain or admin role, directly or through a team. The account is
   the tagger's, the one GitHub matches to the tag's email (so tag with an
   email verified on your account). The roles are the only list of who
   may release: give someone the role, and their key counts; take it
   away, and it stops. The keys are fetched from GitHub
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
   push, that is enough. Before giving push access to anyone else, add a
   tag ruleset limiting who may create `v*` tags, and move the signing
   key into a `release` environment that needs a maintainer's approval.
3. The image workflow runs again for the tag: it rebuilds the image, runs
   every VM suite, including upgrades to it from earlier releases
   (`tests/vm/upgrade-test.sh`, from the releases
   `.github/upgrade-from.sh` names, see [operations](operations.md#upgrades)), publishes the image as `sha-<commit>` (only `main`'s own builds move `testing`, and only once every suite has passed),
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
   It looks up the build's `sha-<commit>` tag once, then checks the
   signature on that digest and copies the digest, not the tag, so a
   moved tag can't publish an image whose signature wasn't checked. A
   rebuild's promotion does the same, and the release-assets job checks
   the digest it pulled before building the media.
   `stable` only moves forward: a backport published after a newer
   release leaves it, the Homebrew tap and GitHub's "Latest" release with
   the newer one.
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

## Release branches

New work always lands on `main`. A series gets a branch only when it
needs a patch release after `main` has moved on to the next minor
version: until then, a patch release is tagged on `main` as usual.

1. Cut the branch from the series' last release tag, and push it:
   ```shell
   git push origin v0.6.0^{commit}:refs/heads/release/0.6
   ```
   The repository's ruleset covers `release/*` as it does `main`: pull
   requests with the same required checks, no force push, no deletion.
   CI and the image workflow run on pushes to it as on `main`, except
   that its builds never move `testing`.
2. Fix the bug on `main` first, by the usual pull request. Then
   cherry-pick the merged commit onto a branch from `release/0.6`, and
   open a pull request into `release/0.6`:
   ```shell
   git switch -c backport-1234 origin/release/0.6
   git cherry-pick -x <commit on main>
   ```
   A fix that only applies to the old series (the code on `main` has
   changed too much) goes to the release branch directly, and the pull
   request says why.
3. Tag the release on the branch, as in [the steps above](#releasing):
   an `-rcN` first, then the signed release on the same commit. The tag
   check accepts a commit on any branch the ruleset covers. The upgrade
   suites test it from the newest earlier release and the newest of the
   previous series (`.github/upgrade-from.sh`).

A patch release carries bug fixes only. It never adds a schema revision
(`x-since`): revisions are numbered on `main`, and one added in a patch
would clash with the next minor's and break upgrades from it.

Until 1.0, only the newest series gets patch releases: once 0.7.0 is
out, nodes on `stable` move to it, and a 0.6.x after that only reaches
nodes that stay on 0.6 by choice.

## Dependency updates

[Renovate](https://docs.renovatebot.com/) (`renovate.json`, the Renovate
GitHub App) proposes every update, so none waits on someone
remembering. The Dependency Dashboard issue lists what it found and
what's waiting.

- **When:** Mondays before 06:00 UTC, at most 8 open pull requests and
  2 new ones an hour. Security fixes (GitHub's advisories and OSV) are
  opened at once, whatever the day.
- **Waiting:** a new release of an npm package, crate or action waits
  3 days before it's proposed, so one pulled for a bad release never
  arrives. Security fixes don't wait.
- **Merging itself:** minor, patch and digest updates merge themselves
  (squash) once every check on the pull request has passed. So does the
  weekly lock file refresh. CI runs on every pull request. The VM suites
  (`image.yml`) run when it touches what the image is built from: the
  crates and `Cargo.*`, the Containerfiles, `ui/package.json` and its
  lock file, and `image.yml` itself. An update to a workflow that
  never runs on a pull request (`release.yml`, `rebuild.yml`,
  `resign.yml`) has nothing to check it, so it waits for review, with
  the rest of its group. A failing update stays open for someone to fix.
- **Groups:** the Rust crates, the web UI's npm packages and the GitHub
  Actions (with the Renovate release CI checks this file with) each go
  in one pull request. The Rust toolchain and the bootc-image-builder
  digest (`image/bib/Containerfile`) get their own.
- **Major updates** open a pull request each, never merged by
  Renovate. TypeScript is the exception: Angular names the releases it
  supports, so a new major waits for approval on the dashboard.
- **Node.js** in CI is left alone: it's the major that Fedora builds the
  UI with in the image, and it moves with Fedora.
- **Fedora.** Within a release, the base images (`fedora-bootc:45`,
  `fedora:45`, `fedora-minimal:45`) float on purpose: the monthly
  rebuild tracks them, below. A new release comes from Bodhi's release
  list, and only once Bodhi marks it `current` (stable), never while
  it's branched, in beta or Rawhide. It arrives as one pull request
  that changes every Containerfile and the base images `image.yml`
  records. It's a major OS upgrade: it goes through every VM suite and
  is merged by hand.
- **ulogd and libnetfilter_log** are built from netfilter.org's
  tarballs in `image/Containerfile` (Fedora doesn't package ulogd, and
  has too old a libnetfilter_log). Renovate follows their git tags and
  bumps the `_VERSION` ARG, but it can't compute the tarball's checksum.
  Update the matching `_SHA256` ARG by hand, from the release's tarball
  (check its signature); until then the build fails at `sha256sum -c`,
  by design. No advisory database covers them, so before a release,
  still check netfilter.org and the CVE lists for both. A fix ships in a release, not a rebuild, since a rebuild
  builds the same source. Both are in the image's SBOM
  (`.github/sbom-source-builds.sh`), and their license texts are in
  `/usr/share/licenses`.
- **Checked:** CI runs `renovate-config-validator` on any change to
  `renovate.json`, since Renovate reads the file from `main` and stops
  every update, without failing anything here, if it can't.

Dependabot's version updates are off; its security alerts stay on.

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
between tags, a prerelease of the next version, from `git describe`
(`0.3.2-dev.4+gabc123456789` four commits after `v0.3.1`), so builds
sort as semver says. Once a series has a release branch, `main` builds
the next minor's (`0.7.0-dev.N` after `v0.6.0`, with `release/0.6`
cut), and the branch, or a pull request into it, the next patch's.
The release job refuses an image or CLI that reports anything else. A
local `cargo build` reports the `Cargo.toml` version, which is not bumped
per release.

## Rebuilds

A release's image is built once, from its tag, on whatever the floating
Fedora base images (`fedora-bootc:45`, `fedora:45`, `fedora-minimal:45`)
were that day; each image records the base digests it was built on
(`org.sparewall.base.bootc`, `.fedora`, `.minimal`). Security fixes reach
`stable` between releases by a rebuild (#187): the same source on newer
base images. A code change is a patch release, never a rebuild.

**Deciding.** `rebuild.yml` runs every Monday (and by hand, with
`force` or `dry_run`). It takes the newest release, checks that `stable`
is that release or a rebuild of it, and rebuilds it when the `stable`
image has a security advisory pending (`dnf advisory list --security`
inside it), or when it was built 30 or more days ago. Its summary says
which, and why. Scheduled runs act only while the repository variable
`REBUILDS` is `on`.

**Building.** It dispatches `image.yml` on the release's tag with
`rebuild=N`, which:

- checks the tag as for a release, against the maintainers' keys: the
  bot that dispatches it signs nothing, and the tag's signature is what
  counts. `rebuild.yml` checks it first with the current `check-tag.sh`,
  since `image.yml` runs as it was at the tag;
- builds `X.Y.Z+rN` (`sparewall --version` and `org.sparewall.version`):
  semver build metadata, so a node compares it as the same version and
  offers it as a rebuild when its digest differs;
- pushes it under its own immutable tags, `X.Y.Z_rN` (OCI tags cannot
  hold `+`) and providers' `sha-<commit>-rN`, never `testing`;
- runs every suite, with an upgrade from the release's own disk image
  besides the usual ones;
- only then moves `X.Y.Z`, and `stable` while it still is this release,
  to the rebuild, signed by CI as every image is, and adds a line under
  **Rebuilds** in the release's notes: the date, the digest, and the
  advisories it picks up.

The release's media (ISO, disk images, CLI) are not rebuilt: a fresh
install from them is offered the rebuild by `sparewall upgrade`. A rebuild
runs `image.yml` as it was at the tag, so only releases tagged after
#226 can be rebuilt (0.4.0 and 0.5.0 checked their tags against a list of
signers, since replaced by the roles); for an earlier one, the decision
says so.
