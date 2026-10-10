# Implementation notes

Where the implementation departs from, or settles open questions in,
[design.md](design.md). Each entry says why.

## Platform

- **Fedora 45 bootc.** The design names Fedora bootc with systemd 261+;
  Fedora 45 ships systemd 262, Kea 3.2.0 and keepalived 2.3.4.
- **Provider images are built from Fedora packages** (`image/providers/`)
  rather than ISC's images: ISC publishes no Kea 3.2 images (a "to prove"
  item). So the default Kea is 3.2, not 3.0 LTS; 3.2's interface handling
  is what the design wanted to fall back to anyway.
- **Bound provider images are pinned by an immutable per-commit tag**
  (`ghcr.io/sparewall/kea:sha-<commit>`), not by digest: `bootc install`
  cannot copy a digest-referenced logically bound image from host storage
  ("would require changing layer representation"). Signatures are still
  verified on the digest by the containers policy.
- **Fedora base images are used by tag, not digest.** quay.io/fedora
  publishes no dated tags and prunes a superseded `:45` manifest within
  about a day, so digest pins broke CI within a day of being set. Builds
  record the digests they used in the CI run summary, and the SBOM lists
  every package. bootc-image-builder, whose digests are retained, stays
  pinned.
- **ulogd2 is built from source** in an image stage (Fedora 45 does not
  package it), with libnetfilter_log 1.0.2 linked statically because
  Fedora has 1.0.1. node_exporter is likewise not packaged and not yet
  included.
- **Confined daemons read their configs from their own runtime
  directories** (`/run/chrony`, `/run/keepalived`), which carry their
  SELinux labels; everything else is under `/run/sparewall/<subsystem>`.
- **SELinux stays enforcing**, and confined daemons get files they may
  read: networkd's WireGuard keys are copies in `/run/systemd/network`
  (masters stay root-only under `/var/lib/sparewall`); conntrackd's
  configuration is relabelled `conntrackd_conf_t`; keepalived's health
  check and notify scripts live in `/usr/libexec/keepalived` (where they run
  unconfined), and transitions reach the coordinator through a FIFO the
  notify script writes, since keepalived itself may not use notify_fifo.
- **Commands the coordinator's sandbox forbids** (podman config checks,
  the keepalived netns check, bootc) run as the oneshot unit
  `sparewall-run@<id>.service`; `systemd-run` from inside the sandbox fails.
- **Bound images** are reached with
  `--storage-opt=additionalimagestore=/usr/lib/bootc/storage` per podman
  invocation (Quadlet `GlobalArgs=`): a global storage setting breaks
  `bootc install`.
- **Admin SSH keys** are written to `~admin/.ssh/authorized_keys`: with
  SELinux enforcing, sshd cannot read keys under `/var/lib`. The `admin`
  account has passwordless sudo; root cannot log in over SSH.

## Coordinator

- **networkd is driven with `networkctl`** (`reload`, `reconfigure`,
  `delete`) and `udevadm` rather than the Varlink link methods; the
  behaviour is the same and the Varlink calls can replace them later.
- **Forwarding is set with sysctl** (`net.ipv4.conf.all.forwarding`), not
  `IPv4Forwarding=` in networkd.conf, so bootstrap mode can turn it off.
- **nft reloads** use a prelude computed from the live table that flushes
  and deletes coordinator-owned chains and sets, except sets networkd
  fills, in the same transaction as the new table body. A test against the
  kernel shows networkd's elements survive a reload (a "to prove" item).
- **Config checks that need runtime state** run against a variant: Kea's
  test listens on all interfaces and keepalived's runs in a private netns
  with dummy links of the same names, because both reject interfaces that
  only appear once the change is applied.
- **Rollback reactivates an existing generation** rather than creating a
  new one; `history` shows each generation once.
- **The peer link** uses Varlink over TCP on the sync-tunnel address,
  spliced onto a root-only Unix socket (zlink has only Unix transports).
- **Equal-version cluster secrets** made independently by both nodes
  (each applied the pairing document) converge on the one created first.
- **Health endpoint detail and `/metrics`** need an API token, except
  `/metrics` when `metrics.mode` is `external`.

## Not built yet

- ACME `http-01` and lego-based DNS providers (RFC 2136 is built in).
- Schema migrations (only schema 1 exists); the Web UI.
- The SELinux policy module for the coordinator, benchmarks.
