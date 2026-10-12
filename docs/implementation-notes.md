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
- **Providers order after `sparewall-early.service`, not sparewalld.**
  sparewalld starts them during its own start-up activation, so ordering
  them after sparewalld deadlocked a reboot of a configured node. Early
  boot installs their configuration; at start-up sparewalld queues the
  starts (`--no-block`) rather than waiting on them.
- **The containers signature policy defaults to `reject`.** bootc's
  `--enforce-container-sigpolicy`, which upgrades use, refuses a policy
  whose default accepts anything. `ghcr.io/sparewall` requires the
  project's signature and local transports are open.
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
- **Rollback creates a generation** holding the target's document, on top
  of the active one, so the rolled-back generation stays in history and a
  peer receives the rollback as an ordinary change. Reactivating the old
  generation made the node look behind its peer, which pushed the newer
  generation straight back (#4). Discarding an unconfirmed change is the
  exception: it never left the node, so `rollback` (and a missed confirm
  window) just returns to its revert target, without the peer. Whether a
  request is only that discard is decided under the same coordinator lock
  as the rollback, so a confirm window expiring or a confirmation in
  between cannot turn it into an ungated new generation.
- **Catching up pushes history, runs only the newest.** A peer behind by
  several generations stores the earlier ones (`Push` with
  `activate: false`) and runs only the last, so after a change and its
  rollback it never runs the rolled-back configuration. Equal content does
  not mean in sync when one history contains the other: the peer would
  otherwise miss those generations and its next change would look like
  divergence. Older peers ignore `activate` and run each generation.
- **The peer link** uses Varlink over TCP on the sync-tunnel address,
  spliced onto a root-only Unix socket (zlink has only Unix transports).
  The peer methods trust the connection, not `Hello`'s node name, so the
  connection is what is authenticated, in three independent layers: the
  listener is bound to `swsync` (`SO_BINDTODEVICE`), so the kernel
  delivers only connections that arrived through WireGuard (the binding
  is to an interface index, so the listener rebinds when networkd
  recreates `swsync`, as it does for a new sync key); it accepts
  only the peer's tunnel address as the source (WireGuard admits that
  address only from the peer's key, and the client binds its own tunnel
  address to match); and the first input rule drops anything for the
  tunnel subnet arriving on another interface, ahead of conntrack state,
  zone policy and raw rules, while the forward chain routes nothing into
  or out of the tunnel. No zone-to-self policy can open it.
- **Equal-version cluster secrets** made independently by both nodes
  (each applied the pairing document) converge on the one created first.
- **Health endpoint detail and `/metrics`** need an API token, except
  `/metrics` when `metrics.mode` is `external`.
- **DHCP takeover is driven by VRRP.** Kea's hot-standby standby declares
  its partner down only after `max-unacked-clients` (5) distinct clients
  go unanswered, which a small network may never produce. When a node is
  the VRRP master and the peer is unreachable over the sync tunnel for
  15 seconds, the coordinator has its Kea serve the primary's scope
  (`ha-scopes`). A cut sync VLAN alone leaves the VRRP roles in place
  (adverts run on the client VLANs), so it cannot split the pool.
- **Backups seal secrets with the backup password** (Argon2id and
  ChaCha20-Poly1305) rather than relying on restic's encryption alone, so
  a bundle on the node's disk or copied by hand is no weaker than one in
  the repository. The restic upload runs inside sparewalld's sandbox; the
  timer is a transient unit recreated at start, so no unit file follows
  the schedule.
- **`systemd-creds setup` runs before the sandbox** (`ExecStartPre=+`):
  the host credential key lives under `/var/lib/systemd`, which the
  sandboxed coordinator cannot create on first use.

## Not built yet

- ACME `http-01` and lego-based DNS providers (RFC 2136 is built in).
- Schema migrations (only schema 1 exists); the Web UI.
- The SELinux policy module for the coordinator, benchmarks.
