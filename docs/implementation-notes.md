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
- **The coordinator has its own SELinux domain, `sparewalld_t`,
  permissive for now** (`image/selinux`, installed with `semodule` in
  the image build); permissive means every access is allowed and
  logged. Its state, runtime and temporary files and its units have their
  own types (`sparewalld_var_lib_t`, `sparewalld_var_run_t`,
  `sparewalld_tmp_t`, `sparewalld_unit_file_t`), and the confined daemons
  that read configs from `/run/sparewall` (ulogd, journal-upload,
  conntrackd) get rules for that. tmpfiles relabels `/var/lib/sparewall`
  at boot. Two grants stay generic: running `bin_t` commands, which run
  in `sparewalld_t` under the same rules; and Quadlet's generated units,
  which share one type. The rules are what the VM suites saw it do, and
  the suites fail on any denial by `sparewalld_t` or on its types, so a
  change that needs a new access adds its rule with the code. Enforcing (dropping `permissive`) waits for
  production nodes to log none: the suites do not exercise everything
  (ACME issuance on a node, real hardware).
  `sparewall-run@` runs the same binary but stays `unconfined_service_t`
  (`SELinuxContext=`): it runs what the coordinator's confinement forbids.
- **The installer ISO is bootc-image-builder's `anaconda-iso`**: it
  installs unattended to the first disk, from the image embedded in it,
  with no network. An interactive installer would need a custom Anaconda
  build. The release notes and getting-started say it erases the disk.
  It builds Anaconda from the image's repositories, which it reads from
  `/etc/yum.repos.d`, so the image copies Fedora 45's dnf5 repository
  files there (nodes never run dnf; bootc replaces the whole image).
- **Physical nodes get their identity from a seed stick**: a filesystem
  labelled `SPAREWALL` with `sparewall-identity.yaml` (or `.json`). A udev
  rule starts `sparewall-seed@.service`, which mounts it read-only and
  runs `sparewall init --from`, until an identity is recorded. The
  unattended ISO sets no root password, so the console route
  (`sparewall init`) needs one set by other means. A custom kickstart
  could write the identity too; the release ISO has none.
- **Releases are drafted, then published by a maintainer**
  ([releasing.md](releasing.md)). A `v*` tag reruns every VM suite; the
  draft carries the ISO, raw and qcow2 images, the static (musl) CLI,
  SBOMs and signed checksums. Publishing tags the tested image with the
  version and, unless it is a prerelease, `stable`: promotion is that
  decision, not a separate test run.
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
- **keepalived's health check has a socket of its own**,
  `/run/sparewall/org.sparewall.Health`, served by a second instance of
  the same service. zlink answers one call at a time per server, and some
  admin calls wait on the peer (a sync-link change waits up to 15 s for
  the push reply); behind one of those, the check would time out (5 s,
  three in a row) and keepalived would hand the gateway addresses over.
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

- **Host operations beyond `System` are narrow adapters** in
  `sparewall_core::host`: `Conntrackd`, `BackupRepository` (restic),
  `Timers` (transient systemd timers), `DnsZone` (RFC 2136) and
  `UpgradeHost` (bootc, reboot, keepalived), plus the daemon's
  `UpgradePeer`. Each method is one operation with its own error, not a
  general command runner, and the orchestration (failover, backup, ACME
  challenges, the rolling upgrade) is tested against fakes (#12).
  Reading status (`bootc status`, `bootc upgrade --check`) still calls
  the host directly.
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
- **A generation that never ran gives way.** A local change that fails
  to activate is moved aside (`generations/<id>.failed-<hash>`), out of
  history, and its id is reused. One left by a crash before `state.json`
  named it, or stored as history from the peer, is replaced by the peer's
  generation with that id when the push extends the active generation
  (set aside as `<id>.diverged-<hash>`); otherwise every push of that id
  conflicted until `sync --from` (#24).
- **A state write that fails after activation is reconciled.** The store
  reports whether the new record had replaced the old one before the
  failure. Before the rename, `apply` and a peer push re-activate the
  previous generation, then set the change aside or reject it. After the
  rename (a failed directory sync), they write the previous record back
  and run what is then readable. They keep the generation unless the
  old record was written back cleanly. Tests inject failures with a
  directory at the temporary path and with `Store::inject_sync_faults`
  (#28).
- **Generations are synced before they can be named.**
  `Store::sync_generation` fsyncs a generation's directory and
  `generations/`. It runs after every save, and again before running the
  peer's generation, so a retry over a leftover whose sync failed redoes
  it. Every store write fsyncs its directory after the rename (#28).
- **Equal-version cluster secrets** made independently by both nodes
  (each applied the pairing document) converge on the one created first.
- **Health endpoint detail and `/metrics`** need an API token, except
  `/metrics` when `metrics.mode` is `external`.
- **Roles are not enforced per call yet** (#11). The only client path
  to the coordinator is its root-only socket (directly, or through SSH
  and `sparewall bridge`), and every caller there is admin. API tokens,
  with their roles, are checked only by the HTTPS health and metrics
  endpoints. How token-holding scripts and front ends reach the
  coordinator is decided with the web UI (milestone 7), and per-call role
  checks come with that transport.
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

- **Live firewall verification** records the table right after each load
  (`nft -j`, normalized: no counter values, quota use, `last` timestamps,
  element timeouts, handles, or networkd-filled set elements) and compares
  it on every health check, so drift is caught even when chain names are
  unchanged. It fails closed: if the table cannot be read back right after
  a load, the node is unverified (health failed, no applied hash) until
  the next load records a baseline; health never learns one from the live
  table, which may have drifted by then. The baseline is the kernel's own listing
  after a successful atomic load, not a re-parse of the rendered script,
  because nft canonicalizes expressions. A drifted node reports no applied
  hash, so readiness, VRRP health, pair sync and the upgrade gate all see
  it.

- **Replication-only links degrade, never fail.** The renderer lists the
  sync network's interface, and a port carrying only it, apart from the
  links that carry traffic. keepalived's track script fails only on
  failed health, so losing sync locally (a dedicated port down, the sync
  VLAN deleted) or upstream degrades health and stops replication without
  moving the gateway addresses, as a cut sync link affects both nodes
  equally. A shared trunk carrying service networks still fails health.

- **Sync-link changes go to the peer first, in two phases** (#25).
  - **Staging:** in a pair with the peer reachable, `apply` (and a
    rollback) only stores a change whose cluster sync settings, sync
    network or per-node sync port differ (`ApplyResult::staged`). It
    refuses one made while a change is pending, or one that changes
    anything else.
  - **Push and run:** the daemon pushes it gated through the current
    tunnel (peer protocol 3), then `activate_staged` runs it pending
    with `peer_gate`, plus `needs_admin` if a confirm window was asked
    for.
  - **Reply first:** running the change switches the tunnel the push's
    reply goes through (the pair VM test hung there). So the receiver
    validates a gated sync-link push, replies, and then runs it. A
    failure after the reply is never confirmed, so the pusher reverts.
    That keeps the pusher's wait short on the normal path.
  - **Lost push replies:** a push that was sent but got no reply within
    15 s runs anyway. If the peer took it, it confirms over the new
    link; if not, nothing confirms it and this node reverts at its
    deadline. Only a refusal, or a failure before sending, sets the
    change aside.
  - **Prepare:** the receiver marks a gated push that changes its sync
    link `link_change`. Its `confirm_received` only sets `prepared`:
    from then on the change is in doubt. The pusher's `peer_confirmed`
    and the admin's `confirm` together keep it there.
  - **Record:** every way a `decides_link` change ends (kept by
    `finish_confirm`; reverted at the deadline, at boot or by a
    rollback) writes `State::link_decision` in the same state write.
    Hello shows the record until the peer is seen with nothing pending
    (`peer_followed`). While a sync-link change is pending, apply,
    merge and patch are refused on both nodes. On the decider, confirm
    and rollback stay available (they are how the admin keeps or drops
    the change). On the receiver they are refused too, and `sync --from`
    is the explicit way out.
  - **Durability:** a kept decision whose write fails after the rename
    is written back as pending. If that fails too, `decision_unsure`
    makes Hello report pending with no decision until `tick` manages
    to sync the state directory. Boot syncs it first and sets
    `decision_unsure` if that fails, so a restart does not publish an
    unsynced decision.
  - **Follow:** the in-doubt receiver's sync loop calls
    `resolve_in_doubt` from the record. Without one, it only keeps the
    change if the pusher's lineage has it, and never infers a revert
    from history that may be pruned. Neither `tick` nor `boot` reverts a
    prepared change. Without contact for 30 s, `alternate_in_doubt`
    runs the other link, and the tunnel follows `live_document`.
  - **Not taken:** a staged change the peer does not take, or one
    overtaken by another local change, is set aside as `unsent`.
- **Pushed generations are gated by the pusher's confirmation** (peer
  protocol 2: `Push` with `gated`, then `Confirm` on a new connection).
  The receiver records what already fails before it runs the generation,
  per resource (each required link down, each provider unit inactive,
  each other failed check), and confirms only if nothing else fails, so
  a change that breaks a link it needs is not kept, even beside an older
  fault of the same kind, while one landing on a node with a known fault
  can be. Until confirmed, `applied()` (status, `sparewall_config_applied`,
  the peer view) reports nothing applied, and the `applied` check is
  degraded, not failed: failed would block the confirmation and lower
  VRRP priority. The pusher confirms right after
  pushing and again on each sync pass while the peer reports it waiting,
  so a transient tunnel blip during reconfiguration is retried until the
  deadline (`PEER_CONFIRM_SECONDS`, 120 s, in the persisted state). An
  older peer is pushed ungated and confirms at once, as before.

- **Remote-access VPN failover is measured, not assumed.** The pair test
  connects five clients over the WAN VLAN: an active one with inner TCP
  and UDP flows, an idle one with a session older than 120 s, an idle one
  with a fresh session, an active one behind NAT with
  `PersistentKeepalive`, and an idle one behind NAT sending only
  keepalives. Probing starts the moment the gateway moves (for the
  upgrade, when the CLI reports the handover, with the fresh session
  renewed until then), after checking each idle session's age. Each
  client must recover within 60 s (180 s for the keepalive-only client,
  which waits for its session to reach 120 s) and still have the gateway
  address as its endpoint; the results are in the run's step summary.
  `tests/vm/vpn-check-test.sh` checks the recovery assertions without VMs. Recovery is the client's: the shared
  static key lets the new master accept a handshake, but sessions are not
  synced. The test found that a node handing the address over replied
  from its own address, so an active client roamed to it and was cut off
  for good once it rebooted; the output chain now drops remote-access
  packets from anything but the gateway address.

## Providers

- **One table of providers** (`sparewall_config::providers`), per role:
  name, default, built or not, whether it runs in an HA pair, and the
  state it keeps (Kea's lease database), with where it lives and which
  providers can import it. Validation rejects an unknown provider, one
  that cannot run in a pair, and one not built yet. The renderers choose
  by it. Backups take the lease file from the chosen DHCP provider.
  `apply` warns when a change of provider leaves state behind. With one
  built provider per role, provider-specific status and state
  export/import are not abstracted yet. The VM conformance suite covers
  the built providers (Kea, Unbound).
- **lego runs whole ACME orders**, not just the DNS records: it has no
  command that only publishes a TXT record. So a lego certificate uses
  lego's ACME account, one per node under `/var/lib/sparewall/lego`, not
  the cluster's (built-in RFC 2136 orders share one account through the
  secret store). The coordinator decides when to order (two-thirds of
  the lifetime, as for RFC 2136) and passes `--renew-force`. lego runs in
  its provider image, a logically bound image, through
  `sparewall-run@` (podman is outside the coordinator's sandbox); the
  credentials go in an environment file under `/run/sparewall/lego` that
  exists only while lego runs. Provider codes are checked for form only;
  lego rejects an unknown one when it runs.

## Release gates

The two-node suite that gates promotion to `stable` (design: "Testing")
runs as two CI jobs, each booting its own pair: `pair-test.sh` (build,
boot, publish) and `pair-faults.sh` (pair faults).

| Gate | Where | State |
| --- | --- | --- |
| Kill the master: gateway, flow and lease survive | pair-test | Tested |
| Cut only the sync VLAN; divergence and `sync --from` | pair-test | Tested |
| Lose a replication-only link on the master | pair-test | Tested |
| Move the sync link, kept and reverted | pair-test | Tested |
| VPN clients reconnect across failover and upgrade | pair-test | Tested |
| Rolling upgrade, unsigned image refused | pair-test | Tested, to a derived image of the same build |
| Flap a bond member on the master | pair-faults | Tested |
| The master loses its whole trunk | pair-faults | Tested |
| Cut one service VLAN on one side | pair-faults | Recorded, not asserted: see below |
| Destroy both nodes, restore from bundles, re-pair | pair-faults | Tested |
| Rolling upgrade from the previous release | | Outstanding: needs a first release |
| Schema upgrade and downgrade, mixed versions | | Outstanding: needs schema 2 |

**A service VLAN cut on the master's side only** leaves the roles where
they are: keepalived's sync group keeps every instance BACKUP on the
other node while it hears the master on the remaining VLANs, so nothing
flaps, but the cut network has no gateway until the cut is mended. Each
node's own links are up, so health cannot see it. Detecting it (each
node probing the peer on every service VLAN over the sync tunnel, and a
rule for which side gives up) is outstanding.

## Not built yet

- ACME `http-01`.
- Alternative providers: networkd's DHCP server (`dhcp.provider:
  networkd`) and syslog forwarding (`logging.remote.provider: syslog`).
  Earlier versions accepted them and then rendered nothing, silently
  turning DHCP or log forwarding off; validation now rejects them as
  not built yet (#10).
- Schema migrations (only schema 1 exists); the Web UI.
- The coordinator's SELinux domain enforcing; benchmarks.
- A local Prometheus (`metrics.mode: local`, `metrics.retention`),
  scheduled upgrades (`updates.mode: windowed`, `updates.window`) and
  provider passthrough (`provider_options`). The schema keeps their
  fields, and validation rejects them with an error at their path, so a
  document never shows a setting that has no effect.
