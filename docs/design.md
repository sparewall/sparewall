# Sparewall — Design

Oct 9, 2026 · @Steven Pritchard

Sparewall is an open-source, image-based Linux firewall: a single node or an HA pair, configured from one versioned document, built from systemd, nftables and a small Rust coordinator.

## Overview

Sparewall turns a Linux box or VM into a firewall appliance that is upgraded and rolled back as a whole image, configured from one document, and run either standalone or as an active/standby pair. It targets homelabs and small offices first, without anything in its defaults or schema that is specific to one site.

### Goals

- **Image-based and rollback-safe.** The OS is a signed, versioned image; an upgrade is a reboot into the new image, and a rollback is a reboot into the old one.
- **One source of truth.** A single JSON/YAML document describes the whole deployment. Every change is validated, applied atomically, and reverted automatically unless confirmed.
- **HA when wanted, not required.** The same image and document shape run one node or an HA pair; growing from one to two nodes is invisible to clients.
- **Portable.** Runs on VMs and physical hardware, with one NIC or several, VLAN trunks, LACP or active-backup bonds.
- **Built from standard parts.** systemd (networkd, Varlink), nftables, keepalived, conntrackd, WireGuard, Podman; the only new code is the coordinator and its CLI.
- **Entirely open source,** including everything the project builds.
- **Swappable services.** DHCP, DNS, certificate issuance, log forwarding, metrics and backup are pluggable providers behind an implementation-neutral schema.

### Scope of the first releases

| In scope | Later |
| --- | --- |
| Standalone node or HA pair (active/standby) | More than two nodes, active-active |
| VLANs, LACP and active-backup bonds, VM or physical ports |  |
| One WAN | Multiple WANs, WAN failover, load balancing |
| IPv4 routing, NAT and DHCP; IPv6 link-local only | IPv6 routing: SLAAC and RA, prefix delegation, DHCPv6 |
| Zone-based firewall with raw nftables rules | IPsec, captive portal, multi-tenancy |
| WireGuard remote-access VPN | Site-to-site beyond static WireGuard peers |
| Optional recursive DNS (Unbound), NTP, logging, metrics, health endpoints | DHCP-to-DNS updates (DDNS), IDS/IPS (Suricata), dynamic routing (BGP, OSPF) |
| `sparewall` CLI and the Varlink API | Web UI and HTTP API |

### Design principles

1. **The coordinator is the only writer** of daemon configuration; people and tools change the document, never the files.
2. **Kernel-adjacent daemons on the host, applications in containers.** nftables, keepalived, conntrackd and networkd run on the host; Kea, the resolver and other application services run as Podman Quadlet containers.
3. **Every change can be undone:** configuration generations with confirm-or-revert, and image deployments with `bootc rollback`.
4. **Secure by default, debuggable with standard tools:** one network namespace for the data plane, systemd sandboxing for management services, SELinux enforcing.
5. **Intent over implementation:** the document says what a service must do; providers decide how a particular daemon does it.

## Architecture

Each node has four layers: a read-only bootc image, host services that touch kernel networking state, containers for application services, and one coordinator that is the only writer of their configuration.

&#91;embedded content: node architecture · 4 layers, one coordinator\]

Clients hand the coordinator a document; it renders, tests, applies and, if unconfirmed, reverts every layer together. In a pair, the second node is identical and is reached only through a WireGuard tunnel on the sync VLAN.

## Platform: a bootc image

Sparewall ships as a bootable container image built from a Containerfile on a Fedora bootc base. Nodes `bootc upgrade` to new images and `bootc rollback` to old ones; nothing is installed on a running node.

### Base OS path

- **Now: Fedora bootc.** It carries systemd 261+ (Fedora 45 is getting 262), whose Varlink interfaces the coordinator depends on, with `systemd-networkd` as an ordinary subpackage.
- **Next: CentOS Stream 10 bootc** with the CentOS Hyperscale SIG's systemd rebuilds (261.3 at the time of writing), tested in CI as a second image variant.
- **Long term: CentOS Stream 11 or AlmaLinux 11 bootc** once they are released, for a longer support window. Each move is a `FROM` change plus package-name fixes, then `bootc switch` on each node in the normal rolling-upgrade order.
- Stock Fedora CoreOS is not used: it ships NetworkManager and deliberately omits systemd-networkd.

### Filesystem semantics

| Path | Behaviour | Holds |
| --- | --- | --- |
| `/usr` | Read-only, versioned with the image | OS, daemons, coordinator, Quadlet units, pinned container image references |
| `/etc` | Mutable with a 3-way merge on upgrade by default; Sparewall aims to make it transient once identity provisioning is proven | Nothing site-specific long term |
| `/var` | Persistent, shared across deployments | Configuration generations, secrets, leases, container storage, logs |
| `/run` | Volatile, rebuilt every boot | Daemon configs rendered by the coordinator |

### Image contents

`systemd-networkd`, `nftables`, `keepalived`, `conntrack-tools`, `chrony`, `ulogd2`, `podman`, `wireguard-tools`, `restic`, the coordinator (`sparewalld`) and CLI (`sparewall`), Quadlet units for the containerized services with their images pinned by digest, troubleshooting tools (`tcpdump`, `conntrack`, `ethtool`, `nft`, `wg`), and a built-in bootstrap configuration that keeps a management interface reachable before any config has been applied.

## Deployment targets and the port model

The same image and the same config document run on a VM fed a VLAN trunk, a single-NIC mini PC, or a multi-NIC box with bonds, including a mixed pair of one VM and one physical node. The document makes this possible by separating **ports** (physical, per node) from **networks** (logical, shared); zones, gateway addresses, DHCP and policy only ever reference networks.

- A **port** is a per-node role name (`uplink`, `wan`, `mgmt`) bound to hardware: one NIC matched by permanent MAC or PCI path, or a bond of several NICs.
- A **network** is one L2 segment: a port role, an optional VLAN ID, per-node addresses, and (in a pair) a gateway address (`vip`) and VRRP ID. Management and sync are networks with a role.
- Because networks reference port *roles*, `uplink` can be a virtio trunk on one node and an LACP bond on the other.

```yaml
ports:
  fw1:
    uplink: { nic: "52:54:00:aa:00:01" }
  fw2:
    uplink: { bond: { members: ["9c:6b:00:00:00:01", "9c:6b:00:00:00:02"], mode: 802.3ad } }
networks:
  wan:   { port: uplink, vlan: 10, role: wan,
           addresses: { fw1: 203.0.113.2/29, fw2: 203.0.113.3/29 }, vip: 203.0.113.1/29, vrid: 10 }
  users: { port: uplink, vlan: 20,
           addresses: { fw1: 192.0.2.2/24, fw2: 192.0.2.3/24 }, vip: 192.0.2.1/24, vrid: 20 }
  sync:  { port: uplink, vlan: 4000, role: sync,
           addresses: { fw1: 10.255.0.1/30, fw2: 10.255.0.2/30 } }
```

### Port shapes

| Shape | Rendered as | Notes |
| --- | --- | --- |
| Single NIC, untagged | `.link` (stable name) + `.network` | One network per NIC |
| Single NIC, VLAN trunk | NIC `.network` with `VLAN=`, one VLAN `.netdev` and `.network` per network | Typical for VMs and one-port mini PCs |
| Bond, LACP | Bond `.netdev` with `Mode=802.3ad`, `LACPTransmitRate=`, `TransmitHashPolicy=`, `MIIMonitorSec=`; members join with `Bond=` | Switch needs a matching LAG; VLANs stack on the bond |
| Bond, active-backup | Same with `Mode=active-backup`, optional `PrimarySlave=` | No switch configuration |
| Several independent NICs | One `.link`/`.network` per NIC, each its own port role | For example `wan` on its own NIC |

MTU (parent and VLAN) and NIC offload overrides are per port.

### On libvirt with Open vSwitch

- Give each VM a fixed MAC in its domain XML so port matching stays stable.
- Pass VLANs as a trunk on one virtio interface (OVS `vlan_mode=trunk` with an explicit `trunks` list), with virtio multiqueue enabled.
- Do not apply libvirt's `clean-traffic` nwfilter: it blocks the extra MACs and addresses that gateway addresses need.
- VRRP adverts use link-local multicast, which OVS floods; switch instances to `unicast_peer` if anything in the path filters it.
- PCI passthrough or SR-IOV remain options where virtio becomes the bottleneck.

### Mixed pairs

Give the larger node the higher VRRP priority and keep `nopreempt`, so the pair does not bounce when that node flaps. Size connection tracking, Kea and nft sets for the smaller node, since it must carry the full load after a failover.

## The configuration document

One versioned document describes a whole deployment, one node or a pair, and the coordinator is the only thing that turns it into daemon configuration. It is JSON on the wire and accepted or emitted as JSON or YAML; a JSON Schema shipped in the image validates it.

### Conventions

- **One document per deployment.** Shared values appear once; per-node values are keyed by node name (`addresses: { fw1: …, fw2: … }`).
- **Collections of named things are maps keyed by name**, never arrays: zones, networks, policies, rules, raw entries, VPN peers, DHCP reservations. Adding one item is then a one-entry merge.
- **Explicit order where order matters.** Rules within a zone pair and raw entries at one hook carry an `order` number with gaps (100, 200, …), so a new entry can be inserted without renumbering.
- **Arrays only for value lists** where replacing the whole list is expected: bond members, a network's addresses, DNS servers.
- **No secrets in the document.** Secrets are referenced by name (`secret:dns-tsig`) and live in the coordinator's secret store.
- **Types come from the schema**, never from YAML guessing; parsers are YAML 1.2.
- **Canonical form.** Exported documents use a fixed key order and formatting, so files in git diff cleanly and the content hash is stable.

### Schema reference (top level)

| Key | Holds | Per node? |
| --- | --- | --- |
| `schema` | Integer schema version | No |
| `cluster` | Node names (one or two), VRRP timing, which network carries sync | No |
| `management` | Which network is management; anti-lockout switch | No |
| `ports` | Per node: port role → NIC (MAC or PCI path) or bond (members, mode, LACP options); MTU; offload overrides | Yes |
| `networks` | Name → port role, VLAN, role (`wan`, `management`, `sync`, service), addresses, `vip`, `vrid`, MTU, WAN DHCP client | Addresses per node |
| `zones` | Name → member networks; `self` is built in | No |
| `objects` | Named address and port sets; dynamic sets filled by networkd | No |
| `policy` | `"from->to"` → default action, NAT mode, `rules` (named, ordered) | No |
| `forwards` | Named inbound port forwards (DNAT) | No |
| `raw` | Named raw nft statements with a hook point and order | No |
| `dhcp` | Per network: pools, reservations, options, lease time; provider; HA mode | No |
| `dns` | Enabled flag, provider, listening networks, forwarders or recursion, local records | No |
| `ntp` | Upstream servers; networks to serve time on | No |
| `vpn` | Remote-access WireGuard instances and their peers | No |
| `tls` | Certificates: names, ACME settings, DNS-01 provider | No |
| `logging` | Rule-log defaults; remote forwarding target | No |
| `metrics` | Mode: external scrape, local Prometheus, or off; retention | No |
| `backup` | Enabled flag, restic repository, schedule, credentials reference | No |
| `updates` | Channel, mode (manual or windowed), maintenance window | No |
| `provider_options` | Per-provider passthrough settings | No |

Users, API tokens and secrets are coordinator state, not document content.

### A minimal document

```yaml
schema: 1
cluster: { nodes: [fw1, fw2], sync_network: sync }
management: { network: mgmt }
zones:
  wan:   { networks: [wan] }
  users: { networks: [users] }
policy:
  users->wan: { action: accept, nat: masquerade }
  wan->self:
    action: drop
    rules:
      ssh-admin: { order: 100, proto: tcp, dport: 22, src: "@admin_nets", action: accept }
dhcp:
  users: { pool: 192.0.2.100-192.0.2.199, reservations: {} }
dns: { enabled: true, provider: unbound }
```

(`ports` and `networks` as in the previous section.)

## Configuration lifecycle

Every change, whether a full document or a one-line `set`, becomes a numbered **generation** that is validated, rendered, applied as a unit, and automatically reverted unless confirmed. In a pair, the coordinator then pushes it to the peer and tracks whether both nodes hold and run the same configuration.

### Apply, confirm, roll back

1. **Validate:** the JSON Schema, then semantic checks (overlapping subnets, reused VRIDs, rules naming missing zones, pools outside their subnet, capabilities the chosen providers lack).
2. **Render** generation N into `/var/lib/sparewall/generations/N/`: networkd files, the nft script, keepalived and conntrackd configs, provider configs, WireGuard configs.
3. **Dry-run** every artifact with its own checker: `nft -c -f`, the DHCP provider's config test, `keepalived --config-test`.
4. **Activate** by pointing the live paths under `/run` at N, then reload only what changed: per-link networkd reconfigure, one nft transaction, provider reloads, keepalived reload.
5. **Confirm window:** unless `Confirm(N)` arrives within the requested time, the coordinator re-activates N−1. A change that cuts off management access therefore reverts itself.
6. **Peer:** after local confirmation, the generation is pushed to the peer through the sync tunnel and goes through the same steps there. During upgrades the BACKUP node is changed first.

Generations are kept on disk with their author, timestamp and diff summary; `sparewall history` lists them and `sparewall rollback N` returns to one. A rollback is itself a new generation carrying generation N's document, so the generation it replaces stays in history and, in a pair, the rollback is pushed to the peer like any other change (a change still in its confirm window is simply discarded, since it was never pushed).

### What a generation carries

- **`id`:** a number that increases across the pair, assigned by the node that accepted the change.
- **`hash`:** SHA-256 of the canonical document, so equal content always hashes equal.
- **`base`:** the generation it was derived from. Every change, and every push to the peer, is rejected if `base` is no longer current, so nobody overwrites a change they have not seen.
- **`schema`:** the schema version it was written in.

### Pair sync states

Each node reports a **desired** hash (the confirmed generation it holds) and an **applied** hash (what its daemons are verified to be running).

| State | Condition | Meaning |
| --- | --- | --- |
| In sync | All four hashes equal, and neither node's history is missing the other's generations | Both nodes hold and run the same config |
| Applying | Desired equal, an applied hash differs, apply in progress | Normal for seconds after a change |
| Apply failed | Desired ≠ applied on a node after the apply finished | That node runs older config; alert |
| Behind | The peer's generation is an ancestor of the local one (even with equal content: after a change and its rollback, the peer still lacks both) | Push pending; retried automatically. Generations before the last are stored without being run |
| Diverged | Desired hashes differ and neither descends from the other | Changes were made on both sides; needs a decision |

### Divergence policy

- With the peer reachable, a change on either node is accepted and pushed at once.
- With the peer unreachable, a change requires `--allow-diverge` and marks the pair diverged.
- Nothing merges automatically. An admin resolves divergence with `sparewall sync --from <node>`; the other side's generation stays in history.

Lease replication, connection-state sync and the OS image version are reported separately and never count toward config sync; differing images are expected midway through a rolling upgrade.

## The coordinator and its Varlink API

`sparewalld` is a Rust daemon that owns the configuration document, renders and applies it, coordinates with the peer, and exposes everything over Varlink. It talks Varlink to systemd where systemd offers it, and uses small adapters for daemons that do not.

### What systemd exposes over Varlink

| Interface | Used for | Since |
| --- | --- | --- |
| `io.systemd.Network` | Describe links; reconfigure, renew or force-renew one link | Describe 257; link methods 261 |
| `io.systemd.Unit`, `io.systemd.Manager` | Unit status, transient units, reboot and soft-reboot | 261 |
| `io.systemd.Job` | List and cancel queued jobs | 261 |
| `io.systemd.Resolve`, `io.systemd.Resolve.Monitor` | Host-side lookups, DNS configuration events | Earlier releases |

### Adapters for everything else

| Component | Native control surface | The adapter |
| --- | --- | --- |
| nftables | `nft -f` scripts, `nft -j` JSON | Loads generated scripts; reads counters and set contents |
| keepalived | `notify_fifo`, D-Bus, signals | Turns FIFO lines into events; triggers reloads |
| conntrackd | Its control socket via the `conntrackd` CLI | Runs the failover sequence; reads statistics |
| Providers (Kea, Unbound, …) | Each daemon's own control interface | Implemented per provider (see Service providers) |
| WireGuard | Netlink | Reads per-peer handshake and traffic |

Adapters shell out to `nft` and `conntrackd` rather than reimplementing their netlink protocols, keeping low-level code in well-tested tools.

### Implementation

- Rust, using [zlink](https://github.com/z-galaxy/zlink) (MIT) for Varlink services and clients, with bindings generated from `.varlink` IDL, including for systemd's interfaces.
- One Cargo workspace for `sparewalld`, `sparewall`, the schema, the renderers and the providers.
- Socket-activated from a `.socket` unit at `/run/sparewall/org.sparewall.Firewall`, mode 0600, root only. A second, restricted socket can be added for a future front end. The peer never uses this socket; it talks through the sync tunnel.
- Interface names follow the project domain in reverse: `org.sparewall.*`.

### Interface sketch

```varlink
interface org.sparewall.Firewall

type Generation (id: int, hash: string, base: ?int, schema: int, author: string, applied: string, confirmed: bool)

method Validate(config: object) -> (warnings: []string)
method Apply(config: object, base: int, confirm_seconds: ?int) -> (generation: Generation, changed: []string)
method Merge(patch: object, base: int, confirm_seconds: ?int) -> (generation: Generation, changed: []string)
method Patch(ops: []object, base: int, confirm_seconds: ?int) -> (generation: Generation, changed: []string)
method Confirm(id: int) -> ()
method Rollback(id: ?int, allow_diverge: ?bool) -> (generation: Generation)
method GetConfig(id: ?int) -> (config: object, generation: Generation)
method Export(id: ?int) -> (config: object)
method History(limit: ?int) -> (generations: []Generation)
method Sync(from_node: string) -> (generation: Generation)
method Health(verbose: ?bool) -> (level: string, role: string, checks: ?[]object)
method Status() -> (role: string, sync: object, links: object, vrrp: object, conntrack: object, services: object)
method Backup() -> (path: string, digest: string)
method Subscribe() -> (event: object)  # called with "more": streams events

error ValidationFailed (errors: []string)
error Conflict (current: int)
error ConfirmTimeout (rolled_back_to: int)
error PeerUnreachable (peer: string)
error PermissionDenied (role: string)
```

Related interfaces follow the same pattern: `org.sparewall.Auth` (users, tokens, roles), `org.sparewall.Secrets` (write-only secret store), `org.sparewall.Upgrade` (rolling upgrades and channels).

## The sparewall CLI

`sparewall` is a thin Varlink client with kubectl-style ergonomics: whole documents or small fragments in JSON or YAML, individual values by path, and the same validate, diff and confirm-or-revert safety on every change.

### Design goals

1. **Thin client.** All validation, rendering and state live in the coordinator, so any future front end can do everything the CLI can.
2. **JSON and YAML, in and out.** Input format detected from extension or content (`-f site.yaml`, `-f -`); output chosen with `-o json|yaml|table`. YAML is converted in the client; Varlink carries JSON.
3. **Small pieces merge in** without restating the whole document.
4. **Get and set by path** from the command line, no file needed.
5. **Every change is safe:** validated, diffable, and applied with a confirm window.
6. **Scriptable:** stable `-o json`, meaningful exit codes, `--quiet`, generated shell completion.

### Commands

| Command | What it does | kubectl analogue |
| --- | --- | --- |
| `sparewall get [path] [-o yaml]` | Print the document or a subtree | `get -o yaml` |
| `sparewall set path=value …` | Set values in one transaction | `set`, `patch` |
| `sparewall unset path …` | Remove keys or map entries | `patch` with null |
| `sparewall merge -f fragment.yaml` | Merge a partial document | `apply` |
| `sparewall apply -f site.yaml` | Apply a whole document, replacing the current one | `replace` |
| `sparewall patch --type json -f ops.json` | Apply RFC 6902 operations | `patch --type json` |
| `sparewall diff -f fragment.yaml` | Show what a merge or replace would change | `diff` |
| `sparewall edit [path]` | Edit in `$EDITOR`, validate and apply on save | `edit` |
| `sparewall explain path` | Describe a field from the schema | `explain` |
| `sparewall status`, `history`, `confirm`, `rollback N` | Operational state and generations | `rollout` |
| `sparewall sync --from <node>` | Resolve a diverged pair | none |
| `sparewall backup`, `export` | Backup bundle; canonical document export | none |
| `sparewall upgrade [--channel stable]` | Rolling, health-gated OS upgrade | none |
| `sparewall schema upgrade` / `downgrade` | Migrate the document between schema versions | none |
| `sparewall token …`, `secret …`, `vpn client-config <peer>` | Tokens, write-only secrets, VPN client configs | none |

```shell
sparewall get networks.users -o yaml
sparewall set networks.users.vip=192.0.2.1/24 dhcp.users.pool=192.0.2.100-192.0.2.199
sparewall unset vpn.roadwarrior.peers.old-laptop
sparewall merge -f add-guest-vlan.yaml --confirm 120
sparewall get policy.'wan->self'.rules -o json | jq .
```

### Semantics

- `merge` uses JSON Merge Patch (RFC 7386): objects merge, `null` deletes, other values replace. Because collections are maps keyed by name, adding a peer or a rule is a one-entry fragment.
- `set` and `unset` compile to merge patches client-side; `patch --type json` covers anything a merge cannot express.
- Paths are dot-separated; keys containing dots or `->` are quoted (`policy.'wan->self'`). Values are typed by the schema, so `vlan=20` is a number and string fields stay strings.
- Several `set`/`unset` pairs in one invocation are one generation and one confirm window.
- Every mutation sends its `base` generation; if the document changed in between, the coordinator returns a conflict instead of overwriting.
- `--dry-run` validates and prints the diff. `--confirm N` sets the revert window; over SSH the default is non-zero.

### Implementation notes

- Rust, in the same workspace as the coordinator, sharing the zlink-generated types; `clap` for arguments and completions.
- An actively maintained YAML 1.2 crate (`serde_yaml` was archived upstream in 2024).
- Remote use runs over SSH to a node; named contexts for each deployment live in the user's config directory.

## Networking with systemd-networkd

systemd-networkd owns every link and address except the VRRP gateway addresses. The coordinator renders its files into `/run/systemd/network/`, so the document, not hand-edited files, is the source of truth; `/etc/systemd/network/` stays empty and is reserved for emergency overrides, which take precedence over `/run`.

| Need | networkd mechanism | Note |
| --- | --- | --- |
| Stable names | `.link` files, `Name=` matched on `PermanentMACAddress=` or `Path=` | Interfaces are named after port roles and networks |
| VLANs, bonds, WireGuard | `.netdev` plus `VLAN=` and `Bond=` in `.network` | Remote-access VPN and the sync tunnel are WireGuard netdevs |
| WAN addressing | `DHCP=` or static `Address=`/`Gateway=` | `[DHCPv4] NFTSet=` puts the leased address into an nft set |
| Forwarding | `IPv4Forwarding=` in `networkd.conf` | Global |
| Addresses in firewall sets | `NFTSet=source:family:table:set` with sources `address`, `prefix`, `ifindex` | networkd only adds and removes elements; the sets must already exist |
| Reverse-path filtering | `IPv4ReversePathFilter=` per network | Strict on single-homed LANs |
| LLDP | `LLDP=`, `EmitLLDP=` | Shows which switch port each NIC is on |
| WAN queue management | `[CAKE]` qdisc | Bandwidth set per WAN in the document |
| DHCP relay | `DHCPRelay=` (261+) | For segments served by another DHCP server |
| NAT | Not `IPMasquerade=` | nft owns NAT, so there is one rule source |

networkd's built-in DHCP server is available as a provider for a simple standalone node, but it has no failover protocol, so pairs use Kea.

### Coexisting with keepalived

networkd treats addresses it did not configure as foreign and drops foreign configuration when it starts, which can remove VRRP gateway addresses. The design guards against this:

- `KeepConfiguration=` on links that carry gateway addresses, and `ManageForeignRoutes=no` / `ManageForeignRoutingPolicyRules=no` in `networkd.conf`.
- Changes are applied with a per-link reconfigure over Varlink, never by restarting networkd.
- keepalived 2.x re-adds addresses it sees removed, so a mistake costs a blip rather than an outage.

### IPv6 (later)

The first releases assume no IPv6 from the ISP and route IPv4 only. When IPv6 arrives it will use networkd's `IPv6SendRA=`, `DHCPPrefixDelegation=` and `[IPv6Prefix]`. A pair needs a decision then: either both nodes advertise, or only the active node advertises from a virtual link-local address; dynamic prefix delegation should run only on the active node.

## Firewall: zones plus raw rules

The coordinator renders the nftables ruleset from the document: a zone-based policy for the common case, with raw nft statements allowed at defined hook points for anything the zone model cannot express.

### Zone model

- **Zones** are named groups of networks, plus a built-in `self` zone for traffic to and from the firewall.
- **Policies** are per zone pair (`users->wan`): a default action (accept, drop, reject) and named, ordered rules (protocol, ports, source and destination objects, log, rate limit).
- **Objects** are named address and port sets rendered as nft named sets. Sets that networkd fills via `NFTSet=` (the WAN address, for example) appear as dynamic objects, so rules never hold literal addresses that DHCP can change.
- **NAT** attaches to zone pairs (masquerade or SNAT outbound); **forwards** define inbound DNAT.

### Raw rules

Raw entries are literal nft statements placed at named hook points, so the zone model never has to grow a feature for every edge case.

| Hook point | Typical use |
| --- | --- |
| Before or after one zone pair's generated rules | An exception the policy language lacks, a catch-all log |
| Prerouting at raw priority | `notrack` for VRRP or sync traffic, early drops |
| Forward, before zone dispatch | Global blocks, MSS clamping |
| Postrouting | Custom SNAT, marks for policy routing |

The coordinator does not parse raw rules: it places them, tags each with a comment naming its entry, and validates the whole script with `nft -c`. They ride in the same atomic transaction and the same confirm-or-revert window as everything else, and their counters are reported by name.

```yaml
policy:
  users->wan: { action: accept, nat: masquerade }
  wan->self:
    action: drop
    rules:
      ssh-admin: { order: 100, proto: tcp, dport: 22, src: "@admin_nets", action: accept }
raw:
  block-scanner:
    at: { pair: wan->users, position: before }
    order: 100
    nft: ip saddr 198.51.100.0/24 counter drop
  notrack-vrrp:
    at: { hook: prerouting-raw }
    order: 100
    nft: ip protocol vrrp notrack
```

### Rendering

- Base chains accept `ct state established,related` and drop `invalid` first, then dispatch by interface pair through verdict maps, for example `iifname . oifname vmap { "users" . "wan" : jump users_to_wan }`, so rule count stays flat as networks are added.
- Each zone-pair chain runs: raw *before* entries, generated rules, raw *after* entries, default action.
- An **anti-lockout rule** for SSH and HTTPS from the management network to `self` is always rendered first, unless an `admin` explicitly disables it.
- Protocols that need conntrack helpers (FTP, SIP) get explicit `ct helper` objects; nftables does not assign helpers automatically.
- Rule logging uses `log group N`, collected by ulogd2 (see Observability).

### Sharing nftables with other software

The coordinator owns one table (`inet sparewall`) and loads each generation as one `nft -f` transaction. It never runs `flush ruleset`, because others write nft too:

- **networkd** inserts set elements only when addresses change, so those sets are declared idempotently (`add table`, `add set`) and never flushed; only coordinator-owned chains are flushed and rebuilt.
- **keepalived** may install its own rules.
- **Podman's Netavark** manages container networking in nftables; Sparewall's containers run with host networking or none, which keeps it out of the way.

Every script is validated with `nft -c -f` before loading, and the previous generation's script is kept for rollback. Flowtables (a fast path for established flows) stay off until they are proven compatible with conntrackd failover.

## High availability and standalone mode

A pair is active/standby: keepalived moves the gateway addresses, conntrackd moves connection state with them, and the DHCP provider runs its own HA protocol. All replication runs over a dedicated sync VLAN inside a WireGuard tunnel; no dedicated sync cable is required.

### Sync over a shared trunk

- **Isolation.** `sync` is its own VLAN, never routed or bridged anywhere. nft on it accepts only WireGuard from the peer's sync address. Every switch port between the nodes must carry it.
- **Authentication and encryption.** conntrackd's protocol has neither, so it runs inside a WireGuard tunnel between the nodes' sync addresses, configured by networkd. DHCP HA and the coordinator's config push use the same tunnel. Each node generates its sync key at first boot; only public keys appear in the document.
- **Split-brain behaviour.** VRRP adverts stay on the service VLANs, never on `sync`. Losing only the sync VLAN degrades state and lease replication but cannot move or duplicate gateway addresses; losing a whole trunk takes VRRP and sync down together, which is what VRRP is built to handle. Sync loss raises its own alert.
- **Contention (optional).** The sync VLAN can carry an 802.1p priority (networkd `EgressQOSMaps=`), honoured by switches and OVS.

### keepalived

- One `vrrp_sync_group` holds every VRRP instance, so all gateway addresses move together; a split would break stateful filtering.
- VRRPv3; `track_interface` on every member link; `nopreempt`; optional `use_vmac`.
- A `track_script` calls the coordinator's `Health()` over Varlink. Only a **failed** result lowers priority, with a hold-down so a briefly failing check cannot flap the pair.
- State changes reach the coordinator through `notify_fifo`, so transitions are serialized and logged in one place.

### conntrackd

FTFW mode, active/backup, bound to the tunnel addresses. Connection tracking is shared by iptables and nftables, so it works unchanged with an nft ruleset. On becoming master the coordinator runs the standard sequence: commit the external cache (`-c`), flush the internal cache (`-f`), resync (`-R`), request a bulk send (`-B`).

### DHCP HA

With the Kea provider: hot-standby mode, with the HA hook and `lease_cmds`, both open source since Kea 3.0. Each Kea binds to its node's own addresses, not the gateway address; clients receive the gateway address as their router, so it does not matter if the VRRP master and the active Kea briefly differ. HA traffic uses the peer's tunnel address.

### Failover sequence

1. The standby's keepalived stops seeing adverts and becomes MASTER, adding every gateway address and announcing it with gratuitous ARP.
2. The coordinator receives the FIFO event and runs the conntrackd sequence, so established flows keep passing the new master's stateful rules.
3. Independently, the DHCP provider detects its partner down after its own timeouts and starts answering.
4. The old master returns as BACKUP, bulk-syncs connection state and leases, and stays standby until the next failure.

### Standalone mode

A document listing one node in `cluster.nodes` runs the same image as a single firewall; the mode comes from the document alone.

| Concern | Pair | Standalone |
| --- | --- | --- |
| Gateway addresses (`vip`) | Moved by keepalived | Plain static addresses |
| keepalived, conntrackd | Running | Not started |
| `sync` network and tunnel | Required | Rejected by validation |
| DHCP provider | HA mode | No HA |
| Config apply | BACKUP first, then pushed to the peer | Local, same confirm and rollback |
| OS upgrade | Rolling, no outage | One reboot of downtime |
| `Status` role | MASTER / BACKUP | standalone |

The gateway address stays separate from the node's own address even when standalone. Growing to a pair is therefore additive: install the second node, add it and a `sync` network to the document, and apply; clients notice nothing.

## Service providers

The document says what a service must do; a **provider** turns that intent into one implementation's configuration and controls it. Every application-level service is a provider, so any of them can be replaced, or moved to a new major version, without changing the schema.

### Roles and providers

| Role | Neutral config | Default provider | Alternatives |
| --- | --- | --- | --- |
| DHCPv4 | Pools, reservations (MAC, address, name), options (router, DNS, NTP, domain), lease time, HA | Kea 3.0 LTS | Kea 3.2; networkd's built-in server (standalone only); dnsmasq |
| DNS resolver | Enabled flag, listening networks, forwarders or full recursion, local records from reservations | Unbound | Knot Resolver; dnsmasq; disabled |
| ACME DNS-01 | Names, CA directory, provider name, secret reference | Built-in RFC 2136 | lego (Google Cloud DNS, Cloudflare, Route 53 and many more) |
| Log forwarding | Destination, protocol, TLS | `systemd-journal-upload` | rsyslog remote (syslog or RELP); off |
| Metrics storage | Mode, retention | External scrape | Local Prometheus container; off |
| Backup | Repository, schedule, credentials | restic | Any restic backend; off |

### What a provider is

- A Rust module in the coordinator implementing one interface: render the intent, validate with the daemon's own checker, apply and reload, report status and metrics, declare capabilities, and export/import state.
- For containerized services, a Quadlet unit and pinned image. The image may bundle more than one provider version (Kea 3.0 and 3.2), so switching is a config change and a reload, not a rebuild.

### Rules that keep providers swappable

- **Neutral schema first.** Anything most implementations can express belongs in the shared schema.
- **Escape hatch.** `provider_options.<provider>` passes settings straight into that provider's config; it is validated by the daemon's checker, shown in diffs, and ignored with a warning if the provider changes.
- **Capabilities are checked.** Each provider declares what it supports (HA, DDNS, DNSSEC, VLAN redetection); validation rejects a document needing something the chosen provider lacks.
- **State moves or is declared lost.** Switching runs the provider's export and import (Kea's lease file, for example) where possible, and otherwise warns that state will be lost.
- **One conformance suite per role,** run against every provider and version: a lease on every VLAN, reservations honoured, lease continuity across failover, local names resolve.

### Container conventions

- Quadlet files ship in the image under `/usr/share/containers/systemd/`; images are pinned by digest, so a service and the OS move and roll back together. Nodes never run `podman auto-update`.
- bootc logically bound images make `bootc upgrade` pull new container images before the reboot.
- Containers use host networking where they serve the LAN (Kea needs raw broadcast handling) or no network at all; Netavark stays out of the firewall's nft table.
- All capabilities dropped, then added back per service (Kea: `NET_RAW`, `NET_BIND_SERVICE`); read-only root filesystems; no privileged containers.
- State in named volumes under `/var/lib/containers`; control sockets in a shared `/run/<service>/` the coordinator can reach.

### Defaults in detail

- **Kea:** ISC's official open-source images for `kea-dhcp4`. Start on 3.0 LTS; move to 3.2 if 3.0's interface handling falls short on VLAN-heavy hosts, since 3.2 adds `interface-redetect` and refactored interface code. Since 3.0 the DHCP daemons serve their control API directly, and 3.2 removed the Control Agent. The coordinator drives Kea over its control socket (`config-test`, `config-set`, lease and HA status).
- **Unbound:** a recursive resolver bound to the gateway addresses of the networks it serves; the whole service can be turned off for sites with their own DNS. systemd-resolved remains the host's own stub resolver and never serves the LAN.
- **Time:** chrony runs on the host as both client and LAN time server; systemd-timesyncd cannot serve time.

## Remote-access VPN (WireGuard)

Remote-access WireGuard is built in: networkd runs the tunnel, the VPN is a zone in the policy, and peers are entries in the document. Nothing extra is installed.

```yaml
vpn:
  roadwarrior:
    listen_port: 51820
    endpoint: vpn.example.org
    addresses: [10.99.0.1/24]
    zone: vpn
    dns: [10.99.0.1]
    peers:
      alice-laptop: { public_key: "<base64>", addresses: [10.99.0.10/32] }
```

The coordinator renders a WireGuard `.netdev` (`ListenPort=`, `PrivateKeyFile=`, one `[WireGuardPeer]` per peer with `PublicKey=` and `AllowedIPs=`) and a `.network` with the tunnel addresses. It adds the WAN-to-`self` rule for the listen port and MSS clamping for the tunnel's smaller MTU; policy from `vpn` to other zones is written like any other zone pair.

### Keys

- **Client keys are generated on the client.** Only public keys enter the document, so git never holds a VPN secret.
- **The server key is a cluster secret:** clients know one public key and one endpoint, so both nodes must hold the same private key. The coordinator generates it once, sends it to the peer through the sync tunnel, and keeps it in the secret store.
- **Rotation** generates a new server key and lists the clients needing a new config; WireGuard has no in-place key rollover.
- `sparewall vpn client-config <peer>` prints a client config and QR code with the server's public key, endpoint and DNS; the client supplies its own private key.

### With HA

- Clients connect to the WAN gateway address. Both nodes run the same interface, key and peer list, but only the gateway holder receives traffic.
- WireGuard is stateless UDP: after a failover the new master learns each client's endpoint from its next packet. Client configs recommend `PersistentKeepalive = 25` so this happens within seconds.
- Flows inside the tunnel are tracked and synced by conntrackd like any other traffic.
- The remote-access interface and the sync tunnel are separate WireGuard interfaces with separate ports and keys.

Standalone nodes run the same configuration. Static-endpoint peers can later cover simple site-to-site tunnels with the same mechanism.

## Observability and health

Logs land in the journal and can be forwarded off the box; metrics are exposed in Prometheus format; one health model answers every "is this node OK?" question. Dashboards, long-term storage and alert delivery live elsewhere, so a firewall never depends on its own monitoring.

### Logging

| Source | Captured by |
| --- | --- |
| Host services (networkd, keepalived, conntrackd, coordinator) | journald |
| Containers (Kea, resolver) | Podman's journald log driver, tagged with the unit name |
| Firewall rule hits | nft `log group N` → ulogd2 → structured JSON entries in the journal, avoiding kernel-log rate limits |
| Connection and NAT records (optional, off by default) | ulogd2's conntrack plugin: flow start and end with NAT mappings |
| Configuration changes | The coordinator: generation, hash, author and diff summary as structured journal fields |

Forwarding is configured in `logging.remote`: `systemd-journal-upload` to a `systemd-journal-remote` collector, an rsyslog remote (plain syslog or RELP), or off. Journal size caps on `/var` keep a log flood from filling the disk.

### Metrics

- **Host:** Prometheus node\_exporter (CPU, memory, NIC counters and errors, conntrack table use).
- **Appliance:** the coordinator serves `/metrics` for everything else: nft rule and raw-entry counters by name, set sizes, VRRP state and failover count, conntrackd sync statistics, DHCP pool use and HA state, WireGuard per-peer handshakes and traffic, config sync state and generation, last apply duration, backup age.
- **Where they go** is configured in `metrics.mode`: exposed for an external Prometheus, collected by an optional local Prometheus container with bounded retention, or off.
- The project ships starter alert rules: failover occurred, pair diverged or apply failed, sync tunnel down, WAN down, DHCP pool above 90%, conntrack table above 80%, backup older than its interval, certificate or key near expiry.

### Health endpoints

One health model lives in the coordinator as `Health()`; HTTP endpoints, `sparewall status` and the keepalived check are all views of it.

| Endpoint | Means |
| --- | --- |
| `/livez` | The coordinator responds; no dependency checks. Locally, systemd's `WatchdogSec=` restarts a hung coordinator |
| `/readyz` | This node could carry traffic now: required links up, nft holds the current generation, providers and conntrackd running, applied hash equals desired hash |
| `/readyz?verbose`, `/readyz/<check>` | Each named check and its result, or one check |
| `/healthz` | Alias of `/readyz` for tools that expect it |

Results have three levels: **ok** (HTTP 200), **degraded** (HTTP 200 with the reason: sync tunnel down, pair diverged, backup stale), and **failed** (HTTP 503). Only *failed* lowers VRRP priority; *degraded* never triggers failover, because a sync fault affects both nodes equally. The node's VRRP role appears only in the response body, never as a status code. Endpoints share the `/metrics` listener on the management network; unauthenticated requests get only the level, and verbose detail requires authentication.

## Security

The coordinator is the single authority: it holds users and tokens, checks every call against a role, stores secrets, and manages certificates. Management services are confined to the management network by systemd, nftables backs that up, and SELinux stays enforcing.

### Authentication

| Who | How |
| --- | --- |
| Admin at a shell | SSH keys; `sparewall` talks to the root-only local socket. A console root password set at install is the break-glass path |
| Scripts, CI, future front ends | API tokens |
| Prometheus and health checks | A `monitor`-role token or a TLS client certificate |
| Peer node | WireGuard keys on the sync tunnel |

- **A built-in `admin` account** has its password set at install; its Argon2id hash is a cluster secret. Password logins are rate-limited.
- **API tokens** are random opaque strings, not JWTs, so revocation is immediate. `sparewall token create --role operator --expires 90d` shows a token once; the coordinator stores only its hash with name, role, expiry and last use.
- **Single sign-on** (OpenID Connect) can be added later and mapped onto the same roles; the local `admin` account always keeps working, so an identity provider reached through the firewall can never lock anyone out of it.

### Roles

| Role | May |
| --- | --- |
| `admin` | Everything, including users, tokens, secrets and certificates |
| `operator` | Change, confirm, roll back and sync configuration; read status |
| `viewer` | Read configuration and status |
| `monitor` | Verbose health and metrics only |

Every authenticated mutation is logged with its principal. Because every setting has a path, path-scoped grants (a token that may only edit `vpn.roadwarrior.peers`) are a natural later extension.

### TLS and ACME

- Each node generates a self-signed certificate at first boot; `sparewall status` shows its fingerprint. Without ACME configured, or if issuance fails, nodes keep serving it and raise an alert.
- ACME is built into the coordinator with a configurable directory URL (Let's Encrypt, a private CA such as step-ca) and External Account Binding.
- **DNS-01 is the primary challenge,** because management interfaces should not be reachable from the internet. RFC 2136 dynamic updates with TSIG are built in; lego (MIT) in a container covers hosted DNS APIs such as Google Cloud DNS, Cloudflare and Route 53. HTTP-01 remains available for public names.
- In a pair, a certificate for a shared name is requested only by the active node and synced to the peer, so CA rate limits are not consumed twice.
- Renewal happens at two-thirds of the lifetime, or earlier when the CA publishes ACME Renewal Information; certificates reload without restarting listeners.

```yaml
tls:
  certificates:
    mgmt:
      names: [fw.example.org]
      acme:
        directory: https://acme-v02.api.letsencrypt.org/directory
        challenge: dns-01
        dns: { provider: gcloud, credentials: secret:gcloud-dns }
```

### Secret storage

Secrets never appear in the document or in git; the document refers to them by name.

| Class | Examples | Leaves the node? |
| --- | --- | --- |
| Node secrets | SSH host keys, sync-tunnel WireGuard key, self-signed TLS key | Never |
| Cluster secrets | VPN server key, admin password hash, issued TLS keys, ACME account key, DNS and log-forwarding credentials | Synced to the peer through the sync tunnel; included in the encrypted backup |

- **At rest:** each secret is encrypted with `systemd-creds`, bound to the TPM2 where present (libvirt VMs can be given a virtual TPM), otherwise to the host credential key.
- **In use:** services receive secrets through `LoadCredentialEncrypted=`, so plaintext exists only in that service's private credentials directory.
- **Between nodes:** TPM-bound ciphertext cannot move, so the coordinator decrypts, sends through the tunnel, and the peer re-encrypts with its own key.
- **Interface:** `sparewall secret set NAME` reads from stdin or a prompt; `sparewall secret list` shows names and versions. Secrets are write-only.
- **The backup repository password is the one secret kept outside Sparewall,** in an operator's password manager.

### Management-plane isolation

The data plane (networkd, nft, keepalived, conntrackd, WireGuard) stays in the root network namespace. Management services are confined per service rather than by separate namespaces, which would require a second networkd, ruleset and resolver and make every debugging command harder. A management VRF is available for sites whose management network has its own upstream gateway.

| Service | Listens on | Restriction |
| --- | --- | --- |
| sshd | Management addresses | `RestrictNetworkInterfaces=` to the management interface; keys only; no root login over SSH |
| Coordinator HTTPS (health, metrics) | Management addresses | `RestrictNetworkInterfaces=`; `IPAddressAllow=` for the management prefix |
| DHCP provider | Service networks | Host network; minimal capabilities; nft limits it to DHCP |
| DNS resolver | Gateway addresses of served networks | Host network; may only query out through the WAN |
| chrony | Served networks (NTP) | Host network |
| Remote-access WireGuard | WAN, one UDP port | Kernel; silent to packets without a valid key |

Nothing else listens on the WAN. ICMP is rate-limited and invalid packets are dropped. The anti-lockout rule keeps SSH and HTTPS reachable from the management network unless an `admin` disables it.

### Host hardening

- **SELinux enforcing.** Distribution policy confines networkd, chronyd, keepalived and containers; the coordinator gets its own policy module before 1.0, with only its domain permissive until then.
- **Coordinator sandboxing:** bounded capabilities (network administration, raw sockets), `NoNewPrivileges=`, `RestrictAddressFamilies=` (UNIX, netlink, IPv4, IPv6), `ProtectHome=`, a `@system-service` syscall filter, writes limited to its own state and rendered configs; tracked with `systemd-analyze security` in CI.
- **Secure Boot and measured boot** are optional and recommended on physical nodes; binding TPM-sealed secrets to the boot state stops a moved disk from unsealing them.

## Bootstrap

A fresh node boots into a safe built-in default that is reachable only on its management port, and receives its real configuration through the same `sparewall apply` path as every later change. Install time carries only a tiny identity.

### 1. Install with a minimal identity

Installer ISOs and raw disk images are built from the bootc image with bootc-image-builder. Three values are supplied at install:

| Value | Why it is needed before any config exists |
| --- | --- |
| Node name (`fw1`, `fw2`) | Selects this node's values in the shared document |
| Admin SSH public key | Lets an operator or CI reach the node |
| Management port, matched by MAC | The only interface bootstrap mode brings up |

On VMs they arrive as systemd credentials (SMBIOS or kernel command line), read by the coordinator with `ImportCredential=`. On physical machines they come from a kickstart for the ISO install, or a small seed file on a USB stick read once at first boot and recorded under `/var/lib/sparewall`.

### 2. First boot: bootstrap mode

With no applied generation, the coordinator renders the default shipped in the image: only the management port up (static address or DHCP client, per the identity), SSH accepted on that port only, all forwarding dropped, and keepalived, conntrackd and providers stopped. It also generates the SSH host keys and the sync-tunnel WireGuard key under `/var/lib`, so private keys never leave the node. A serial console with a local `sparewall` is the fallback.

### 3. First configuration

An operator or CI runs `sparewall apply -f site.yaml --confirm 120` over SSH to the management port and confirms once a post-apply check passes. If the configuration cuts off management access, the confirm timer returns the node to bootstrap mode (generation 0).

### 4. Pairing

1. Install and bootstrap both nodes.
2. Read each node's sync-tunnel WireGuard public key with `sparewall status`.
3. Add both keys to the document's `cluster` section and apply on each node.
4. The tunnel comes up and the nodes authenticate each other; from then on, an apply on one node is pushed to the other.

Only public keys appear in the document.

## Backup and restore

Little on a node needs backing up: the OS is an image in a registry, the document lives in git, and in a pair the peer holds a live copy of everything else. The backup exists for losing both nodes, losing git, or running standalone, and it is one small encrypted bundle per node.

### State and where it is protected

| State | Lives in | Protected by | If every copy is lost |
| --- | --- | --- | --- |
| OS, daemons, coordinator | Registry | Retention of every deployed digest; `sparewall status` records the running digest | Rebuild from the Containerfile at that commit |
| Configuration document | Git (source of truth); generations in `/var/lib/sparewall` | Git, plus the bundle | Export from either node |
| Node identity (SSH host keys, sync key) | `/var/lib` on each node | Not backed up by design | Regenerate on reinstall and re-pair |
| Cluster secrets | Secret store on both nodes | The peer, plus the encrypted bundle | Re-enter or regenerate; a new VPN key means new client configs |
| DHCP leases | Provider state (Kea's memfile) | Provider HA, plus the bundle | Clients re-request; Kea's open-source `ping_check` hook avoids handing out addresses still in use |
| Connection tracking | Kernel, synced to the peer | Never backed up | Connections reconnect |
| Logs and metrics | Journal and exporters | Forwarded off-box when configured | Not a backup concern |

Regenerating node identity instead of backing it up keeps node private keys from ever existing outside their node, at the cost of one pairing step after a rebuild.

### The bundle

`sparewall backup` writes one archive with the active document, the last N generations, the encrypted cluster secrets, a lease export, the running image digest and the node's public keys. A systemd timer runs it on a configurable schedule (hourly by default) and sends it with restic, which encrypts the repository itself, to a configurable repository: a local path, SFTP, S3-compatible storage or a restic REST server. Backups can be turned off. Standalone nodes have no peer copy, so a shorter schedule is recommended where lease continuity matters.

### Restore by scenario

| Failure | Restore |
| --- | --- |
| Bad configuration change | Confirm timeout reverts it; otherwise `sparewall rollback` |
| Bad OS or container update | `bootc rollback` and reboot that node |
| One node destroyed | Reinstall with the same node name, add its new sync key to the document and apply; the peer pushes configuration and secrets, DHCP HA resyncs leases, conntrackd bulk-syncs |
| Both nodes destroyed | Reinstall both, restore the bundle (document, secrets, leases) before services first start |
| Git lost | `sparewall export` from either node, or the latest bundle |
| Registry lost | Rebuild images from the Containerfile; re-pin container digests if upstream images moved |

CI runs a restore drill on every release candidate: destroy one node, then both, and restore from the latest bundle.

## Releases, upgrades and versioning

Every image a node runs is built in CI, signed, and verified on the node; upgrades are orchestrated by the coordinator, never by a timer; and three independently versioned interfaces have rules that keep a rolling upgrade or a rollback from stranding a node.

### Build, sign, publish

- CI builds the OS image from the Containerfile with the base image pinned by digest and records the exact package list as the image manifest. Renovate (or a scheduled job) bumps the base digest so security fixes flow in automatically.
- An SBOM (syft) is generated for each image; images are signed with cosign, using a key held in CI secrets.
- **Everything is published on GitHub.** The OS image goes to GitHub Container Registry as `ghcr.io/sparewall/sparewall` with `stable` and `testing` channel tags, signatures and SBOMs attached. CLI binaries, checksums, SBOMs and installer disk images go on GitHub Releases (2 GiB per asset, so a larger installer ships compressed or split).
- License allow-lists (RPM `License:` tags and `cargo-deny`) gate the build.

### Verify on the node

The image ships a containers signature policy requiring the project's signature; bootc enforces it on `switch` and `upgrade`, and Podman enforces it for Quadlet images. Unsigned or wrongly signed images are refused.

### Upgrade policy

- bootc's own automatic update timer is disabled. `sparewall upgrade` stages the new image on the BACKUP node, pre-pulls bound container images, reboots it, waits for **ok** health and matching config hashes, fails over, then repeats on the other node. A failed gate stops the upgrade; `bootc rollback` returns that node.
- **Channels:** every passing build reaches `testing`; it is promoted to `stable` after the two-node test suite passes. Nodes follow one channel.
- **Modes:** manual by default; optionally automatic within a maintenance window (`updates.window`).
- Standalone nodes use the same command and accept one reboot of downtime.
- The registry keeps every digest ever deployed, so rollbacks and disaster recovery can always fetch it.

### Versioning and compatibility

| Version | Changes when | Rule |
| --- | --- | --- |
| Release (image, semver) | Every release | The image carries the coordinator with the daemons and providers it renders for, so they never skew within a node |
| Config schema (integer) | The document format changes | A coordinator reads its own schema and at least the previous one, migrating on load; writing a newer schema is an explicit step |
| Peer protocol (Varlink interface) | Node-to-node calls change | Only additive changes within an interface; breaking changes get a new interface name; nodes negotiate the highest common version |

Across a schema change, a rolling upgrade goes: upgrade the BACKUP node, fail over, upgrade the other node, then run `sparewall schema upgrade`, which migrates the document as an ordinary generation. New schema features are gated on the oldest release in the pair, so the coordinator rejects a field the peer could not render.

Rollback rules:

- Rolling the image back before `schema upgrade` is always safe.
- Afterwards, an older coordinator cannot read the new schema. Each node keeps the latest generation for every schema version, so an older coordinator falls back to the newest one it understands, reports *apply failed*, and alerts.
- Migrations ship with a down-migration where possible, so `sparewall schema downgrade` can precede an intentional image rollback.
- Backup bundles record their schema version; restores follow the same rules.

## Performance and sizing

Small-office loads (a 1 to 2.5 Gb/s WAN with NAT and a few thousand connections) are expected to fit software forwarding on a modern mini PC or a virtio VM; this is measured, not promised. In a pair the standby must carry the full load, so everything is sized for the smaller node.

### Connection tracking

- The conntrack table maximum and hash size are set explicitly in the document as one value both nodes can hold; the kernel default scales with RAM and would otherwise differ between nodes.
- The established-TCP timeout is lowered from the kernel's 5-day default (to about a day) so dead entries do not fill the table.
- `nf_conntrack_tcp_loose` stays enabled (the default) so a new master picks up mid-stream connections.

### Kernel and NIC settings

- Reverse-path filtering is strict on single-homed LANs.
- ARP behaviour (`arp_ignore`, `arp_announce`) is set on interfaces carrying gateway addresses so replies always match the interface asked.
- GRO, TSO and GSO stay on; the kernel disables LRO automatically when forwarding. Overrides are per port for misbehaving drivers.
- VMs use virtio multiqueue with one queue per vCPU; physical nodes use irqbalance, or RPS where a NIC has one queue.
- nftables flowtables are the largest available forwarding gain and are enabled only once proven compatible with conntrackd failover.

### Benchmarks

- iperf3 through NAT, single and multi-stream, both directions, on each node.
- New-connection rate, and filling the conntrack table to its maximum.
- Failover under load: interruption length and which flows survive.
- Repeated with high-rate rule logging and with CAKE on the WAN, both CPU-heavy.
- Results are kept per hardware profile in the repository and compared on every release, on real hardware rather than shared CI runners.

## Testing and CI

Each layer is tested where it is cheapest, and promotion to the `stable` channel is gated on a two-node VM suite that exercises failure, upgrade and restore end to end. Everything except performance benchmarks runs on GitHub Actions' hosted runners.

| Layer | Tests | When |
| --- | --- | --- |
| Schema and CLI | Valid and invalid document fixtures; property tests for merge, patch and set (set-then-get round-trips, idempotent merges, canonical hash stable across key order and JSON vs YAML); fuzzing of the parsers | Every commit |
| Renderers | Snapshot tests from document to networkd, nft, keepalived, conntrackd, provider and WireGuard files; every rendered file also passes its own checker | Every commit |
| Coordinator logic | Unit tests with fake adapters: apply, confirm, rollback, divergence, health levels, role checks | Every commit |
| Providers | The role's conformance suite against every provider and version | Every merge |
| Single-node VM | Boot the image, bootstrap, first apply, standalone mode, backup and restore | Every merge |
| Two-node VM suite | Failover (kill the master, cut one VLAN, cut only the sync VLAN, flap a bond member); flow survival; lease continuity; VPN client reconnect; rolling upgrade from the previous release; schema upgrade and downgrade; divergence and `sync --from`; full restore drill | Before promotion to `stable` |
| Policy conformance | Generate the expected reachability matrix (zone pairs by service) from the document and probe it from test clients in each zone | In the two-node suite |
| Performance | Benchmarks compared with the previous release | Each release, on real hardware |

### On GitHub Actions

Standard Linux runners for public repositories (4 vCPUs, 16 GB RAM, 14 GB SSD, with `/dev/kvm`) run everything above except benchmarks.

- **Only the firewalls are VMs.** Two at 1.5 to 2 GB each fit easily; LAN clients, the WAN upstream and VPN clients are network namespaces or containers on the runner, attached to the same bridges.
- **Switching:** Open vSwitch on the runner provides VLAN trunks and an LACP bond, so every port shape is exercised. A VLAN-filtering Linux bridge is the fallback.
- **One scenario per job:** a matrix of failover, upgrade, restore, VPN and policy conformance, each booting its own pair.
- **Disk is the tight resource:** preinstalled toolchains are removed at job start, and the upgrade test uses a throwaway local registry.
- **Outcomes, not timings.** Nested virtualization makes timing variable, so tests assert that gateway addresses moved and flows survived, with generous timeouts; failover timing is measured on real hardware.

Self-hosted runners, if added for benchmarks or capacity, never run workflows triggered by pull requests from forks; they are limited to protected-branch pushes, releases and manual runs.

## Web UI (later)

A web UI and HTTP API will be developed as a separate effort, in their own repository, once the Varlink API and the core components are stable and tested. The UI will be deployed as a container on the nodes and will talk to the core only through the versioned Varlink API.

What the core provides now so that effort can start cleanly:

- Every action is available through the coordinator's Varlink API; the `sparewall` CLI is simply its first client.
- The API is versioned, so a front end targets a stable contract.
- Users, API tokens and roles live in the coordinator, so any front end inherits the same authorization.
- The coordinator can expose a second, restricted socket for a front end, separate from the root-only admin socket.

Everything else (frontend technology, the HTTP API's shape, browser-facing authentication, how the container is isolated) is decided in that effort.

## Project

Sparewall lives at [github.com/sparewall](https://github.com/sparewall); `sparewall.org` is the project domain and the source of the `org.sparewall` interface namespace. Everything the project builds is open source, and every artifact is published on GitHub.

### Repositories

| Repository | Contents |
| --- | --- |
| `sparewall/sparewall` | Cargo workspace (`sparewalld`, `sparewall`, schema, renderers, providers), Containerfile and Quadlet units, VM test suites, example documents, and the documentation under `docs/` |
| `sparewall/.github` | Organization profile, shared workflows, security policy, contributing guide |
| Web UI repository (later) | Created when that effort starts |

The schema, coordinator, providers and image live in one repository because they change in lockstep: the image pins the daemon versions the providers render for, and one release tag means one tested image. Documentation lives beside the code so it changes in the same pull request. Rust crates stay unpublished on crates.io until there is a reason to publish them, since crate names cannot be reclaimed.

### Licensing

| Component | License |
| --- | --- |
| Coordinator, CLI, providers, schema (built here) | GPL-3.0 |
| Web UI (built here, later) | AGPL-3.0, as a network service |
| Kea | MPL-2.0. All hooks are open source since 3.0 except RBAC and the Configuration Backend, which Sparewall does not use |
| systemd | LGPL-2.1+ (some tools GPL-2.0) |
| nftables, conntrack-tools, keepalived, chrony, ulogd2 | GPL-2.0 family |
| Podman, bootc, cosign, syft, node\_exporter | Apache-2.0 (bootc also MIT) |
| zlink | MIT |
| Unbound | BSD-3-Clause |
| lego | MIT |
| restic | BSD-2-Clause |
| Fedora base image | Free licences, except redistributable binary NIC firmware in `linux-firmware` |

MIT and Apache-2.0 dependencies are compatible with GPL-3.0 and AGPL-3.0. CI enforces license allow-lists for RPMs (`License:` tags) and crates (`cargo-deny`), so a non-free or incompatible dependency fails the build. Licenses in this table should be confirmed by that check rather than taken from this document.

## Development milestones

Build bottom-up: a bootable image, then a standalone firewall, then services, then HA, then everything around it. Each milestone ends with tests that run in CI, and nothing starts on the web UI until milestone 6 is done.

| # | Milestone | Delivers | Exit criteria |
| --- | --- | --- | --- |
| 0 | Foundations | Repositories, CI skeleton, Fedora bootc Containerfile with networkd, nftables and Podman; signed image published to `ghcr.io/sparewall/sparewall:testing`; license gates | The image boots in a CI VM; its signature verifies; the license checks pass |
| 1 | Standalone core | `sparewalld` and `sparewall`; schema v1 for ports, networks, zones, objects, policy, raw, forwards; networkd and nft renderers; generations with confirm and rollback; bootstrap mode; anti-lockout; `/livez` and `/readyz` | Single-node VM suite: bootstrap, first apply, rollback on missed confirm, policy conformance across VLANs |
| 2 | Services | Provider interface; Kea 3.0 and Unbound providers with conformance suites; chrony; log forwarding; `/metrics`; backup bundle and restore | DHCP leases and reservations on every VLAN; local DNS; standalone backup-and-restore drill |
| 3 | High availability | Sync VLAN and WireGuard tunnel; keepalived and conntrackd; Kea HA; peer push, hashes and divergence handling; health-driven VRRP priority | Two-node suite: failover scenarios, flow survival, lease continuity, `sync --from` |
| 4 | Access and secrets | Secret store; users, tokens and roles; ACME (RFC 2136 and lego) with self-signed fallback; remote-access WireGuard | Token and role tests; certificate issuance against a test CA; VPN client survives failover |
| 5 | Releases and upgrades | `sparewall upgrade` with channels and health gates; signature enforcement on nodes; schema versioning and migrations; installer images on GitHub Releases | Rolling upgrade from the previous release; schema upgrade and downgrade; unsigned image refused |
| 6 | First production deployments | Hardening pass (SELinux module, sandboxing score), benchmarks on real hardware, documentation | Runs in production at two sites; restore drill passes on real hardware; 1.0 released |
| 7 | Web UI | Separate repository against the versioned API | Defined when that effort starts |

Later features (multiple WANs and WAN failover, IPv6 routing, DDNS, IDS/IPS, dynamic routing) follow 1.0 and slot in as providers or schema additions.

## To prove in the lab

Every component here is mature, but some combinations are unproven. Each item below has a concrete test and a fallback; the milestone column says when it must be settled.

| Unknown | Test | Fallback | By milestone |
| --- | --- | --- | --- |
| networkd drops keepalived gateway addresses on reload or restart | Hold MASTER; run a link reconfigure, `networkctl reload`, then a networkd restart; watch for address loss and ARP gaps | `KeepConfiguration=`, `ManageForeign*=no`, never restart networkd in production paths | 3 |
| conntrackd failover loses flows | Long-lived TCP and UDP flows through the pair while the master is killed | Tune FTFW timers; test `nf_conntrack_tcp_be_liberal` | 3 |
| Flowtables hide state from conntrackd | The same test with a flowtable enabled | Leave flowtables off | 6 |
| networkd's `NFTSet=` elements vanish on ruleset reload | Reload the nft script; check the sets still hold WAN and LAN addresses | Never recreate tables; trigger a link reconfigure after reloads | 1 |
| Kea 3.0 misses VLANs that appear late | Boot with a VLAN whose parent comes up slowly | Kea 3.2 with `interface-redetect`; or start Kea after `systemd-networkd-wait-online` | 2 |
| Kea 3.2 container images are not published | Check ISC's registry | Kea 3.0, or build images from distribution RPMs | 2 |
| Container images are absent after an offline install | Install from the ISO with no network; check bound images | Embed images in the installer | 5 |
| `machine-id` persistence with a transient `/etc` | Reboot and upgrade with transient `/etc` enabled | Keep the 3-way-merged `/etc` | 6 |
| bootc's signature-enforcement option and flag name | Switch to an unsigned image | Enforce through the containers policy alone | 5 |
| OVS with an LACP bond on GitHub's hosted runners | Run the two-node suite there | VLAN-filtering Linux bridge with a bond in a namespace | 3 |
| No TPM on a node | Give libvirt VMs a virtual TPM; check physical hardware | Host-key encryption of secrets, documented as weaker | 4 |
| A leaked DNS-01 credential can issue certificates for the zone | Scope the TSIG key or cloud role to `_acme-challenge` records only | Delegate a dedicated challenge subdomain | 4 |
| Remote-access reconnect time after failover | VPN client VM during failover | Tune the recommended client keepalive | 4 |
| The smaller node cannot carry full load after failover | Benchmarks | Flowtables, lighter logging, or larger hardware | 6 |
| Mixed coordinator versions during an upgrade | Rolling upgrade across a schema change | The versioning rules: schema bump only after both nodes upgrade | 5 |

## Version baseline and sources

Versions current in October 2026; recheck when the Containerfile is written.

| Component | Version | Note |
| --- | --- | --- |
| systemd | [262](https://www.phoronix.com/news/systemd-262), released 22 September 2026 | 261 added networkd link Varlink methods and DHCP relay |
| Fedora | 45 being prepared with systemd 262 | Fedora CoreOS and bootc are being unified for Fedora 46 |
| CentOS Stream 10 Hyperscale SIG | systemd [261.3](https://mirror.stream.centos.org/SIGs/10-stream/hyperscale/source/packages-main/Packages/s/) rebuilds | Stock Stream 10 ships 257 |
| Podman | [6.0](https://linuxiac.com/podman-6-0-lands-with-breaking-changes-amd-gpus-support/) | Netavark with nftables only; Quadlet improvements |
| Kea | 3.0 LTS; [3.2](https://www.isc.org/blogs/kea-3-2/) stable since 24 June 2026 | Control Agent removed in 3.2 |
| keepalived | [2.3.x](https://keepalived.org/news/) |  |
| zlink | Releases through 2026 | MIT |

Other components (chrony, ulogd2, restic, lego, step-ca, node\_exporter, cosign, syft) are used at their current distribution or upstream releases.

### Sources

- [systemd.network(5), systemd 262](https://manpages.debian.org/unstable/systemd/systemd.network.5.en.html)
- [systemd 261 release notes (LFS mirror)](https://wiki.linuxfromscratch.org/lfs/ticket/5959) · [Linuxiac on systemd 261](https://linuxiac.com/systemd-261-lands-with-cloud-imds-tpm-and-network-updates/)
- [systemd v257: sd-varlink made public](https://github.com/systemd/systemd/releases/tag/v257)
- [Fedora CoreOS: why networkd is absent](https://discussion.fedoraproject.org/t/systemd-networkd-and-coreos/12535) · [CoreOS and bootc unification](https://github.com/coreos/fedora-coreos-tracker/issues/2214)
- [Fedora bootc filesystem layout](https://docs.fedoraproject.org/en-US/bootc/filesystem/)
- [Kea 3.2 announcement](https://www.isc.org/blogs/kea-3-2/) · [Kea hooks feature matrix](https://kb.isc.org/docs/aa-01615) · [Kea 3.2.0 release mail](https://lists.isc.org/pipermail/kea-users/2026-June/006120.html) · [ISC container images](https://cloudsmith.io/~isc/repos/docker/packages)
- [conntrack-tools manual](https://conntrack-tools.netfilter.org/manual.html) · [keepalived news](https://keepalived.org/news/)
- [networkd restart removing keepalived addresses (Ubuntu bug 1815101)](https://bugs.launchpad.net/bugs/1815101)
- [Podman 6.0.0 release notes](https://github.com/podman-container-tools/podman/releases/tag/v6.0.0-rc1)
- [zlink](https://github.com/z-galaxy/zlink)
- [GitHub-hosted runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
