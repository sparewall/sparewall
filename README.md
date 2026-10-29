# Sparewall

Sparewall is an open-source, image-based Linux firewall: a single node or an
HA pair, configured from one versioned document, built from systemd,
nftables and a small Rust coordinator.

> **Status:** pre-release, under active development. Not ready for
> production use. See [`docs/design.md`](docs/design.md) for the design and
> the development milestones.

## What it is

- **Image-based and rollback-safe.** The OS is a signed
  [bootc](https://bootc-dev.github.io/bootc/) image; an upgrade is a reboot
  into the new image, and a rollback is a reboot into the old one.
- **One source of truth.** One JSON/YAML document describes the whole
  deployment. Every change is validated, applied with compensating
  recovery if a step fails, and reverted automatically unless confirmed.
- **HA when wanted, not required.** The same image and document shape run
  one node or an active/standby pair.
- **Built from standard parts:** systemd-networkd, nftables, keepalived,
  conntrackd, WireGuard, Podman. The only new code is the coordinator
  (`sparewalld`), its CLI (`sparewall`), and the web UI with its HTTP
  API gateway (`sparewall-httpd`).
- **A web UI and an HTTP API, off until you turn them on.** Status and
  health, the configuration as a form with a dry-run review, a zone
  policy matrix, history and rollback, and users and API tokens. Every
  call is checked against the user's or token's role.

## A taste

```yaml
schema: 1
cluster: { nodes: [fw1] }
management: { network: mgmt }
ports:
  fw1:
    uplink: { nic: "52:54:00:aa:00:01" }
networks:
  mgmt:  { port: uplink, role: management, addresses: { fw1: 10.0.99.2/24 } }
  wan:   { port: uplink, vlan: 10, role: wan, dhcp_client: true }
  users: { port: uplink, vlan: 20, addresses: { fw1: 192.0.2.2/24 }, vip: 192.0.2.1/24 }
zones:
  wan:   { networks: [wan] }
  users: { networks: [users] }
policy:
  users->wan: { action: accept, nat: masquerade }
  wan->self:  { action: drop }
dhcp:
  users: { pool: 192.0.2.100-192.0.2.199 }
```

```shell
sparewall apply -f site.yaml --confirm 120   # reverts unless confirmed
sparewall confirm
sparewall set networks.users.vip=192.0.2.254/24
sparewall get policy.'users->wan' -o yaml
sparewall history
```

The CLI runs on Linux and macOS workstations, from the release downloads
or with Homebrew:

```shell
brew install sparewall/tap/sparewall
```

Or turn on the web UI, add a user, and open `https://<node>/`:

```shell
sparewall set management.web=true
sparewall user add alice --role operator
```

More complete examples live in [`examples/`](examples/). Start with
[docs/getting-started.md](docs/getting-started.md), then
[docs/pairing.md](docs/pairing.md) and [docs/operations.md](docs/operations.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/sparewall-config` | Document model, JSON Schema, validation, canonical form, merge/patch/path operations |
| `crates/sparewall-render` | Renderers: networkd, nftables, sysctl, and the service providers (Kea, Unbound, chrony) |
| `crates/sparewall-core` | Generations, apply/confirm/rollback, health, adapters |
| `crates/sparewall-api` | Varlink interfaces (`org.sparewall.*`) shared by the daemon, CLI and gateway, and the OpenAPI description generated from them |
| `crates/sparewalld` | The coordinator daemon |
| `crates/sparewall` | The CLI |
| `crates/sparewall-httpd` | The HTTP API gateway, serving the web UI |
| `ui/` | The web UI (Angular) |
| `image/` | bootc Containerfile, systemd units, Quadlet files, provider images |
| `tests/` | VM test suites |
| `docs/` | Design and documentation |

## Building

```shell
cargo build --workspace
cargo test --workspace
```

The OS image is built from `image/Containerfile`; see `image/README.md`.

## License

Sparewall is licensed under the GNU General Public License v3.0 only; see
[`LICENSE`](LICENSE).
