# Operations

## Changing the configuration

| Task | Command |
| --- | --- |
| Show the document or a part of it | `sparewall get [path] [-o json\|yaml]` |
| Set values (one change, one confirm window) | `sparewall set networks.users.mtu=1400 dhcp.users.lease_time=7200` |
| Remove a key or map entry | `sparewall unset vpn.roadwarrior.peers.old-laptop` |
| Merge a fragment | `sparewall merge -f add-guest-vlan.yaml` |
| Replace the whole document | `sparewall apply -f site.yaml` |
| RFC 6902 operations | `sparewall patch --type json -f ops.json` |
| Preview | `sparewall diff -f fragment.yaml` or any change with `--dry-run` |
| Edit in `$EDITOR` | `sparewall edit [path]` |

Keys containing dots or `->` are quoted: `policy.'wan->self'.rules`.
Values are typed by the schema, so `vlan=20` is a number. Every change
carries the generation it was based on; if someone changed the
configuration in between, you get a conflict (exit code 4) instead of
overwriting their change.

Over SSH, changes get a 120-second confirm window by default; set
`--confirm 0` to apply without one, or `--no-prompt` to confirm later with
`sparewall confirm`.

## Generations

```shell
sparewall history            # newest first, with author and summary
sparewall rollback           # back to the previous generation
sparewall rollback 12        # to a specific one
sparewall export > site.yaml # canonical form, for git
```

A rollback is a new generation with the old document ("rollback to
generation 12" in `history`); the generation it replaced stays in history,
so a rollback can itself be rolled back. In a pair it reaches the peer like
any change, so it needs the peer reachable (or `--allow-diverge`). The
exception is a change still waiting for confirmation: `rollback` just
discards it, with or without the peer, since it was never pushed.

### A generation the node cannot read

If the coordinator cannot read the active generation's document at boot,
it runs the newest generation in its history that it can read, instead of
stopping. That happens to a document from a newer release after
`bootc rollback` (it says which schema revision it needs), or to a damaged
file. If no generation is readable, it runs the bootstrap configuration:
only the management port comes up, with SSH and HTTPS, forwarding is
dropped and the providers stop.

Either way health reports `generation` **failed**, naming the generation,
why it cannot be read and what runs instead, so in a pair the peer keeps
or takes the gateway addresses. The node stays in this state until you run
`sparewall rollback` to a generation it can read, or apply a whole document
with `sparewall apply -f`. `sparewall set` and other partial changes are
refused, since there is no document to change. A change left unconfirmed
reverts to what ran before it. Backups still work: the bundle keeps the
unreadable generation's files as they are.

### Schema revisions

A document's `schema` is the oldest schema revision that reads it: each
field names the revision that added it, and the coordinator records the
newest revision among the fields a change uses. You never need to set it;
any revision up to the newest the release reads is accepted. A document
that uses nothing new stays readable by older releases, so rolling a node
back to one of them keeps its configuration.

| Revision | Added | First read by |
| --- | --- | --- |
| 1 | Everything up to 0.2.0 | 0.2.0 |
| 2 | `management.web` | 0.3.2 (0.3.0 and 0.3.1 read the field but only `schema: 1`) |
| 3 | `updates.check`, `updates.window_minutes`, `networks.<name>.vmac`, `backup.retention`, `management.sources`; the value `updates.mode: windowed` | 0.4.0 |
| 4 | `logging.remote.ca`, `logging.remote.certificate`, `metrics.retention`, `metrics.retention_size`, `vpn.<name>.peers.<peer>.keepalive`, `vpn_clients`; the values `logging.remote.provider: syslog` and `metrics.mode: local` | 0.5.0 |
| 5 | `networks.<name>.ipv6`, `objects.<name>.suffixes`; the value `objects.<name>.type: ipv6`; an IPv6 address in a rule's `src` or `dst` or in `management.sources` | 0.6.0 |

In a pair, a change, rollback included, that needs a newer revision than
the peer reads is refused until the peer is upgraded: each node reports
the newest revision it reads, and one that does not say (0.3.1 or older)
reads revision 1. What the peer last said holds while it is out of
reach, and across a restart, so a change with `--allow-diverge` during
a cut sync link is checked against it. If the peer is rolled back
meanwhile, it refuses a generation it cannot read when one reaches it
(as `sync --from`), so nothing runs that cannot be read. Until a peer
has answered once (a new pairing), a change that needs more than
revision 1 waits for it; a new pairing itself is not checked this way:
each node checks its own apply.

## Secrets and tokens

Secrets never appear in the document; it refers to them as
`secret:<name>`.

```shell
sparewall secret set dns-tsig          # reads the value from stdin, or a prompt
sparewall secret list                  # names and versions only
sparewall token create prometheus --role monitor --expires 90d
sparewall token list
sparewall token revoke prometheus
```

A secret cannot be read back, so `secret set` helps you check what you
stored. At a prompt it asks twice (`--no-confirm` asks once). It warns
about a carriage return or whitespace at either end of the value, which
usually come with a paste. It also reports the stored length:

```console
$ sparewall secret set backup-password --fingerprint
Value for backup-password:
Value for backup-password again:
Stored backup-password (version 2, cluster): 32 bytes, fingerprint 9f3a1c0d.
```

To compare the fingerprint with the copy in your password manager:

```shell
printf %s "$value" | sha256sum | cut -c1-8
```

`--fingerprint` is opt-in: it narrows the search for a weak value, so
use it for keys and long random passwords only.

Roles: `monitor` (health and metrics), `viewer`, `operator` (change,
confirm, roll back, sync) and `admin`.

### The admin console password

`admin` has no password by default: SSH takes keys only, and root is
locked. For a break-glass login at the console, give it one:

```shell
sparewall passwd           # asks twice; only the hash leaves your machine
sparewall passwd --lock    # back to keys only
```

The hash is the `admin-password` cluster secret: both nodes of a pair
set it (a node that was down catches up when it rejoins), the encrypted
backup carries it, and a restore or reinstall sets it again. Log in as
`admin` on the console, then `sudo` as usual.

Password logins over SSH stay off unless the document opts in, which is
applied and confirmed like any change (and warned about by `validate`):

```yaml
management:
  network: mgmt
  ssh:
    password: true    # keys still work
```

The firewall still limits SSH to what the policy allows (the
anti-lockout rule opens it on the management network only).

### Tokens for scripts

As root (`sudo sparewall`, or over SSH with `sudo sparewall bridge`),
every command acts with full rights and needs no token. A token lets a
script or another user act with a role instead, without root: with
`SPAREWALL_TOKEN` set, the CLI uses the restricted socket
(`/run/sparewall-api/org.sparewall.Api`), which any local user may
reach, and every call there is checked against the token's role.

```shell
sudo sparewall token create ci --role operator --expires 90d -q > ci.token
SPAREWALL_TOKEN=$(cat ci.token) sparewall set networks.users.mtu=1400
```

| Role | May |
| --- | --- |
| `monitor` | Health (and over HTTPS, verbose health and `/metrics`) |
| `viewer` | Also read the configuration, history, status and events; validate; check for upgrades |
| `operator` | Also apply, confirm, roll back, sync and fail over |
| `admin` | Also secrets, tokens, backups, VPN client configurations, upgrades, acknowledging health checks, and turning `management.anti_lockout` off |

A refused call exits with code 6. Changes made with a token are
recorded as `token <name>` in the history and in the journal. Revoking
a token, or its expiry, takes effect at once, also on connections
already bound to it. From another machine, point a context's
`remote_command` at the restricted socket and keep the token on your
side: `sparewall bridge --socket /run/sparewall-api/org.sparewall.Api`
runs without `sudo`.

### Users

People log in to the web UI as named users, each with one of the roles
above. A `monitor` user can't sign in: the UI needs `viewer` at least.
`admin` is built in, and its password is the console password
(`sparewall passwd`). The others:

```shell
sparewall user add alice --role operator   # asks for the password
sparewall user list
sparewall user role alice viewer
sparewall user passwd alice                # or --lock
sparewall user remove alice
```

Only the password's SHA-512 crypt hash leaves your machine. Users are
cluster secrets, so the peer and the encrypted backup have them too. A
login opens a session of 12 hours on the node that took it. Changing a
user's password or role, or removing it, ends its sessions at once.
After five failed logins, a user's logins are refused for 15 minutes
(attempts made at once count before any is checked). Attempts with
names that are not users are counted apart, so they cannot lock a user
out.

### The web UI and HTTP API

A node serves neither until the document turns them on:

```shell
sparewall set management.web=true
```

They share the HTTPS port with the health endpoints, so they are
reached where those are, on the management network, with the same
certificate (the `mgmt` one from `tls.certificates`, or the node's
self-signed one). The coordinator keeps the port and passes every
other path to `sparewall-httpd`, a sandboxed service that runs only
while `management.web` is on and holds no authority of its own: each
call is made with the caller's token or session, under that role.

Scripts call the API with a token:

```shell
curl -X POST -H "Authorization: Bearer $TOKEN" \
    https://fw1.example.net/call/org.sparewall.Firewall.Status
```

`/openapi.json` describes every call, and the web UI's **API** page
shows it, role by role, with a `curl` example for the node;
[docs/api](api/README.md) has the
conventions, errors and statuses. Turning `management.web` off stops the
service, and SSH, the console and the anti-lockout rule never depend on
it.

People open `https://<node>/` and sign in as one of the users above.
The UI has these pages:

- **Status:** the node's status and health, updated as they change.
- **History:** the generations, from which an operator can roll back.
- **Configuration:** a form built from the document's schema. It shows
  one section at a time (`/config/<section>`, so a section can be
  bookmarked), chosen from a sidebar grouped into Network, Firewall,
  Services, VPN and System. A search finds any setting by its name, its
  path or words in its description.
  - An operator edits the form, then reviews what the change does. The
    review is the node's own dry run: the changed paths, the subsystems
    the change touches, and any warnings.
  - The operator then applies the change, with a window to confirm it
    in: two minutes unless changed.
- **Zone policy:** every pair of zones as a matrix, from each row to
  each column.
  - Each cell shows the pair's action, NAT, logging and number of
    rules.
  - A pair without a policy shows its default: dropped, except what the
    firewall itself sends.
  - Selecting a pair edits its policy. Edits to several pairs are
    reviewed and applied together.
- **Users and API tokens:** for admins.
  - A new password is hashed in the browser, as `sparewall user passwd`
    hashes it on your machine, so only the hash reaches the node.
  - A new token is shown only once.

While a change waits for confirmation, every page shows how long is
left, with Confirm and Revert now. Each page offers only what the
user's role allows, and the node checks every call regardless. The UI
loads nothing from outside the node.

## IPv6 on the WAN

A node's WAN takes IPv6 from the upstream (#213). A pair's follows the
master: see [Running an HA pair](pairing.md#ipv6).

```shell
sparewall set networks.wan.ipv6.mode=dhcpv6     # or ra, or static
```

- **`dhcpv6`:** the upstream's router advertisements give the default
  route, and an address by SLAAC when they carry a prefix. The DHCPv6
  client starts on the first advertisement, whatever its M flag says, and
  asks for an address and a delegated prefix of `prefix_length` (default
  56; the ISP may grant another). Its DUID is the WAN's MAC address
  (DUID-LL), so the node keeps its lease and prefix across a reboot or a
  reinstall on the same NIC.
- **`ra`:** an address by SLAAC only, and no delegated prefix.
- **`static`:** the link's `prefix`, the node's address in it, and the
  upstream router:

  ```yaml
  ipv6:
    mode: static
    prefix: "2001:db8:ffff::/64"
    addresses: { fw1: "2001:db8:ffff::2" }
    gateway: fe80::1
  ```

- **The firewall:** the WAN accepts router advertisements (in `dhcpv6`
  and `ra` modes) and DHCPv6 replies, to the node only; everything else
  from the WAN zone is its policies', for IPv6 as for IPv4. A dynamic
  `ipv6` object on the WAN holds the node's IPv6 address (`source:
  address`) or the link's prefix from the router advertisements
  (`source: prefix`; empty when they carry none), as an IPv4 WAN's holds
  its subnet. The delegated prefix is not the WAN's: it is the inside
  networks', whose own prefix objects hold their /64s.
- **Forwarding** stays off until an inside network has IPv6: a WAN alone
  gives the node itself IPv6, and routes nothing.
- **What it has:** `networkctl status wan0` shows the addresses, the
  DHCPv6 lease and the delegated prefix.

## IPv6 on inside networks

Each inside network with `ipv6` gets a /64 and advertises it (#214). In
a pair the gateway is `fe80::1` on the master, and the nodes take no
address in the /64: see [Running an HA pair](pairing.md#ipv6).

```yaml
networks:
  lan:
    ipv6: { mode: delegated, subnet_id: 1 }   # a /64 of the WAN's delegated prefix
  lab:
    ipv6: { mode: static, prefix: "2001:db8:0:2::/64" }
```

- **Addresses:** a standalone node is `::1` in the /64; hosts configure
  themselves by SLAAC from its router advertisements. DHCPv6 on inside
  networks is a later feature (#217).
- **A new delegated prefix** renumbers the network by itself: the node
  takes `::1` in the new /64 and advertises it. networkd would simply
  stop advertising the old one (systemd #29651), leaving hosts to prefer
  their old address for up to 30 minutes, so the node goes on
  advertising it as deprecated (a preferred lifetime of 0) while it is
  still valid, for at most 2 hours (#232). Hosts keep their address
  there for existing connections, but pick the new one for new ones. The
  last prefix in use is kept across a reboot, so a node that comes back
  with another deprecates the old one too.
- **DNS:** where DHCPv4 hands out the node as the resolver (`dns` serves
  the network, and `dhcp.<network>.options.dns` names no other servers),
  its advertisements name it too, with DHCP's search domain: on a static network by its
  address there, on a delegated one by its link-local address, which a
  new prefix does not change. Unbound then also answers over IPv6, on
  every address of the node, and the firewall drops IPv6 to its DNS port
  from every interface but the served networks', whatever a policy to
  `self` accepts (`service:dns-served-only`). Where DHCPv4 names other servers (a
  directory's, say), the advertisements name none, and dual-stack
  clients keep asking those over IPv4, AAAA records included.
  `ipv6.dns` names the resolvers outright, in place of all that, for
  servers that have IPv6 addresses or for IPv6-only clients; an empty
  list names none:

  ```yaml
  networks:
    lan:
      ipv6: { mode: delegated, subnet_id: 1, dns: ["2001:db8:0:5::53", "2001:db8:0:5::54"] }
  ```

  Each is a fixed, routable address (not link-local). Clients reach
  those servers through the policies, as any other host; nothing on the
  node opens for them.
- **Forwarding** is on once an inside network has IPv6. A network routed
  through a [VPN client](#vpn-clients-leaving-through-a-provider) gets no
  IPv6 beyond the node while the client's kill switch is on: the tunnel
  is IPv4 only. What crosses
  between zones is the policies', for IPv6 as for IPv4, without NAT.
- **Objects:** a dynamic `ipv6` object on an inside network holds its
  /64 (`source: prefix`) or the node's address (`source: address`).
  Hosts by suffix (`suffixes`) follow a static prefix; in a delegated
  one they are not built yet: name their addresses instead.

### Checking IPv6

`sparewall status` lists each network with IPv6, as networkd has it now:

```text
ipv6:
  lan        lan0 delegated; advertises 2001:db8:100:1::/64
  wan        wan0 dhcpv6; 2001:db8:ffff::100/128; delegated 2001:db8:100::/56 (preferred 30m, valid 1h); default via fe80::1
```

The status API's `ipv6` holds the same, with lifetimes in seconds left,
and the web UI's status page shows it in an IPv6 card. The web UI's
editor shows a network's `ipv6` fields only for the mode, and the kind
of network (WAN or inside), they apply to.
Health's `ipv6` check is degraded while a WAN with IPv6 has no IPv6
default route, or a `dhcpv6` WAN has no delegated prefix for the
`delegated` networks. On `/metrics`, `sparewall_ipv6_default_route` is 1
while a WAN has its default route, and
`sparewall_ipv6_delegated_prefix_valid_seconds` and
`…_preferred_seconds` count down the delegated prefix's lifetimes: alert
when the valid lifetime runs low, as the ISP has stopped renewing it.

## Remote-access VPN

Clients generate their own keys; only public keys go in the document:

```shell
wg genkey | tee laptop.key | wg pubkey
sparewall set "vpn.roadwarrior.peers.laptop.public_key=<public key>" \
              "vpn.roadwarrior.peers.laptop.addresses=[10.99.0.11/32]"
sparewall vpn client-config laptop --qr
```

### More ports, for restrictive networks

Hotel and guest networks often block UDP except to the DNS and HTTPS
ports. `extra_ports` makes the instance answer on those too: they are
redirected to the listen port on the WAN gateway address only, so
nothing else on the WAN interfaces changes, and the clients' traffic is
the same WireGuard on another port.

```shell
sparewall set "vpn.roadwarrior.extra_ports=[53, 443]"
sparewall vpn client-config laptop --port 443
```

Validation refuses a port that a UDP forward from the WAN, DNS or NTP
served on the WAN, or another VPN instance already uses.

### Keeping an existing server key

Clients know the server by its public key, so a VPN moved from another
WireGuard server keeps working for them if Sparewall uses the same
private key. The coordinator generates a key only for an instance that
has none, so store the old one before the first apply that defines the
instance, as the secret named `vpn-<instance>`:

```shell
sparewall secret set vpn-roadwarrior < server.key   # the base64 private key
```

It is a cluster secret: in a pair it reaches the other node through the
sync tunnel. Set it on the node you apply the document to; a generation
pushed to the peer never generates keys. Setting it later replaces the
generated key at once (the interface is recreated), but clients
configured with the generated key then need the new one.

### Preshared keys

A peer may also use a WireGuard preshared key. Like the server key it is
a cluster secret, referenced by name; the document never holds it:

```shell
wg genpsk | sparewall secret set psk-laptop
sparewall set "vpn.roadwarrior.peers.laptop.preshared_key=secret:psk-laptop"
sparewall vpn client-config laptop --qr      # now includes PresharedKey
```

Changing the secret takes effect at once. While a referenced key is not
set, the apply warns and health is degraded (`vpn`): that peer cannot
complete a handshake. For clients moved from another server, store each
client's existing preshared key the same way.

After a failover, or the gateway's handover during an upgrade, each
client is cut off until it makes a new handshake with the new master. A
client sending traffic recovers after about 16 seconds, or within a few
seconds if its session is more than two minutes old; an idle client
recovers the next time it sends. These are the times the pair test
measures with Linux WireGuard clients; other clients use the same protocol
timers.

The pair syncs the state of connections inside the tunnel, so a TCP
connection survives the outage if its retransmissions and the
application's timeouts outlast it; one with a shorter timeout may give up.
`PersistentKeepalive` in the client config keeps NAT mappings open; it
does not start the recovery timer, so lowering it does not shorten the
outage. A client that cannot wait can reconnect (`wg-quick down`/`up`) to
handshake at once.

## Site-to-site tunnels

A peer with an `endpoint` is another site: the node connects to it as
well as accepting it, and routes the networks behind it through the
tunnel. It is a peer of a `vpn` instance like any other, and the
instance's zone takes policies like any zone:

```yaml
vpn:
  branch:
    listen_port: 51821
    endpoint: hq.example.org          # what the other site connects to
    addresses: [10.98.0.1/30]
    zone: branch
    peers:
      office-b:
        public_key: "<the branch's public key>"
        endpoint: office-b.example.net:51821
        addresses: [10.98.0.2/32, 192.168.20.0/24]   # its tunnel address, and its network
        keepalive: 25
zones:
  branch: {}
policy:
  users->branch: { action: accept }   # no nat: the sites see each other's addresses
  branch->users: { action: accept }
```

- **Routes:** the peer's addresses outside the tunnel's subnet are
  routed through it. Validation refuses one that is, or overlaps, a
  network of this node, a tunnel's subnet or another site's network, and
  the default route (a tunnel for all traffic is a different feature,
  #149).
- **`keepalive`** (seconds) keeps the tunnel up while it is idle, and
  open through NAT on either side. With it, health is degraded
  (`tunnels`) when the peer has had no handshake for three minutes.
- **Endpoint names** are resolved when the interface is created, and
  again whenever the peer has had no handshake for over two minutes, so a
  site on a dynamic address is found again.
- **The other site's configuration:** `sparewall vpn peer-config
  office-b` (the same as `client-config`) prints it, for wg-quick: its
  tunnel address, the port its endpoint names, this node's public key and
  endpoint, and as `AllowedIPs` (which wg-quick routes) the tunnel's
  subnet and this node's networks other than the WAN, or the instance's
  `client_allowed_ips`. Fill in its private key. Between two Sparewall
  nodes, each document lists the other as a peer instead.

In a pair, site-to-site peers need exactly one WAN, with static
addresses, a gateway address and a gateway (not one DHCP lease for the
pair). Only the master sends to a site, from the gateway address:
WireGuard marks its packets, and on the master they leave through a
routing table keepalived fills with routes from that address; on the
backup the table is empty, and the firewall drops what the backup would
send from its own address. After a failover the new master starts the
tunnel itself, without the other site's help, within its `keepalive`
and a handshake. In the pair test, with a 10-second keepalive, the new
master had the tunnel up 8 seconds after the master was lost, and 5
seconds after the gateway moved in a rolling upgrade.
Connections inside the tunnel are synced, as for remote access.

## VPN clients: leaving through a provider

A node can be a WireGuard client of a service it does not run: a VPN
provider, a cloud host, another organisation's hub. The networks it
routes then reach everything but this node's own networks through the
tunnel; the node's own traffic, and every other network's, keep the WAN.

```yaml
vpn_clients:
  egress:
    private_key: secret:provider-key     # as the service issued it
    addresses: [10.64.12.34/32]          # the address it assigned
    zone: egress
    peer:
      public_key: "<the service's public key>"
      endpoint: nl1.provider.example:51820
      keepalive: 25                      # the default
      # preshared_key: secret:provider-psk
    dns: [10.64.0.1]                     # optional: its resolvers
    route:
      networks: [guests]
      kill_switch: true                  # the default
zones:
  egress: {}
policy:
  guests->egress: { action: accept }
```

```shell
sparewall secret set provider-key < provider.key
```

- **Routing:** the client's tunnel has a routing table of its own,
  with the service as the default route. The routed networks' traffic
  looks up the main table first without its default route, so it still
  reaches this node's other networks and tunnels, then the client's.
- **The service sees one address:** what leaves through the tunnel takes
  the tunnel address, whatever the policy's `nat` says.
- **Kill switch:** the routed networks' traffic to the WAN is dropped,
  so while the tunnel is down it goes nowhere. With `kill_switch: false`
  it may leave through the WAN instead (validation warns).
- **IPv6:** the tunnel carries IPv4 only. A routed network with `ipv6`
  keeps IPv6 to the node and the other inside networks, but with the
  kill switch its IPv6 to the WAN is dropped, so nothing leaves around
  the tunnel; without it, its IPv6 leaves by the WAN. Validation warns
  of either.
- **DNS:** DHCP hands the routed networks the client's `dns`, unless a
  network sets its own servers (`dhcp.<network>.options.dns`). The
  service's resolvers are reached through the tunnel; Unbound on the
  node is not asked.
- **Health:** `tunnels` is degraded when the service has not completed a
  handshake for three minutes, and `vpn` while a referenced key is not
  set. An endpoint named by DNS is resolved again while the tunnel is
  quiet.
- **In a pair** both nodes use the same key and address, so the service
  sees one client. Only the master's tunnel is up: the new master brings
  it up when it takes over, and connections through it carry on if the
  service keeps its translation of the tunnel address (the pair test's
  does: the service saw the new master 3 seconds after the old one went,
  and a TCP connection through the tunnel carried on). A service that
  ties a session to the client's own address may drop them.

## Monitoring

| Endpoint | Purpose |
| --- | --- |
| `/livez` | The coordinator answers |
| `/readyz`, `/healthz` | 200 when ok or degraded, 503 when failed |
| `/readyz?verbose`, `/readyz/<check>` | Detail (needs a token) |
| `/metrics` | Prometheus metrics: the appliance's own and the host's from node\_exporter, which listens only on localhost (needs a token unless `metrics.mode: external`; `off` disables it). With `metrics.mode: local`, loopback needs no token, for the [local Prometheus](#history-a-local-prometheus) |

```shell
curl -k -H "Authorization: Bearer $TOKEN" https://fw1/metrics
```

### History: a local Prometheus

Without an external Prometheus, each node can keep its own history:

```shell
sparewall set metrics.mode=local
sparewall set metrics.retention=30d metrics.retention_size=2GB   # optional
```

- **What it keeps:** what `/metrics` shows (the coordinator's metrics
  and node\_exporter's), every 15 seconds, and Prometheus's own, with
  the node's name as the `instance` label. In a pair each node keeps its
  own; for one view of both, use an external Prometheus.
- **How long:** `metrics.retention` (default `15d`) and
  `metrics.retention_size` (default `1GB`; Prometheus counts in powers
  of 1024) cap it: whichever is reached first, the oldest goes. A change
  to either reloads Prometheus, which keeps what it has.
- **How it runs:** in its own container, `sparewall-prometheus`, as
  `nobody` with no capabilities, its memory capped at 512 MB, and after
  everything else for CPU and disk. It listens on 127.0.0.1:9090 only
  and scrapes `/metrics` over loopback, which needs no token in this
  mode; from the management network `/metrics` needs one, as without a
  `metrics` section.
- **Querying:** `org.sparewall.Metrics.Query` and `QueryRange` take
  PromQL, for any token or session from `monitor` up. Over HTTPS (with
  `management.web` on):

  ```shell
  curl -k -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"query": "rate(node_network_receive_bytes_total{device=\"uplink\"}[5m])"}' \
    https://fw1/call/org.sparewall.Metrics.Query
  ```

  `QueryRange` takes `start` and `end` (RFC 3339 or Unix seconds) and a
  `step` (`1m`). A call answers 400 when the node keeps no history, 422
  for a query Prometheus refuses, and 503 while Prometheus is down.
- **Health:** a stopped Prometheus makes `services` degraded, never
  failed: it carries no traffic.
- **Not backed up:** the history (the volume `sparewall-prometheus-data`)
  is not in the backup bundle and does not survive a reinstall. `external`
  or `off` stops Prometheus and keeps the volume, which `local` uses again
  (less what has aged out meanwhile). To delete it, with Prometheus
  stopped: `podman volume rm sparewall-prometheus-data`.

**At login**, the node says how it is: a line with its role, generation
and health, and one line per check that is not ok, with what to do
about it (a pending change to confirm, SELinux denials to acknowledge).
The coordinator rewrites the banner (`/run/motd.d/50-sparewall`) within
seconds of a change and removes it when it stops; each version shows
when it was written.

### What health verifies

Readiness (`/readyz`, the VRRP health check, the applied hash the pair
compares, `sparewall_config_applied`) reflects these checks of the
running system, each repeated on every health request:

| Check | Verifies | Does not verify |
| --- | --- | --- |
| `generation` | A configuration is applied: degraded in bootstrap mode, failed when the active generation cannot be read ([above](#a-generation-the-node-cannot-read)) | |
| `applied` | The last activation of the desired generation succeeded, and the live firewall still matches it | Anything the other checks do not |
| `nft` | The live `inet sparewall` table matches, rule for rule, what was loaded for the generation: chains with their hooks and policies, every rule, static set elements. What traffic changes (counters, quota use, `last` timestamps, element timeouts), handles, and the sets networkd fills at runtime are excluded. If the table cannot be read back right after a load, the node fails this check until the next reload | Tables other software owns |
| `links` | Every interface that carries traffic exists and is up (failed otherwise, so VRRP moves the gateway addresses). A trunk shared by the sync VLAN and service networks counts as carrying traffic | Addresses, routes or bond membership on them |
| `replication` | Every replication-only interface (the sync network, and a port carrying nothing else) exists and is up. Losing one is **degraded**, never failed: traffic still flows, so the gateway addresses stay where they are while the pair stops replicating | |
| `services` | Every provider unit the generation needs (Kea, Unbound, keepalived, conntrackd, ulogd, journal-upload or rsyslog, Prometheus) is active in systemd. A management service down (the web UI, Prometheus) is degraded, not failed | That a daemon still runs the files installed for it; those passed the daemon's own config test before they were installed |
| `pair`, `tls`, `backup` | Sync tunnel and peer state, certificate validity, the last backup | |
| `tunnels` | On the node that holds them (standalone, or the master), every site-to-site peer with a `keepalive`, and every VPN client, has had a handshake in the last three minutes. Degraded, never failed | Peers without a keepalive, whose idle tunnels have no handshakes |
| `ipv6` | Once a network has IPv6: each WAN with IPv6 has an IPv6 default route, and a `dhcpv6` WAN has a delegated prefix for the `delegated` networks. Degraded, never failed: IPv4 still flows | That hosts on the inside networks have taken addresses |
| `selinux` | SELinux is enforcing, and no denial by the coordinator's domain or on its types has been logged since the last acknowledgement. Degraded, never failed; it stays degraded, across reboots, until `sparewall health ack selinux` (which records who acknowledged). `sparewall_selinux_denials_total` on `/metrics` counts every denial, for alerting | Denials before sparewalld started, or of other domains on other types |

Any change to the firewall made outside Sparewall (`nft flush`, an extra
rule, a changed policy) fails `nft` and `applied`, so the node reports
**failed**: it leaves the VRRP master role and the pair shows
`apply-failed`. To restore it, reload the generation:
`systemctl restart sparewalld` (or apply any new change).

### Logged traffic

`log: true` logs the packets that reach a policy's default action, match
a rule, or are forwarded:

```shell
sparewall set "policy.'guests->users'.log=true"
sparewall set "policy.'users->self'.rules.ssh.log=true"
```

Each hit becomes a journal entry from sparewalld, with the rule
(`guests->users:default`, `users->self:ssh`) and a one-line summary of
the packet as fields:

```shell
journalctl -u sparewalld TARGET=sparewall::rules \
    --output=verbose --output-fields=F_RULE,F_PACKET
journalctl -u sparewalld F_RULE='guests->users:default'   # one rule
```

`F_RECORD` holds ulogd's full JSON record. Hits go to the journal and,
with `logging.remote`, wherever the journal is forwarded.

### Forwarding logs

`logging.remote` sends the journal, rule hits included, to a collector
off the box. Each node of a pair sends its own.

To a **syslog collector** (rsyslog, syslog-ng, Graylog, a SIEM), with
`provider: syslog`. The node runs rsyslog, which reads the journal and
sends each entry as RFC 5424 syslog. A rule hit's message carries the
rule and the packet (`rule hit rule=guests->users:default tcp
10.1.2.3:51000 -> 10.1.1.5:22 in=guests out=users`).

```yaml
logging:
  remote:
    provider: syslog
    destination: logs.example.org     # host, or host:port
    protocol: tcp                     # udp (the default), tcp or relp
    tls: true
    ca: |                             # optional: a private CA
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

| `protocol` | Default port | Delivery |
| --- | --- | --- |
| `udp` | 514 | Fire and forget: a message lost on the way is gone, and nothing is encrypted |
| `tcp` | 514, or 6514 with `tls` (RFC 5425) | Reliable while connected; a message in flight when the connection breaks can be lost |
| `relp` | 2514 | Each message acknowledged by the collector; none lost across a broken connection |

- **TLS:** with `tls: true`, the collector's certificate must be valid
  for the destination's host name, signed by `ca` or by a CA the system
  trusts.
- **Client certificates:** for a collector that requires one, store the
  node's private key and certificate (PEM, in one secret) and name it:

  ```shell
  cat fw-key.pem fw-cert.pem | sparewall secret set log-client
  sparewall set logging.remote.certificate=secret:log-client
  ```

  RELP over TLS always needs one: without it, librelp offers only
  anonymous TLS, which collectors refuse. It is a cluster secret, so a
  pair's nodes share it; the collector then sees the same certificate
  from both. Health's `log-forwarding` check is degraded while the
  secret is missing or holds no key and certificate.
- **While the collector is unreachable,** messages wait in memory and
  then on disk under `/var/lib/rsyslog`, up to 256 MB, and are sent when
  it is back, also across a restart. With the queue full, rsyslog stops
  reading the journal, and later carries on where it stopped: what
  the journal still holds is not lost.
- **The start:** a node forwards from the moment forwarding is turned
  on, not the journal's earlier history.

To a **systemd-journal-remote** collector, with `provider:
journal-upload` (the default), which keeps every journal field:

```yaml
logging:
  remote:
    destination: https://logs.example.org:19532
```

Changing the provider stops the one no longer used.

## Certificates

Each node serves a self-signed certificate on the management network
until a certificate under `tls.certificates` is issued (by preference the
one named `mgmt`). ACME orders use the DNS-01 challenge. In a pair only
the master orders; the certificate reaches the peer as a cluster secret.
Renewal starts at two-thirds of the lifetime, and the `tls` health check
degrades when an order fails or a certificate is within a week of
expiring.

With an RFC 2136 server (BIND, Knot, PowerDNS), the coordinator updates
the zone itself:

```yaml
tls:
  certificates:
    mgmt:
      names: [fw.example.org]
      acme:
        directory: https://acme-v02.api.letsencrypt.org/directory
        email: ops@example.org
        dns:
          provider: rfc2136
          credentials: secret:dns-tsig     # hmac-sha256:keyname:base64secret
          options: { server: ns1.example.org, zone: example.org }
```

Any other `provider` is a [lego provider](https://go-acme.github.io/lego/dns/)
code (`gcloud`, `cloudflare`, `route53`...). lego runs the order in its
container. The credentials secret holds the provider's secret variables
as `KEY=value` lines, and `options` its other variables, plus lego's own
(`LEGO_DNS_RESOLVERS`, `LEGO_DNS_PROPAGATION_WAIT`):

```shell
printf 'CLOUDFLARE_DNS_API_TOKEN=%s\n' "$TOKEN" | sparewall secret set cloudflare-dns
sparewall set 'tls.certificates.mgmt.acme.dns={"provider": "cloudflare", "credentials": "secret:cloudflare-dns"}'
```

Scope the credential to the `_acme-challenge` records where the DNS
service allows it, or delegate `_acme-challenge` to a zone of its own: a
leaked credential can otherwise issue certificates for the whole zone.
Each node keeps its own lego account under `/var/lib/sparewall/lego`.

## Backup and restore

A bundle holds the active document, recent generations, the cluster
secrets, DHCP leases and the running image digest. Leases granted after
the backup are not in it, but Kea pings each address before offering
it, so one still in use is skipped (turn this off with
`dhcp.ping_check: false`, or per network, where ICMP echo is filtered). Node private keys are
never included: a rebuilt node of a pair is re-paired with its new sync
key.

The secrets are sealed (Argon2id and ChaCha20-Poly1305) with the
`backup-password` cluster secret, which is also the restic repository
password. **Keep a copy of it outside Sparewall**, in a password manager:
without it a bundle restores everything but the secrets. With no
`backup-password` set, bundles leave the secrets out.

```shell
sparewall secret set backup-password
sparewall set backup.enabled=true \
    backup.repository=rest:https://backup.example.net/fw1 \
    backup.schedule=hourly      # a systemd calendar expression
sparewall backup                # a bundle now, sent to the repository
sparewall backup --check-password        # try your copy (any context)
```

**Check the password before relying on the backups.** After setting it
and writing a bundle, run `sparewall backup --check-password` and paste
the password from your password manager. Through a context (`-c fw1`, or
`--host`) the node answers (admins only): whether it is the stored
`backup-password`, and whether it opens the secrets in the newest bundle
on the node, which may predate a change of the password. Nothing derived
from the stored password comes back, and a wrong one is answered after a
second. On the node itself, `sudo sparewall backup --check-password`
reads the newest bundle directly, which also works with sparewalld
stopped. Neither needs restic or the repository, and neither changes
anything. `--file` checks another bundle, and works on any machine the
bundle is copied to. A wrong password exits non-zero. Get it right before the first backup
reaches the repository: restic initialises the repository with the
password, and changing it later orphans the snapshots already there.

`backup.repository` is any restic repository: SFTP, S3-compatible
storage or a restic REST server (a local path must be under
`/var/lib/sparewall`, which sparewalld can write). The repository is
initialised on first use. Credentials such as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` go as `KEY=value` lines in a secret named by
`backup.credentials` (`secret:backup-s3`). Each run sends one snapshot
(host = node name, tag `sparewall`). The node keeps its newest five bundles under
`/var/lib/sparewall/backups`.

**Retention.** After each successful send, the node forgets its own old
snapshots in the repository (`restic forget --host <node> --tag
sparewall`), never its peer's, by restic's keep rules:

```yaml
backup:
  retention:          # the default, when a repository is set:
    hourly: 48        # --keep-hourly
    daily: 30         # --keep-daily
    weekly: 12        # --keep-weekly
    monthly: 24       # --keep-monthly
    # last, yearly: --keep-last, --keep-yearly
```

A snapshot is kept if any rule keeps it, so the default keeps two days at
full resolution and two years at monthly resolution. Rules that keep
nothing are refused; `retention: {enabled: false}` keeps every snapshot,
for a repository pruned elsewhere. In a pair, the master (or a standalone
node) also prunes (`--prune`), which removes the data no snapshot refers
to; the standby only forgets. Both wait up to ten minutes for the other's
repository lock (`--retry-lock`) instead of failing. A retention that
fails leaves the backup itself successful: the `backup-retention` check
turns **degraded**, and
`sparewall_backup_retention_last_success_timestamp_seconds` stops moving.
`retention` is schema revision 3.

A failed backup makes health **degraded**, and
`sparewall_backup_last_success_timestamp_seconds` lets an alert catch
backups that stopped.

To restore on a reinstalled node, before it is configured:

```shell
systemctl stop sparewalld.service sparewalld.socket
sparewall restore --repository rest:https://backup.example.net/fw1   # newest bundle of this node
# or: sparewall restore -f sparewall-fw1-g12-....tar.gz
systemctl start sparewalld.socket sparewalld.service
```

`restore` asks for the backup password (or takes `--password-file`;
`--no-secrets` skips them). The reinstalled node keeps its own install
identity, so a management port with a new MAC address still works.

## Upgrades

Nodes run a signed bootc image and follow a channel, `stable` or
`testing`, of the repository they were installed from:

```shell
sparewall upgrade --check                 # is a newer image available?
sparewall upgrade                         # the document's updates.channel
sparewall upgrade --channel stable        # once, to another channel
sparewall upgrade --image mirror.example:5000/sparewall:stable
```

**Choosing a channel.** Set it in the document, which changes nothing
until the next upgrade and reaches both nodes of a pair:
`sparewall set updates.channel=stable`. Without it, a node follows the
channel it tracks, and a node that tracks a build or a release (one
installed from a release's ISO or disk image, which come from a build tag)
follows `stable`. `--channel` is for one upgrade; the node then tracks
that channel.

**Rebuilds.** Between releases, the current release is rebuilt on newer
Fedora base images when they bring security fixes, or at least monthly:
the same Sparewall source, version `X.Y.Z+rN` (`0.4.0+r2` is the second
rebuild of 0.4.0). It passes the same tests as a release before `stable`
moves to it, and the release's notes list each rebuild and the advisories
it picks up. A node offers it as "a rebuild of 0.4.0", and upgrades to it
as to any image.

**Never backwards by accident.** Images carry their Sparewall version
(`org.sparewall.version`), and `--check` shows it next to the node's own.
A newer version is offered; the same version is offered when the image
differs (a rebuild, such as base image updates); an older one is not, and
`sparewall upgrade` refuses it. Moving to `stable` from a newer `testing`
build therefore waits until `stable` passes it. `--allow-downgrade` moves
to an older release anyway: roll the configuration back to a generation
that release reads first ([a generation the node cannot
read](#a-generation-the-node-cannot-read)). Images from before 0.3.2 carry
no version, so they are compared as before, by digest only, and
`--check` says so.

On a standalone node this stages the image and reboots (one reboot of
downtime). In a pair the master runs it, whichever node you start it on:

1. The master downloads its own image without applying it, while it still
   has its own WAN. A download that keeps failing stops the upgrade here,
   with nothing changed.
2. The standby is upgraded and rebooted.
3. Once the standby is back on the new image, healthy and in sync, the
   master hands it the gateway addresses (established connections carry
   over through conntrackd), applies the image it downloaded, which needs
   no network, and reboots.

Started on the standby, the command shows the master's progress until the
standby reboots; follow the rest with `sparewall status` or the master's
journal. A failed gate before the handover stops the upgrade and the
master keeps the addresses. After the handover, a failure gives them back
to the master. A downloaded image that was never applied is discarded at
the next reboot. `bootc rollback` and a reboot return a node to its
previous image.

If a run stops with one node on the new image (a failure after the
handover, or a reboot during it), run `sparewall upgrade` again. A master
that already runs the target upgrades only the standby and keeps the
gateway addresses: no handover, no reboot of the master. Releases before
0.3.2 hand over and reboot the master regardless; with one of those as
master, run `sudo bootc upgrade && sudo systemctl reboot` on the standby
instead, which moves no addresses. The containers signature policy
rejects images from anywhere but `ghcr.io/sparewall`, whose images must
carry a valid signature; to upgrade from a mirror, add it to
`/etc/containers/policy.json` with its own signature requirement.

**Which upgrades are tested.** Before a release, CI upgrades a single
node and a pair from the newest earlier release to it, and a pair from
the newest release of the previous minor series too (for 0.3.2: from
0.3.1, and from 0.2.0), each installed from that release's own disk
image, then rolls one node back with `bootc rollback`. Upgrade from one of
those; from anything older, upgrade through them in turn.

**Checking in the background.** Each node, both nodes of a pair, asks
the registry what its channel offers a few minutes after it starts and
about every 6 hours after that, with the same comparison as
`--check`. It contacts only the registry of the image it would upgrade to
(`ghcr.io` unless the node was installed from a mirror), with `skopeo
inspect`, which reads the image's manifest and labels without downloading
it. The answer is in `sparewall status -o json` (`update`), and in
`/metrics`:

| Metric | Meaning |
| --- | --- |
| `sparewall_update_available{kind}` | 1 when the channel offers a `newer` version, a `rebuild` of this one, or a `different` image whose version cannot be read; 0 with `kind="none"` |
| `sparewall_update_last_check_success_timestamp_seconds` | When a check last succeeded |

When an update is available, `sparewall status` and the login banner
say so in one line ("update: 0.4.1 is available (running 0.4.0); sparewall
upgrade"), which changes neither the health summary nor any exit code,
and `sparewall upgrade --check` shows when the node last checked on its
own. The web UI shows the same on its status page, with a link to
the release notes, and a small update icon beside the node's name on
every page. Admins can start the upgrade there: it runs
what `sparewall upgrade` runs, to the document's channel, after a
confirmation, and the page follows its steps. When the node serving the
page reboots, the page says so, reconnects, and shows how the node came
back. On a pair's standby, which the master upgrades first, the page
then follows the master's part from status until both nodes run the new
image, in sync. Any other dropped connection, or a failed step, is shown
as an error. `--image` and `--allow-downgrade` stay in the CLI. A node
runs one upgrade at a time: a second start, from the CLI, the web UI or a
schedule, is refused while one runs. In a pair, each node reports its own image; if the two run
different images, status and the banner say that too ("images: …"),
which usually means an upgrade stopped halfway: run `sparewall upgrade`
again to finish it.

When what is available changes, and only then, the node logs it once
("0.4.1 is available on ghcr.io/sparewall/sparewall:stable (running
0.4.0)") with `MESSAGE_ID=c8f95979678447529aa9b5914a38a3a0`, and sends
it as an `update` event (`sparewall events`). A failed check is logged
once, when checks start failing, with
`MESSAGE_ID=52e0a9567b834f27aee3019c5703cf13`, and retried about an hour
later; the last answer is kept meanwhile. Select either with
`journalctl MESSAGE_ID=…`, or forward them with the rest of the journal
(`logging.remote`). An available update, or a failing check, never
changes health, so in a pair it never moves the gateway addresses.

To keep a node from contacting the registry on its own, on an air-gapped
site for instance: `sparewall set updates.check=false` (schema revision
3, which 0.3.x cannot read). `sparewall upgrade --check` still asks when
you run it.

**Scheduled upgrades.** With `updates.mode: windowed`, a node upgrades
itself in a maintenance window, through the same sequence as `sparewall
upgrade`:

```yaml
updates:
  channel: stable
  mode: windowed
  window: "Sun *-*-* 03:00"   # a systemd calendar expression: when an upgrade may start
  window_minutes: 60          # how long after that one may still start (default 60)
```

The window is in the node's time zone, which is UTC unless set; systemd
checks the expression when the change is applied, and `sparewall upgrade
--check` shows when the next window opens. In a pair only the master acts,
so the two nodes never start at once, and the rolling sequence (the
standby first, then the handover) runs unchanged. Each window is tried
once: when it opens, the node checks the channel and, if a newer image is
there, starts the upgrade. It skips the window, and records why, unless:

- health is `ok`: not degraded, so no unacknowledged SELinux denials;
- no change waits for confirmation, and the pair is not held
  (`cluster.hold`);
- in a pair, the two are in sync;
- no scheduled upgrade has failed since: a failure makes the `upgrade`
  health check degraded and stops scheduled upgrades until someone
  acknowledges it (`sparewall health ack upgrade`) or starts an upgrade by
  hand.

Every attempt, skipped, started, succeeded or failed, is logged with
`MESSAGE_ID=4f0b6f0a8f4c4e1f9c7d2b3a5e6d7c81` and sent as a
`scheduled-upgrade` event; `/metrics` has
`sparewall_scheduled_upgrade_last_attempt_timestamp_seconds`,
`sparewall_scheduled_upgrade_last_result{result}` and
`sparewall_scheduled_upgrade_blocked`. `testing` with a window installs
every passing build of main unattended, and validation warns about it. A
standalone node accepts its one reboot of downtime inside the window.

## SELinux

The coordinator runs confined, in the enforcing SELinux domain
`sparewalld_t`. If an action fails with a permission error that file
modes do not explain, look for a denial:

```shell
sudo journalctl -b _TRANSPORT=audit | grep 'avc:.*denied.*sparewalld'
sudo ausearch -m avc -ts boot -c sparewalld   # with auditd
```

To keep the node working while the missing rule is fixed, make only the
coordinator's domain permissive (the rest of the system stays
enforcing), and undo it once an image with the rule is installed:

```shell
echo '(typepermissive sparewalld_t)' > /tmp/sparewalld-permissive.cil
sudo semodule -i /tmp/sparewalld-permissive.cil   # allowed and logged
sudo semodule -r sparewalld-permissive            # enforcing again
```

The module survives reboots and upgrades until it is removed.

Please report the denial lines in an issue: the policy is built from
what the test suites see, and a denial on a real node is a missing rule.

## Settings not built yet

`provider_options` and `dhcp.provider: networkd` are rejected with an
error at their path, and so are hosts by suffix in a delegated prefix
and IPv6 in `management.sources` (management stays IPv4 for now). The
document takes them, and validation checks them in full; activating one
is refused. `ipv6` objects, IPv6 in policies (#212), a node's WAN (#213,
[IPv6 on the WAN](#ipv6-on-the-wan)), inside networks (#214, [IPv6 on
inside networks](#ipv6-on-inside-networks)) and IPv6 in a pair (#215,
[Running an HA pair](pairing.md#ipv6)) are built. (`updates.mode: windowed` and `updates.window` were
too, before 0.4.0 built them, and `logging.remote.provider: syslog`,
`metrics.mode: local` and `metrics.retention` before 0.5.0.) Builds
before 0.1.0 accepted them, though nothing acted on them. After
upgrading:

- A node already running a document with one of them keeps running it,
  across reboots: the running configuration is not re-checked.
- Any change, rollback, push or `sync --from` that would run such a
  document is refused until the settings are gone. Remove the ones
  present in one change, which runs exactly as the old document did:

  ```shell
  sparewall unset provider_options
  ```

  For a provider, unset it to use the built-in default (`sparewall unset
  dhcp.provider`, which means Kea). With networkd's DHCP server, nothing
  served DHCP before; Kea starts with an empty lease database. Kea pings
  each address before offering it, so a client still holding an old
  lease is not given away (`dhcp.ping_check`).

  A document with `metrics.mode: local` from such a build is valid from
  0.5.0, and starts the local Prometheus.
- History may keep such generations: a peer catching up stores them
  without running them, then runs the newest one, which must be valid.

## Exit codes

0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable
(including a pair peer), 6 permission denied.
