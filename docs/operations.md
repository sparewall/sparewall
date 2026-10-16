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

## Secrets and tokens

Secrets never appear in the document; it refers to them as
`secret:<name>`.

```shell
sparewall secret set dns-tsig          # reads the value from stdin
sparewall secret list                  # names and versions only
sparewall token create prometheus --role monitor --expires 90d
sparewall token list
sparewall token revoke prometheus
```

Roles: `monitor` (health and metrics), `viewer`, `operator` (change,
confirm, roll back, sync) and `admin`.

**What a token can do today.** Every `sparewall` command goes through
the coordinator's root-only socket, locally or over SSH with
`sudo sparewall bridge`, and acts with full rights; no command takes a
token. Tokens are accepted only by the HTTPS endpoints: verbose health
(`/readyz?verbose`, `/readyz/<check>`) and `/metrics`, which any role
may read. A token cannot change configuration, read secrets or manage
tokens. Token access for scripts and front ends comes with the web UI's
API (#11).

## Remote-access VPN

Clients generate their own keys; only public keys go in the document:

```shell
wg genkey | tee laptop.key | wg pubkey
sparewall set "vpn.roadwarrior.peers.laptop.public_key=<public key>" \
              "vpn.roadwarrior.peers.laptop.addresses=[10.99.0.11/32]"
sparewall vpn client-config laptop --qr
```

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

## Monitoring

| Endpoint | Purpose |
| --- | --- |
| `/livez` | The coordinator answers |
| `/readyz`, `/healthz` | 200 when ok or degraded, 503 when failed |
| `/readyz?verbose`, `/readyz/<check>` | Detail (needs a token) |
| `/metrics` | Prometheus metrics: the appliance's own and the host's from node\_exporter, which listens only on localhost (needs a token unless `metrics.mode: external`; `off` disables it) |

```shell
curl -k -H "Authorization: Bearer $TOKEN" https://fw1/metrics
```

There is no local Prometheus yet: `metrics.mode: local` and
`metrics.retention` are rejected.

### What health verifies

Readiness (`/readyz`, the VRRP health check, the applied hash the pair
compares, `sparewall_config_applied`) reflects these checks of the
running system, each repeated on every health request:

| Check | Verifies | Does not verify |
| --- | --- | --- |
| `applied` | The last activation of the desired generation succeeded, and the live firewall still matches it | Anything the other checks do not |
| `nft` | The live `inet sparewall` table matches, rule for rule, what was loaded for the generation: chains with their hooks and policies, every rule, static set elements. What traffic changes (counters, quota use, `last` timestamps, element timeouts), handles, and the sets networkd fills at runtime are excluded. If the table cannot be read back right after a load, the node fails this check until the next reload | Tables other software owns |
| `links` | Every interface that carries traffic exists and is up (failed otherwise, so VRRP moves the gateway addresses). A trunk shared by the sync VLAN and service networks counts as carrying traffic | Addresses, routes or bond membership on them |
| `replication` | Every replication-only interface (the sync network, and a port carrying nothing else) exists and is up. Losing one is **degraded**, never failed: traffic still flows, so the gateway addresses stay where they are while the pair stops replicating | |
| `services` | Every provider unit the generation needs (Kea, Unbound, keepalived, conntrackd, ulogd, journal-upload) is active in systemd | That a daemon still runs the files installed for it; those passed the daemon's own config test before they were installed |
| `pair`, `tls`, `backup` | Sync tunnel and peer state, certificate validity, the last backup | |

Any change to the firewall made outside Sparewall (`nft flush`, an extra
rule, a changed policy) fails `nft` and `applied`, so the node reports
**failed**: it leaves the VRRP master role and the pair shows
`apply-failed`. To restore it, reload the generation:
`systemctl restart sparewalld` (or apply any new change).

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
secrets, DHCP leases and the running image digest. Node private keys are
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
```

`backup.repository` is any restic repository: SFTP, S3-compatible
storage or a restic REST server (a local path must be under
`/var/lib/sparewall`, which sparewalld can write). The repository is
initialised on first use. Credentials such as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` go as `KEY=value` lines in a secret named by
`backup.credentials` (`secret:backup-s3`). Each run sends one snapshot
(host = node name, tag `sparewall`); prune with `restic forget` on your
own schedule. The node keeps its newest five bundles under
`/var/lib/sparewall/backups`.

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

Nodes run a signed bootc image and track a channel (`testing` or `stable`)
of the repository they were installed from:

```shell
sparewall upgrade --check                 # is a newer image available?
sparewall upgrade                         # the document's updates.channel
sparewall upgrade --channel stable
sparewall upgrade --image mirror.example:5000/sparewall:stable
```

On a standalone node this stages the image and reboots (one reboot of
downtime). In a pair, run it on the master: the standby is upgraded and
rebooted first, and once it is back on the new image, healthy and in sync,
the master hands it the gateway addresses (established connections carry
over through conntrackd) and upgrades itself. A failed gate stops the
upgrade and the master keeps the addresses; `bootc rollback` and a reboot
return a node to its previous image. The containers signature policy
rejects images from anywhere but `ghcr.io/sparewall`, whose images must
carry a valid signature; to upgrade from a mirror, add it to
`/etc/containers/policy.json` with its own signature requirement.

Upgrades run only when asked for: scheduled upgrades
(`updates.mode: windowed`, `updates.window`) are not built yet and are
rejected.

## Settings not built yet

`provider_options`, `metrics.mode: local`, `metrics.retention`,
`updates.mode: windowed`, `updates.window`, `dhcp.provider: networkd`,
and `logging.remote.provider: syslog` are rejected with an error at
their path. Earlier versions accepted them, though nothing acted on
them. After upgrading:

- A node already running a document with one of them keeps running it,
  across reboots: the running configuration is not re-checked.
- Any change, rollback, push or `sync --from` that would run such a
  document is refused until the settings are gone. Remove the ones
  present in one change, which runs exactly as the old document did:

  ```shell
  sparewall unset provider_options metrics updates.mode updates.window
  ```

  For a provider, unset it to use the built-in default (`sparewall unset
  dhcp.provider`, which means Kea). With networkd's DHCP server, nothing
  served DHCP before; Kea starts with an empty lease database.

  Unsetting `metrics` returns `/metrics` to needing a token, which is
  what `local` did; to keep `external` or `off`, unset only
  `metrics.retention`.
- History may keep such generations: a peer catching up stores them
  without running them, then runs the newest one, which must be valid.

## Exit codes

0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable
(including a pair peer), 6 permission denied.
