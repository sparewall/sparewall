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

## Remote-access VPN

Clients generate their own keys; only public keys go in the document:

```shell
wg genkey | tee laptop.key | wg pubkey
sparewall set "vpn.roadwarrior.peers.laptop.public_key=<public key>" \
              "vpn.roadwarrior.peers.laptop.addresses=[10.99.0.11/32]"
sparewall vpn client-config laptop --qr
```

After a failover, or the gateway's handover during an upgrade, each
client is cut off until it makes a new handshake with the new master. A
client sending traffic recovers after about 16 seconds, or at its next
packet if its session is more than two minutes old; an idle client
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
| `/metrics` | Prometheus metrics: the appliance's own and the host's from node\_exporter, which listens only on localhost (needs a token unless `metrics.mode: external`) |

```shell
curl -k -H "Authorization: Bearer $TOKEN" https://fw1/metrics
```

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

## Exit codes

0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable
(including a pair peer), 6 permission denied.
