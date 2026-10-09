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

## Monitoring

| Endpoint | Purpose |
| --- | --- |
| `/livez` | The coordinator answers |
| `/readyz`, `/healthz` | 200 when ok or degraded, 503 when failed |
| `/readyz?verbose`, `/readyz/<check>` | Detail (needs a token) |
| `/metrics` | Prometheus metrics (needs a token unless `metrics.mode: external`) |

```shell
curl -k -H "Authorization: Bearer $TOKEN" https://fw1/metrics
```

## Backup and restore

```shell
sparewall backup            # writes a bundle under /var/lib/sparewall/backups
# On a reinstalled node, before sparewalld first starts:
systemctl stop sparewalld.service sparewalld.socket
sparewall restore -f sparewall-fw1-g12-....tar.gz
systemctl start sparewalld.service
```

Bundles hold the document, recent generations, DHCP leases and the image
digest. Node private keys are never included; a rebuilt node of a pair is
re-paired with its new sync key.

## Exit codes

0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable
(including a pair peer), 6 permission denied.
