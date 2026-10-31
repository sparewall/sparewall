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

In a pair, a change, rollback included, that needs a newer revision than
the peer reads is refused until the peer is upgraded: each node reports
the newest revision it reads, and one that does not say (0.3.1 or older)
reads revision 1. Until the peer has answered since sparewalld started,
and while it is unreachable, which revisions it reads is not known, so a
change that needs more than revision 1 waits until the peer is reached.
A new pairing is not checked this way: each node checks its own apply.

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

`/openapi.json` describes every call; [docs/api](api/README.md) has the
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
| `services` | Every provider unit the generation needs (Kea, Unbound, keepalived, conntrackd, ulogd, journal-upload) is active in systemd | That a daemon still runs the files installed for it; those passed the daemon's own config test before they were installed |
| `pair`, `tls`, `backup` | Sync tunnel and peer state, certificate validity, the last backup | |
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
sudo sparewall backup --check-password   # on the node: try your copy
```

**Check the password before relying on the backups.** After setting it
and writing a bundle, run `sparewall backup --check-password` on the
node and paste the password from your password manager: the check tells
you whether it opens the secrets in the newest local bundle. It needs
neither restic nor the repository, and changes nothing. `--file` checks
another bundle, and works on any machine the bundle is copied to. A
wrong password exits non-zero. Get it right before the first backup
reaches the repository: restic initialises the repository with the
password, and changing it later orphans the snapshots already there.

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
downtime). In a pair the master runs it, whichever node you start it on:
the standby is upgraded and rebooted first, and once it is back on the new
image, healthy and in sync, the master hands it the gateway addresses
(established connections carry over through conntrackd) and upgrades
itself. Started on the standby, the command shows the master's progress
until the standby reboots; follow the rest with `sparewall status` or the
master's journal. A failed gate stops the
upgrade and the master keeps the addresses; `bootc rollback` and a reboot
return a node to its previous image. The containers signature policy
rejects images from anywhere but `ghcr.io/sparewall`, whose images must
carry a valid signature; to upgrade from a mirror, add it to
`/etc/containers/policy.json` with its own signature requirement.

Upgrades run only when asked for: scheduled upgrades
(`updates.mode: windowed`, `updates.window`) are not built yet and are
rejected.

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
  served DHCP before; Kea starts with an empty lease database. Kea pings
  each address before offering it, so a client still holding an old
  lease is not given away (`dhcp.ping_check`).

  Unsetting `metrics` returns `/metrics` to needing a token, which is
  what `local` did; to keep `external` or `off`, unset only
  `metrics.retention`.
- History may keep such generations: a peer catching up stores them
  without running them, then runs the newest one, which must be valid.

## Exit codes

0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable
(including a pair peer), 6 permission denied.
