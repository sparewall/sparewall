# Running an HA pair

Two nodes run as active/standby: keepalived moves the gateway addresses,
conntrackd moves connection state with them, and Kea runs its own
hot-standby HA. All replication runs over a `sync` VLAN inside a WireGuard
tunnel between the nodes. See [`examples/pair.yaml`](../examples/pair.yaml).

## Pairing

1. Install and bootstrap both nodes ([getting-started.md](getting-started.md)).
2. Read each node's sync-tunnel public key:
   ```shell
   ssh admin@fw1 sudo sparewall status | grep 'sync key'
   ssh admin@fw2 sudo sparewall status | grep 'sync key'
   ```
3. Put both keys in the document and apply it **on each node**:
   ```yaml
   cluster:
     nodes: [fw1, fw2]
     sync_network: sync
     sync_keys:
       fw1: "<fw1's key>"
       fw2: "<fw2's key>"
   ```
4. The tunnel comes up and the nodes find each other. From then on a
   change applied on either node is pushed to the other once confirmed.

Until both keys are in, a node of a pair offers no DHCP leases: Kea's
HA runs through the tunnel, and two unpaired nodes would otherwise hand
out the same pool. To serve DHCP from the first node before the second
is keyed, set `dhcp.ha: off` until then.

Private keys never leave their node; only public keys are in the document.
Cluster secrets (such as the remote-access VPN server key) are sent through
the tunnel and re-encrypted by the receiving node.

## The WAN

The nodes need no public address of their own. Give them private
addresses on the WAN link, and put the public block (the gateway address,
any extra addresses and the ISP's gateway) in a subnet of its own:

```yaml
networks:
  wan:
    port: uplink
    vlan: 10
    role: wan
    addresses: { fw1: 10.0.10.2/24, fw2: 10.0.10.3/24 }
    vip: 203.0.113.1/29
    extra_vips: [203.0.113.5/29]
    vrid: 10
    gateway: 203.0.113.6
```

The master holds every public address and the default route; the backup
reaches the internet through the master, as the gateway address, so
upgrades, ACME, NTP and backups work on either node. Nothing from the
private addresses reaches the ISP. Public node addresses in the same
subnet as `vip` still work as before.

With one public address leased by DHCP, give the nodes private addresses
and a `vrid`, and no `vip`:

```yaml
networks:
  wan:
    port: uplink
    vlan: 10
    role: wan
    dhcp_client: true
    addresses: { fw1: 10.0.10.2/24, fw2: 10.0.10.3/24 }
    vrid: 10
```

The master runs the DHCP client on `swwan`, a link with the VRRP virtual
MAC (`00:00:5e:00:01:0a` here), so the ISP sees one MAC and one client and
the lease moves with the gateway. Another network of the pair must have
a gateway address: the lease follows its VRRP master.

## Changing configuration

Apply a change on either node; it runs there first and is pushed to the
other node only once confirmed. Make risky changes on the BACKUP, which
carries no traffic. The full contract, including what happens if a node
fails or restarts midway, is in
[design.md](design.md#configuration-lifecycle).

A change to the sync link itself (the `sync` network's addresses, VLAN or
port, `cluster.sync_port`, or a sync key) goes to the other node first,
through the current tunnel. The node you made it on decides whether both
keep it, once the other node has confirmed it over the new tunnel (and
you have, if you asked for a confirm window). If the new tunnel never
comes up, or you don't confirm, both return to the old tunnel within a
few minutes. Make such a change on its own, with nothing else pending.

## Sync states

`sparewall status` shows the pair's state:

| State | Meaning |
| --- | --- |
| `in-sync` | Both nodes hold and run the same configuration |
| `peer-behind` | The peer lacks newer generations; they are being pushed |
| `local-behind` | This node is behind; it will receive the newer generations |
| `apply-failed` | A node holds the configuration but could not apply it |
| `diverged` | Both nodes changed while apart; you decide which wins |
| `peer-unreachable` | The sync tunnel or the peer is down |

While the peer is unreachable, changes are refused unless you pass
`--allow-diverge`. Resolve divergence with
`sparewall sync --from <node>`: the other node's diverged generation is
kept on disk, not lost.

## Replacing an existing gateway

To stage a pair (or a standalone node) beside the firewall it replaces,
on the same VLANs, apply the real document with `cluster.hold: true`.
Everything is rendered, applied and paired as usual, but no gateway
address is claimed: keepalived runs with every instance held in FAULT,
a standalone node does not install its gateway addresses, and Kea runs
(HA included) with no pools, reservations or authority, so it neither
offers leases nor NAKs the old server's clients. Health shows a
degraded `held` check, so the pair can be checked in sync, its sync
tunnel and conntrackd up, before cutover.

Cut over with one small change, confirm-or-revert like any other:

```shell
sparewall set cluster.hold=false --confirm 300
```

Take the old gateway's addresses off first (or in the same maintenance
window): until then both would answer for them. Setting
`cluster.hold=true` again hands the addresses back.

What a hold cannot prove: Kea HA serves nothing while held, so leases
are first handed out after the cutover; VRRP elections are first held
then too.

## Failover

A node whose health is **failed** puts its VRRP instances into FAULT and
the other node takes over the gateway addresses; *degraded* never causes a
failover. On becoming master, a node commits the connection-tracking state
it received from its peer, so established flows continue.

### Moving the addresses back: `sparewall failover`

The pair does not fail back by itself (`nopreempt`): a node that returns
finds a master and stays the backup, even if it is the larger one. So
the priority you configured decides the master only when both nodes
start together. To move the gateway addresses where you want them, run
on either node:

```shell
sparewall failover             # to the node with the higher priority
sparewall failover --to fw2    # to a named node
```

The master yields and the target takes over as it would from a failed
node, connection tracking included. The old master then returns as
BACKUP and stays there. The command returns once the target is master.
It refuses if the target is not the backup, its health is not `ok`
(degraded, failed, or a required link down), it is not running the same
configuration, or the pair is held or not in sync. If the target does
not take over within a minute, the addresses stay where they were.

Use it:

- after a planned upgrade or restart of both nodes, when the smaller one
  came back first;
- after replacing a node;
- before maintenance on the current master, to move the addresses off it
  first.

**Automatic failback.** To have the higher-priority node take the
addresses back by itself, set a delay:

```yaml
cluster:
  vrrp:
    preempt_delay_s: 300
```

The node then takes over once it has been up and eligible for that long.
This gives up the guarantee that the pair never bounces: if the node
flaps, the delay is the only thing between it and the gateway addresses.
`validate` warns while it is set. With it set, a `sparewall failover` to
the lower-priority node lasts only until the delay has passed.
