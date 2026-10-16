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
