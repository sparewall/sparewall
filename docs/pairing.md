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

## Failover

A node whose health is **failed** puts its VRRP instances into FAULT and
the other node takes over the gateway addresses; *degraded* never causes a
failover. On becoming master, a node commits the connection-tracking state
it received from its peer, so established flows continue.
