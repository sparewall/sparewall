# Getting started

This guide takes one node from a fresh install to a working standalone
firewall. See [pairing.md](pairing.md) to grow it into an HA pair and
[operations.md](operations.md) for day-to-day use.

> Sparewall is pre-release software. Expect rough edges.

## 1. Get an image

Images are published to `ghcr.io/sparewall/sparewall` with `testing` and
(later) `stable` tags, signed with the project's cosign key
([`cosign.pub`](../cosign.pub)):

```shell
cosign verify --key cosign.pub ghcr.io/sparewall/sparewall:testing
```

Each [release](https://github.com/sparewall/sparewall/releases) also has
ready-made images, with checksums signed by the same key:

- `sparewall-VERSION-x86_64.iso`: an installer for physical machines.
  It installs **unattended to the first fixed disk it finds** (USB
  sticks are skipped), but only if that disk is blank: no partitions and
  no filesystem on it. A disk with anything on it stops the install and
  is left untouched. To install there anyway, wipe it
  (`wipefs -a /dev/sdX`), or at the installer's boot menu press `e` and
  add `sparewall.erase=sdX` (or `nvme0n1`) to the `linux` line: that
  erases the named disk whatever it holds.
- `sparewall-VERSION-x86_64.raw.zst`: a disk image to write to the
  machine's disk or a USB stick
  (`zstd -dc sparewall-*.raw.zst | sudo dd of=/dev/sdX bs=4M`).
- `sparewall-VERSION-x86_64.qcow2`: a disk image for VMs.
- `sparewall-VERSION-x86_64-linux.tar.gz`: the `sparewall` CLI for your
  workstation (a static Linux binary).

```shell
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Files named `.partNN` are pieces of one file: `cat` them together first.

Or build a disk image yourself with
[bootc-image-builder](https://github.com/osbuild/bootc-image-builder):

```shell
sudo podman pull ghcr.io/sparewall/sparewall:testing
sudo podman run --rm --privileged --security-opt label=type:unconfined_t \
  -v ./output:/output -v /var/lib/containers/storage:/var/lib/containers/storage \
  quay.io/centos-bootc/bootc-image-builder:latest \
  --type qcow2 --rootfs xfs ghcr.io/sparewall/sparewall:testing
```

Use `--type raw` for a USB stick or `--type anaconda-iso` for an installer.

## 2. Give the node an identity

A fresh node needs its name, an admin SSH key and its management NIC:

```json
{"node": "fw1",
 "ssh_keys": ["ssh-ed25519 AAAA... you@laptop"],
 "management": {"nic": "52:54:00:aa:00:01", "vlan": 99,
                "address": "10.0.99.2/24", "gateway": "10.0.99.1"}}
```

Omit `address` to use DHCP on the management port, and `vlan` if
management is untagged.

For a way in at the console before the network is right, add a password
hash for `admin`, made with `openssl passwd -6` (it prompts):
`"password_hash": "$6$..."`. It becomes the cluster's admin password
([operations](operations.md#the-admin-console-password)) unless one is
set already. SSH stays keys-only either way.

- **VMs:** pass it as the `sparewall.identity` credential. With libvirt,
  add to the domain XML:
  ```xml
  <sysinfo type='fwcfg'>
    <entry name='opt/io.systemd.credentials/sparewall.identity'>{"node": "fw1", ...}</entry>
  </sysinfo>
  ```
  or with QEMU directly:
  `-smbios type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 identity.json)`.
  Give the VM a fixed MAC (`<mac address='52:54:00:aa:00:01'/>`).
- **Physical machines:** a seed stick. Put the identity, as
  `sparewall-identity.yaml` (or `.json`), on a USB stick whose filesystem
  is labelled `SPAREWALL`, and plug it in before the first boot:
  ```shell
  sudo mkfs.vfat -n SPAREWALL /dev/sdX1
  sudo mount /dev/sdX1 /mnt && sudo cp sparewall-identity.yaml /mnt/ && sudo umount /mnt
  ```
  The node reads it once, and ignores the stick after that. Alternatively,
  on a console where you can log in as root, run
  `sparewall init --node fw1 --mgmt-nic <MAC> --ssh-key "<key>"` (or
  `sparewall init --from identity.yaml`).

The node boots into **bootstrap mode**: only the management port is up
(named `mgmt0`, or `mgmt` for a tagged VLAN), SSH is accepted on it for
the `admin` user, and nothing is forwarded.

```shell
ssh admin@10.0.99.2 sudo sparewall status
```

This first `ssh` also asks you to accept the node's host key. Do it
before using the `sparewall` CLI from your workstation: the CLI runs ssh
non-interactively, so it cannot ask, and stops at an unknown host key.

## 3. Write the configuration document

Start from [`examples/standalone.yaml`](../examples/standalone.yaml). Use
`sparewall explain` to read about any field:

```shell
sparewall explain networks.users
sparewall explain policy.'users->wan'
```

Every port must be bound to hardware for this node by permanent MAC (or
PCI path), and every network rides on a port role, optionally tagged.

## 4. Apply it safely

From your workstation, add a context and apply with a confirm window:

```shell
sparewall context add home --host admin@10.0.99.2
sparewall apply -f site.yaml --confirm 120
```

The CLI shows the diff, applies it, and asks whether to keep it. Your
answer travels over a **new** connection, so if the change cut you off,
you cannot confirm and it reverts by itself after 120 seconds (or at the
next boot). On a first apply the management port is usually renamed from
`mgmt0` to its role name, which may drop the SSH session briefly. The CLI
notices within seconds, reconnects for up to a minute, and asks again
about the pending generation. If it cannot reconnect, run
`sparewall status` and `sparewall confirm <generation>` yourself before
the window closes. A longer window (`--confirm 300`) leaves more room
for that.

### Unattended: let the node apply it

A node can also take its first configuration at install time and apply
it by itself, so it comes up configured with no one at the console. Put
the document next to the identity: `sparewall-config.yaml` (or `.json`)
on the seed stick, the `sparewall.config` credential on a VM, or
`sparewall init --config site.yaml` on the console.

While the node is in bootstrap mode (generation 0), it applies a
configuration it has not tried before, with a ten-minute confirm window,
and confirms it itself once its health has stayed out of `failed` for
about fifteen seconds. If health stays failed (a port that does not come
up, say), the window closes and the node returns to bootstrap mode. A
document that is refused (invalid, or not for this node) also leaves it
in bootstrap mode. Either way, `sparewall health --verbose` says why
under `seed`, and a corrected seed stick can be put back in. Once the
node is configured, seeds are ignored.

- **Bind ports by PCI path** (`nic: pci-0000:01:00.0`) when the machine's
  MAC addresses are not known in advance: the path is the same on every
  unit of one hardware model.
- **Secrets are not seeded.** Set them afterwards with
  `sparewall secret set`; until then, health is degraded where one is
  missing (backups without a password, say).
- **Pairs** are seeded one node at a time, without `cluster.sync_keys`;
  pairing stays the manual step in [pairing](pairing.md), since each
  node's sync key is generated on the node.

## 5. Check it

```shell
sparewall status
sparewall health --verbose
sparewall history
```

Health is `ok`, `degraded` (working, but something needs attention) or
`failed`. The same model answers `https://<mgmt address>/readyz`.
