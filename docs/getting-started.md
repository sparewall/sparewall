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

Build a disk image with
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
- **Physical machines:** on the console (log in as root with the password
  set at install), run
  `sparewall init --node fw1 --mgmt-nic <MAC> --ssh-key "<key>"` and then
  `systemctl restart sparewalld`.

The node boots into **bootstrap mode**: only the management port is up
(named `mgmt0`, or `mgmt` for a tagged VLAN), SSH is accepted on it for
the `admin` user, and nothing is forwarded.

```shell
ssh admin@10.0.99.2 sudo sparewall status
```

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
`mgmt0` to its role name, which may drop the SSH session briefly;
reconnect and run `sparewall confirm`.

## 5. Check it

```shell
sparewall status
sparewall health --verbose
sparewall history
```

Health is `ok`, `degraded` (working, but something needs attention) or
`failed`. The same model answers `https://<mgmt address>/readyz`.
