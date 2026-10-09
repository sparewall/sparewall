# The Sparewall OS image

A [bootc](https://bootc-dev.github.io/bootc/) image on Fedora 45 (systemd
262): networkd instead of NetworkManager, nftables, keepalived,
conntrack-tools, chrony, WireGuard tools, restic, troubleshooting tools, and
the coordinator (`sparewalld`) and CLI (`sparewall`).

## Build

```shell
podman build -f image/Containerfile -t localhost/sparewall:dev .
```

## Boot test

`tests/vm/boot-test.sh IMAGE` builds a qcow2 with bootc-image-builder,
boots it under KVM with a node identity passed as a systemd credential,
and checks bootstrap mode, a first apply confirmed over a fresh SSH
connection, the revert of an unconfirmed change, and a reboot. CI runs it
on every image build.

## Node identity

A fresh node needs three values (design: "Bootstrap"): its name, an admin
SSH key and the management NIC. Supply them as JSON or YAML:

```json
{"node": "fw1",
 "ssh_keys": ["ssh-ed25519 AAAA... you@laptop"],
 "management": {"nic": "52:54:00:12:34:56", "vlan": 99,
                "address": "10.0.99.2/24", "gateway": "10.0.99.1"}}
```

- **VMs:** as the `sparewall.identity` systemd credential, e.g. with QEMU
  `-smbios type=11,value=io.systemd.credential.binary:sparewall.identity=<base64>`.
- **Kickstart or console:** write it to `/etc/sparewall/identity.json`, or
  run `sparewall init --node fw1 --mgmt-nic <MAC> --ssh-key "<key>"`, then
  `systemctl restart sparewalld`.

The node then boots into bootstrap mode: only the management port up, SSH
for the `admin` user on it, all forwarding dropped. Apply the real
configuration with `sparewall apply -f site.yaml --confirm 120` over SSH.

## Layout

| Path | Purpose |
| --- | --- |
| `files/usr/lib/systemd/system/sparewall-early.service` | Installs the live generation (links, nft, sysctl) before udev and networkd |
| `files/usr/lib/systemd/system/sparewalld.{service,socket}` | The coordinator and its root-only Varlink socket |
| `files/etc/ssh/sshd_config.d/40-sparewall.conf` | Keys only, no root login; admin keys from the identity |
| `files/etc/containers/policy.json` | Requires the project's cosign signature for `ghcr.io/sparewall` |
| `files/usr/share/sparewall/cosign.pub` | The project's image signing key |
