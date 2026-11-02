# Running Sparewall as a VM

A mini PC with two 2.5 GbE ports and 16 GB of RAM is far more than a
firewall needs. To run other services on it, put a hypervisor on the bare
metal (Proxmox, or libvirt on a general-purpose Linux host) and run
Sparewall as one VM among others. VMs are a first-class target: the
release ships a `.qcow2` disk image, the CI suites run Sparewall in VMs,
and the image carries the QEMU guest agent.

It is easy to get wrong, though, in ways that quietly bypass the firewall.
This guide is about doing it safely, on the usual two-port hardware with
no VLANs ([getting started](getting-started.md)): the WAN on one port, the
LAN, management and (in a pair) sync on the other.

## The trade-off

The firewall now depends on the hypervisor. A hypervisor exploit, a
misconfigured bridge, or a host that holds an address on the WAN puts the
host, and everything on it, past the firewall. Keep the hypervisor
patched, keep its own management off the WAN, and treat its admin
access like the firewall's. If that is more than you want to own, run
Sparewall on its own hardware.

## The WAN never reaches the hypervisor

The one rule that matters: **the host has no address on the WAN.** The
WAN port belongs to the Sparewall VM alone, and the host's own
management (its web UI, SSH, updates) is on the LAN, behind Sparewall,
like any other machine.

Check it on the host:

```shell
ip -br addr show            # the WAN port and its bridge: no IPv4 or global IPv6 address
ip route show default       # the host's default route is via Sparewall's LAN address
```

An IPv6 link-local address (`fe80::`) on the WAN bridge is harmless only
if nothing listens on it; better, turn IPv6 off on that bridge
(`net.ipv6.conf.<bridge>.disable_ipv6 = 1` in `/etc/sysctl.d/`).

## Passthrough or bridges

- **PCI passthrough** gives the VM the WAN NIC itself: the host never sees
  a WAN frame, which is the strongest isolation. It ties the VM to that
  machine and that NIC, needs IOMMU support (`intel_iommu=on` or
  `amd_iommu=on`), and the NIC must be in an IOMMU group of its own. On a
  two-port mini PC both ports are often in one group, and then
  passthrough is not possible.
- **Bridges** are portable and work everywhere. The host's bridges must
  then stay layer 2 only: no host address on the WAN bridge (above), and
  nothing that filters the extra MAC addresses and IP addresses a
  firewall uses. In a pair, the gateway addresses move between VMs, and
  on a static WAN block they move behind the VRRP virtual MAC. Turn off
  any per-VM MAC or IP filtering: libvirt's `clean-traffic` nwfilter,
  Proxmox's firewall on these NICs.

On a two-NIC mini PC, bridges are the usual choice: a WAN bridge on one
port with no host address, and a LAN bridge on the other carrying the
host's own management and the other VMs.

## Proxmox

The bridges, in `/etc/network/interfaces` (the port names are examples):

```text
auto vmbr0                   # the LAN: the host's management lives here
iface vmbr0 inet static
    address 192.168.1.5/24
    gateway 192.168.1.1      # Sparewall's LAN address
    bridge-ports enp2s0
    bridge-stp off
    bridge-fd 0

auto vmbr1                   # the WAN: no address at all
iface vmbr1 inet manual
    bridge-ports enp1s0
    bridge-stp off
    bridge-fd 0
```

The VM, from the release's `.qcow2` (`identity.json` as in
[getting started](getting-started.md#2-give-the-node-an-identity), its
management NIC the LAN NIC's MAC):

```shell
qm create 100 --name fw1 --memory 2048 --cores 2 --machine q35 \
    --bios ovmf --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=0 \
    --tpmstate0 local-lvm:1,version=v2.0 \
    --net0 virtio=52:54:00:aa:00:01,bridge=vmbr1,firewall=0 \
    --net1 virtio=52:54:00:aa:00:02,bridge=vmbr0,firewall=0 \
    --agent enabled=1 \
    --onboot 1 --startup order=1,up=60 \
    --args "-smbios type=11,value=io.systemd.credential.binary:sparewall.identity=$(base64 -w0 identity.json)"
qm importdisk 100 sparewall-VERSION-x86_64.qcow2 local-lvm   # prints the disk's name
qm set 100 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-100-disk-N --boot order=scsi0
qm start 100
```

- **UEFI and a virtual TPM:** secrets are sealed to the TPM; without one
  they fall back to the host credential key, which is weaker.
- **`firewall=0`** on both NICs: Proxmox's firewall would filter the
  addresses and MACs the firewall moves.
- **`--startup order=1`:** Sparewall starts first and, being first, stops
  last. Give the other VMs higher orders.

## libvirt

Bridges `br-wan` (no address) and `br-lan` (the host's management),
made with NetworkManager, systemd-networkd or `/etc/network/interfaces`,
then:

```shell
virt-install --name fw1 --memory 2048 --vcpus 2 \
    --import --disk sparewall-VERSION-x86_64.qcow2,bus=virtio \
    --boot uefi --tpm emulator,model=tpm-crb,version=2.0 \
    --network bridge=br-wan,model=virtio,mac=52:54:00:aa:00:01 \
    --network bridge=br-lan,model=virtio,mac=52:54:00:aa:00:02 \
    --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
    --sysinfo type=fwcfg,entry0.name=opt/io.systemd.credentials/sparewall.identity,entry0.file=identity.json \
    --osinfo linux2022 --noautoconsole
virsh autostart fw1
```

Keep `clean-traffic` and any other `<filterref>` off both interfaces.
libvirt starts autostarted domains in no particular order: to start
Sparewall before VMs that need the network, start those from a systemd
unit ordered after it, or delay their autostart.

## Start and stop order

The other VMs' networks depend on the firewall: start it first and stop
it last. On a host that reboots for updates, that keeps the LAN's
gateway, DHCP and DNS up for as long as anything uses them.

## Pairs

- **Two hosts, one Sparewall VM each,** is real redundancy: either host
  can fail or reboot for updates. Both hosts need the WAN and the LAN on
  the same segments ([pairing](pairing.md); with two NICs, management and
  sync on the LAN).
- **Two VMs on one host** is for trying a pair out, not redundancy: the
  host is the single point of failure.
- **Snapshots and backups:** prefer Sparewall's own backup bundles
  (`sparewall backup`, sent to a repository) to snapshots of a running VM.
  If you snapshot, let the guest agent freeze the filesystems
  (`virsh snapshot-create-as --quiesce`, or Proxmox's backup with the
  agent enabled). Never restore a snapshot of one node of a pair while
  the other runs on: it comes back with old state, which the pair then
  reconciles as a divergence ([pairing](pairing.md#sync-states)).
