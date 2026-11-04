//! The configuration document, schema version 1.
//!
//! Struct field order is the canonical key order used by [`crate::canonical`].
//! Collections of named things are `BTreeMap`s keyed by name, so they export
//! sorted and merge one entry at a time.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The newest schema revision this crate reads. A field added after
/// revision 1 (what 0.2.0 reads) says which revision added it, with
/// `#[schemars(extend("x-since" = N))]`, and a document's `schema` is the
/// newest revision among the fields it uses ([`crate::schema::revision`]),
/// so a release that reads only older revisions can tell it apart from
/// an invalid document, and reads every document that needs nothing newer
/// (#168). A value that earlier releases reject as not built yet says so
/// too, with `x-since-values` (`{"syslog": 4}`) on its field.
pub const SCHEMA_VERSION: u32 = 5;

/// A whole deployment: one node or an HA pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "Sparewall configuration document")]
pub struct Document {
    /// The oldest schema revision that reads this document: the newest
    /// revision among the fields it uses. Set when the document is
    /// applied; a release refuses one newer than it reads.
    pub schema: u32,
    /// Node names and pair-wide settings.
    pub cluster: Cluster,
    /// Which network is management, and the anti-lockout switch.
    pub management: Management,
    /// Per node: port role name to the hardware it is bound to.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, BTreeMap<String, Port>>,
    /// Layer-2 segments, keyed by network name (also the interface name).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub networks: BTreeMap<String, Network>,
    /// Named groups of networks. `self` is built in and cannot be defined.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub zones: BTreeMap<String, Zone>,
    /// Named address and port sets, referenced from rules as `@name`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub objects: BTreeMap<String, Object>,
    /// Zone-pair policies keyed by `"from->to"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy: BTreeMap<String, Policy>,
    /// Inbound port forwards (DNAT).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub forwards: BTreeMap<String, Forward>,
    /// Raw nft statements placed at named hook points.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, RawEntry>,
    /// DHCPv4 service per network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<Dhcp>,
    /// Recursive DNS for the served networks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// Time service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Ntp>,
    /// Remote-access WireGuard instances.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vpn: BTreeMap<String, Vpn>,
    /// WireGuard tunnels this node connects to as a client, of a service
    /// it does not run (a VPN provider, a cloud host, another
    /// organisation's hub): chosen networks' traffic leaves through the
    /// tunnel instead of the WAN (#149).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(extend("x-since" = 4))]
    pub vpn_clients: BTreeMap<String, VpnClient>,
    /// Certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    /// Rule-log defaults and remote forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Logging>,
    /// Metrics collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
    /// Scheduled backups of the node bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<Backup>,
    /// OS image update policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<Updates>,
    /// Per-provider passthrough settings, keyed by provider name. Not
    /// built yet: any entry is rejected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_options: BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// cluster, management

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    /// One node name (standalone) or two (an HA pair). Each is also that
    /// node's hostname: up to 31 lowercase letters, digits and '-',
    /// starting with a letter and not ending with '-'.
    pub nodes: Vec<String>,
    /// The network with role `sync` that carries the pair's WireGuard tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_network: Option<String>,
    /// Each node's sync-tunnel WireGuard public key, from `sparewall status`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sync_keys: BTreeMap<String, String>,
    /// UDP port of the sync tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_port: Option<u16>,
    /// VRRP settings for a pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrrp: Option<Vrrp>,
    /// Connection-tracking sizing, identical on both nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conntrack: Option<ConntrackSizing>,
    /// Stage beside the gateway this replaces: everything runs, but no
    /// gateway address is claimed (VRRP instances held in FAULT, or not
    /// installed standalone) and DHCP offers nothing. Set false to cut over.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hold: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vrrp {
    /// Advertisement interval in centiseconds (VRRPv3). Default 100 (1 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advert_interval_cs: Option<u32>,
    /// VRRP priority per node; give the larger node the higher value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub priority: BTreeMap<String, u8>,
    /// Use VRRP virtual MAC addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_vmac: Option<bool>,
    /// Send adverts unicast to the peer instead of multicast.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unicast: Option<bool>,
    /// Fail back by itself: the node with the higher priority takes the
    /// gateway addresses back once it has been up and eligible for this
    /// many seconds (1-1000). Unset (the default), the pair never
    /// preempts, so it cannot bounce while that node flaps; move the
    /// addresses with `sparewall failover` instead. The delay is then the
    /// only protection against flapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preempt_delay_s: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConntrackSizing {
    /// `nf_conntrack_max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    /// Hash table buckets (`nf_conntrack_buckets`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets: Option<u32>,
    /// Established-TCP timeout in seconds. Default 86400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_established_timeout: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Management {
    /// The network with role `management`.
    pub network: String,
    /// Always accept SSH and HTTPS from the management network to `self`.
    /// Only an `admin` may turn this off.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub anti_lockout: bool,
    /// SSH to the node.
    #[serde(default, skip_serializing_if = "is_default")]
    pub ssh: ManagementSsh,
    /// Serve the web UI and the HTTP API (`sparewall-httpd`) on the HTTPS
    /// port, next to the health endpoints. Off by default; reached only
    /// where HTTPS is, the management network.
    #[serde(default, skip_serializing_if = "is_false")]
    #[schemars(extend("x-since" = 2))]
    pub web: bool,
    /// Who on the management network reaches SSH and HTTPS through the
    /// anti-lockout rule: addresses, prefixes, ranges or `@objects`. Unset,
    /// every host there does. Worth setting when the management network is
    /// also an ordinary one, such as a two-NIC box's LAN (#177).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 3))]
    pub sources: Option<Match>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagementSsh {
    /// Also accept the `admin` password (`sparewall passwd`) over SSH, not
    /// only keys. Off by default: the password is the console's
    /// break-glass path.
    #[serde(default, skip_serializing_if = "is_false")]
    pub password: bool,
}

// ---------------------------------------------------------------------------
// ports and networks

/// What a port role is bound to on one node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Port {
    /// One NIC, matched by permanent MAC address (`52:54:00:aa:00:01`) or by
    /// udev path (`pci-0000:01:00.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic: Option<String>,
    /// A bond of several NICs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<Bond>,
    /// MTU of the port (VLAN networks may set their own, no larger).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// NIC offload overrides for misbehaving drivers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offload: Option<Offload>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bond {
    /// Member NICs, each a permanent MAC address or udev path.
    pub members: Vec<String>,
    /// Bonding mode.
    pub mode: BondMode,
    /// LACP rate (802.3ad only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lacp_rate: Option<LacpRate>,
    /// Transmit hash policy, e.g. `layer3+4`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_policy: Option<String>,
    /// Link monitoring interval, e.g. `100ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miimon: Option<String>,
    /// Preferred member (active-backup only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum BondMode {
    #[serde(rename = "802.3ad")]
    Lacp,
    #[serde(rename = "active-backup")]
    ActiveBackup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LacpRate {
    Slow,
    Fast,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Offload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gro: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gso: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tso: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_checksum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_checksum: Option<bool>,
}

/// One layer-2 segment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// The port role this network rides on.
    pub port: String,
    /// 802.1Q VLAN ID; omit for the untagged network of a port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// What the network is for. Default `service`.
    #[serde(default, skip_serializing_if = "is_default")]
    pub role: NetworkRole,
    /// Each node's own address on this network, in CIDR form.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addresses: BTreeMap<String, Cidr>,
    /// Obtain this node's address by DHCP (WAN or management only).
    #[serde(default, skip_serializing_if = "is_false")]
    pub dhcp_client: bool,
    /// The gateway address clients use. Moved by VRRP in a pair, a plain
    /// static address on a standalone node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip: Option<Cidr>,
    /// More addresses that move with the gateway address (in its VRRP
    /// instance in a pair; static standalone), for forwards and SNAT, e.g.
    /// a mail server's public address. In the gateway address's subnet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_vips: Vec<Cidr>,
    /// VRRP virtual router ID (1-255), unique across the deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrid: Option<u8>,
    /// On a pair's WAN with private node addresses and a static block:
    /// carry the gateway addresses and the public route behind the VRRP
    /// virtual MAC (`00:00:5e:00:01:<vrid>`), so a handover changes no MAC
    /// the upstream sees (the default). `false` puts them on the nodes'
    /// own MACs, for an upstream that limits the MACs it learns on a port.
    /// Not `cluster.vrrp.use_vmac`, keepalived's own virtual MAC for the
    /// other networks' instances.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    #[schemars(extend("x-since" = 3))]
    pub vmac: bool,
    /// Upstream gateway (default route) for a static WAN or a management
    /// network with its own upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    /// Upstream DNS servers learned statically on this network.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    /// MTU of this network's interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// WAN shaping with CAKE, e.g. `{ egress: 900mbit }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cake: Option<Cake>,
    /// Emit and receive LLDP on this network. Default true on untagged ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lldp: Option<bool>,
    /// IPv6 on this network (#211). Unset, the network has link-local
    /// IPv6 addresses only, and routes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 5))]
    pub ipv6: Option<NetworkIpv6>,
}

/// How a network gets its IPv6 addresses. Which fields apply depends on
/// `mode` and on the network's role: each field's `x-modes` lists the
/// modes it applies to, and `x-role` (`wan` or `inside`) the networks, for
/// editors (the web UI shows a field only where it applies).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkIpv6 {
    /// On a WAN: `dhcpv6` (an address by DHCPv6 or SLAAC, as the
    /// upstream's router advertisements say, and a delegated prefix for
    /// the inside networks), `ra` (an address by SLAAC only, no delegated
    /// prefix) or `static`. On another network: `delegated` (a /64 of the
    /// WAN's delegated prefix) or `static`.
    pub mode: Ipv6Mode,
    /// `dhcpv6`: the length of the prefix to ask the ISP to delegate, 48
    /// to 64. Default 56. The ISP may delegate another.
    #[schemars(extend("x-modes" = ["dhcpv6"]))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_length: Option<u8>,
    /// `delegated`: which /64 of the delegated prefix this network takes,
    /// counting from 0 (a /56 has 256). Unique among the networks.
    #[schemars(extend("x-modes" = ["delegated"]))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<u16>,
    /// `static`: the network's prefix. A /64 on an inside network; on a
    /// WAN, the upstream link's prefix.
    #[schemars(extend("x-modes" = ["static"]))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Prefix6>,
    /// `static` on a WAN: each node's own address, in `prefix`.
    #[schemars(extend("x-modes" = ["static"], "x-role" = "wan"))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addresses: BTreeMap<String, Ipv6Addr>,
    /// `static` on a WAN: the upstream router, in `prefix` or link-local
    /// (`fe80::1`).
    #[schemars(extend("x-modes" = ["static"], "x-role" = "wan"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv6Addr>,
    /// On an inside network: the resolvers its router advertisements
    /// name (RDNSS), in place of the node, whatever DHCPv4 hands out; an
    /// empty list names none. Unset, they name the node where DHCPv4
    /// does, and none otherwise.
    #[schemars(extend("x-modes" = ["delegated", "static"], "x-role" = "inside"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<Ipv6Addr>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    Dhcpv6,
    Ra,
    Static,
    Delegated,
}

/// An IPv6 prefix, e.g. `2001:db8:0:1::/64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Prefix6(pub Ipv6Net);

impl JsonSchema for Prefix6 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Prefix6".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "IPv6 prefix, e.g. 2001:db8:0:1::/64",
            "pattern": r"^[0-9A-Fa-f:.]+/\d{1,3}$"
        })
    }
}

impl std::fmt::Display for Prefix6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum NetworkRole {
    #[default]
    Service,
    Wan,
    Management,
    Sync,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cake {
    /// Egress bandwidth, e.g. `900mbit`.
    pub bandwidth: String,
}

/// An IPv4 address with prefix length, e.g. `192.0.2.1/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cidr(pub Ipv4Net);

impl JsonSchema for Cidr {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Cidr".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "IPv4 address with prefix length, e.g. 192.0.2.1/24",
            "pattern": r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
        })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// zones, objects, policy

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    /// Member networks.
    #[serde(default)]
    pub networks: Vec<String>,
}

/// A named set: static elements, or a dynamic set filled by networkd.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Object {
    /// Element type.
    #[serde(rename = "type")]
    #[schemars(extend("x-since-values" = {"ipv6": 5}))]
    pub kind: ObjectKind,
    /// Static elements: addresses, prefixes or ranges for `ipv4` and
    /// `ipv6`, ports or ranges for `port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<MatchItem>,
    /// Fill from a network's addresses instead (`ipv4` and `ipv6`): the
    /// node's own, or the network's prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicSource>,
    /// `ipv6`: hosts in a network's IPv6 prefix, by the network and their
    /// suffix, the address's last 64 bits (`users: ["::20"]`). They follow
    /// the prefix, so a rule for a host survives the ISP renumbering a
    /// delegated one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(extend("x-since" = 5))]
    pub suffixes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    Ipv4,
    Ipv6,
    Port,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DynamicSource {
    /// The network whose addresses fill the set.
    pub network: String,
    /// `address` for the node's own address, `prefix` for the subnet.
    #[serde(default, skip_serializing_if = "is_default")]
    pub source: DynamicKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DynamicKind {
    #[default]
    Address,
    Prefix,
}

/// Policy for traffic from one zone to another.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// What happens to traffic no rule matched.
    pub action: Action,
    /// Log traffic that reaches the default action.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log: bool,
    /// Source NAT applied to this zone pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<Nat>,
    /// Named rules, evaluated by ascending `order`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Nat {
    /// `masquerade`
    Mode(NatMode),
    /// `{ snat: 203.0.113.5 }`
    Snat { snat: Ipv4Addr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NatMode {
    Masquerade,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Position within the zone pair; leave gaps (100, 200, ...).
    pub order: u32,
    /// `tcp`, `udp`, `icmp`, `icmpv6` or another protocol name nft knows.
    /// `icmp` is IPv4's and `icmpv6` IPv6's, so either limits the rule to
    /// its family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Source: an address, a prefix, a range, a list of them, or
    /// `@object`, of either family. The rule applies to the families its
    /// addresses (and `proto`) allow: with only IPv4 ones, to IPv4 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Match>,
    /// Destination, as for `src`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<Match>,
    /// Source port(s): a number, `low-high`, a list, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sport: Option<Match>,
    /// Destination port(s): a number, `low-high`, a list, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dport: Option<Match>,
    /// ICMP type names, e.g. `echo-request` (proto `icmp` or `icmpv6`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_type: Vec<String>,
    /// Rate limit, e.g. `10/second` or `100/minute burst 20`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    /// Log matching packets.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log: bool,
    /// What to do with matching packets.
    pub action: Action,
    /// Free-form note, not rendered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A match value: a scalar, a list, or an `@object` reference. An IPv6
/// address in one needs schema revision 5 (`x-since-ipv6`): earlier
/// releases read only IPv4 there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
#[schemars(extend("x-since-ipv6" = 5))]
pub enum Match {
    Number(u32),
    Text(String),
    List(Vec<MatchItem>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
#[schemars(extend("x-since-ipv6" = 5))]
pub enum MatchItem {
    Number(u32),
    Text(String),
}

/// An inbound port forward.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    /// Zone the connections arrive from. Default `wan`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// `tcp` or `udp`.
    pub proto: String,
    /// Port(s) on the firewall.
    pub dport: Match,
    /// Original destination; default any address of the arriving zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<Match>,
    /// Allowed sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Match>,
    /// Internal address to forward to.
    pub to: Ipv4Addr,
    /// Internal port; default unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_port: Option<u16>,
    /// Log forwarded connections.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log: bool,
    /// Inside zones whose clients may also use the forward by its outside
    /// address (NAT reflection), e.g. `[users]`. Needs `dst`. Clients on
    /// the server's own network are also source-NATed to the firewall's
    /// address there, so that replies come back through it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hairpin: Vec<String>,
}

/// A raw nft statement placed at a hook point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawEntry {
    /// Where the statement goes.
    pub at: RawAt,
    /// Position among raw entries at the same point.
    pub order: u32,
    /// The nft statement, without a trailing comment.
    pub nft: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RawAt {
    Pair {
        /// Zone pair, `"from->to"`.
        pair: String,
        position: RawPosition,
    },
    Hook {
        hook: RawHook,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RawPosition {
    Before,
    After,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum RawHook {
    /// Prerouting at raw priority (`notrack`, early drops).
    PreroutingRaw,
    /// Forward, before zone dispatch (global blocks, MSS clamping).
    Forward,
    /// Input, before zone dispatch.
    Input,
    /// Postrouting at source-NAT priority (custom SNAT, marks).
    Postrouting,
}

// ---------------------------------------------------------------------------
// services

/// DHCPv4: service-wide settings plus one entry per served network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Dhcp {
    /// Implementation: `kea` (the default). `networkd` is not built yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// HA mode for a pair. Default `hot-standby`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha: Option<DhcpHa>,
    /// Default lease time in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,
    /// Ping an address before offering it, and skip it if something
    /// answers: a host still using it without a lease here (after a
    /// restore, or when replacing another DHCP server). Default true; turn
    /// it off on networks that filter ICMP echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_check: Option<bool>,
    /// Served networks, by network name.
    #[serde(flatten)]
    pub networks: BTreeMap<String, DhcpNetwork>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DhcpHa {
    HotStandby,
    Off,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DhcpNetwork {
    /// Address range, `first-last`.
    pub pool: String,
    /// Fixed leases by name.
    #[serde(default)]
    pub reservations: BTreeMap<String, Reservation>,
    /// Lease time in seconds for this network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,
    /// Options; router, DNS and NTP default to the gateway address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<DhcpOptions>,
    /// Ping before offering on this network (default: `dhcp.ping_check`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_check: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub mac: String,
    pub address: Ipv4Addr,
    /// Hostname to hand out (and publish in local DNS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DhcpOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ntp: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub enabled: bool,
    /// Implementation: `unbound` (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Networks to serve; default every network with DHCP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<String>,
    /// Forward to these servers instead of recursing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarders: Vec<Ipv4Addr>,
    /// Local domain for reservation names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Extra local A records, name to address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub records: BTreeMap<String, Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ntp {
    /// Upstream servers or pools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
    /// Networks to serve time on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub serve: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vpn {
    pub listen_port: u16,
    /// More UDP ports clients may use from networks that block the listen
    /// port, e.g. `[53, 443]`: redirected to it on the WAN gateway address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_ports: Vec<u16>,
    /// Public name or address clients connect to.
    pub endpoint: String,
    /// Tunnel addresses of the firewall.
    pub addresses: Vec<Cidr>,
    /// The zone the tunnel interface belongs to.
    pub zone: String,
    /// DNS servers pushed in client configs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    /// Networks routed through the tunnel in client configs; default all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_allowed_ips: Vec<String>,
    #[serde(default)]
    pub peers: BTreeMap<String, VpnPeer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnPeer {
    pub public_key: String,
    /// The peer's tunnel address, and for a site-to-site peer the networks
    /// behind it, which are routed through the tunnel.
    pub addresses: Vec<Cidr>,
    /// `host:port`, an address or a DNS name: a site-to-site peer, which
    /// this node connects to as well as accepting it. A name is resolved
    /// again while the peer does not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Seconds between keepalives to the peer (WireGuard's
    /// `PersistentKeepalive`): it keeps a NAT mapping open, and keeps a
    /// site-to-site tunnel up, so that after a failover the new master
    /// starts it again within this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 4))]
    pub keepalive: Option<u16>,
    /// WireGuard preshared key, a cluster secret: `secret:<name>`. The
    /// client must be configured with the same key (`wg genpsk`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnClient {
    /// This node's private key, as the service issued it: a cluster
    /// secret, `secret:<name>` (in a pair both nodes are the same client).
    pub private_key: String,
    /// The tunnel addresses the service assigned.
    pub addresses: Vec<Cidr>,
    /// The zone the tunnel interface belongs to: policies from the routed
    /// networks' zones to it let their traffic through.
    pub zone: String,
    pub peer: VpnClientPeer,
    /// DNS servers DHCP hands to the routed networks, unless a network
    /// sets its own (`dhcp.<network>.options.dns`): usually the service's
    /// resolvers, which are reached through the tunnel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    /// What leaves through the tunnel.
    pub route: VpnClientRoute,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnClientPeer {
    pub public_key: String,
    /// `host:port`, an address or a DNS name.
    pub endpoint: String,
    /// Seconds between keepalives (default 25): they keep the service's
    /// NAT mapping open, and let health tell a dead tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
    /// A preshared key, if the service issued one: `secret:<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnClientRoute {
    /// The networks whose traffic to anywhere but this node's own
    /// networks leaves through the tunnel. The node's own traffic, and
    /// every other network's, keeps the WAN.
    pub networks: Vec<String>,
    /// While the tunnel is down, drop these networks' traffic to the WAN
    /// rather than let it leave there (default true).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub kill_switch: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub certificates: BTreeMap<String, Certificate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<Acme>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    pub directory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `dns-01` (default) or `http-01`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<AcmeDns>,
    /// External Account Binding key ID and secret reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eab: Option<Eab>,
    /// PEM of the CA that signs the directory's TLS certificate, for a
    /// private CA (default: the system trust store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcmeDns {
    /// `rfc2136` (built in), or a lego provider code such as `gcloud`,
    /// `cloudflare` or `route53` (https://go-acme.github.io/lego/dns/).
    pub provider: String,
    /// Secret reference, `secret:<name>`. For `rfc2136`, the TSIG key as
    /// `algorithm:name:secret`; for lego, the provider's credentials as
    /// `KEY=value` lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// For `rfc2136`, `server` (host[:port]) and `zone`; for lego, the
    /// provider's other environment variables (`GCE_PROJECT`), and lego's
    /// own (`LEGO_DNS_RESOLVERS`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Eab {
    pub kid: String,
    pub hmac: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    /// nflog group used for rule logging. Default 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<u16>,
    /// Record connection start/end with NAT mappings.
    #[serde(default, skip_serializing_if = "is_false")]
    pub connections: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteLog>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteLog {
    /// `journal-upload` (the default): systemd-journal-upload to a
    /// systemd-journal-remote collector. `syslog`: rsyslog, to a syslog
    /// collector (RFC 5424), over `protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since-values" = {"syslog": 4}))]
    pub provider: Option<String>,
    /// For journal-upload, a URL or `host:port`. For syslog, `host` or
    /// `host:port`; the port defaults to 514 (`udp`, `tcp`), 6514 (`tcp`
    /// with `tls`) or 2514 (`relp`).
    pub destination: String,
    /// syslog only: `udp` (the default; messages can be lost), `tcp`, or
    /// `relp` (acknowledged delivery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Encrypt, and check the collector's certificate: its name must be
    /// the destination's host. syslog: with `tcp` or `relp`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls: bool,
    /// syslog only: PEM of the CA that signs the collector's certificate,
    /// for a private CA (default: the system trust store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 4))]
    pub ca: Option<String>,
    /// syslog only, with `tls`: this node's client certificate for a
    /// collector that requires one (RELP over TLS always does), as a
    /// secret reference, `secret:<name>`: the private key and the
    /// certificate (with any intermediates), PEM, in one secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 4))]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// `external`: `/metrics` answers the management network without a
    /// token, for an external Prometheus. `local`: each node also keeps
    /// its own history in a local Prometheus, which the API queries
    /// (`org.sparewall.Metrics`); `/metrics` needs a token, as it does
    /// without a `metrics` section. `off`: not served.
    #[schemars(extend("x-since-values" = {"local": 4}))]
    pub mode: MetricsMode,
    /// With `mode: local`, how long history is kept, in Prometheus's units
    /// (`15d`, `12h`, `1y`). Default `15d`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 4))]
    pub retention: Option<String>,
    /// With `mode: local`, the most history may take on disk (`512MB`,
    /// `2GB`): past it, the oldest goes first, whatever `retention` says.
    /// Default `1GB`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 4))]
    pub retention_size: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MetricsMode {
    External,
    Local,
    Off,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub enabled: bool,
    /// restic repository URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// systemd calendar expression. Default `hourly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    /// Secret reference for repository credentials (not the password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// Generations to include. Default 20.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generations: Option<u32>,
    /// What the repository keeps of this node's snapshots: after each
    /// successful send the node runs `restic forget` on its own snapshots
    /// (`--host <node> --tag sparewall`) with these keep rules, restic's own
    /// names. Without it, a repository keeps `hourly: 48, daily: 30,
    /// weekly: 12, monthly: 24`; `enabled: false` keeps everything (#140).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 3))]
    pub retention: Option<Retention>,
}

/// restic's keep rules (`restic forget --keep-*`): a snapshot is kept if
/// any rule keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    /// `false` keeps every snapshot: prune elsewhere.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// The newest N snapshots (`--keep-last`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<u32>,
    /// The newest snapshot of each of the last N hours (`--keep-hourly`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hourly: Option<u32>,
    /// … days (`--keep-daily`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,
    /// … weeks (`--keep-weekly`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly: Option<u32>,
    /// … months (`--keep-monthly`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly: Option<u32>,
    /// … years (`--keep-yearly`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yearly: Option<u32>,
}

impl Retention {
    /// What a repository keeps when `retention` is not set: two days at
    /// full resolution, then daily, weekly and monthly for two years.
    pub fn default_policy() -> Retention {
        Retention {
            enabled: true,
            last: None,
            hourly: Some(48),
            daily: Some(30),
            weekly: Some(12),
            monthly: Some(24),
            yearly: None,
        }
    }

    /// restic's flags for the rules that keep something.
    pub fn keep_flags(&self) -> Vec<String> {
        [
            ("last", self.last),
            ("hourly", self.hourly),
            ("daily", self.daily),
            ("weekly", self.weekly),
            ("monthly", self.monthly),
            ("yearly", self.yearly),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.filter(|n| *n > 0).map(|n| format!("--keep-{k}={n}")))
        .collect()
    }
}

impl Backup {
    /// The retention the node applies after a send, if any: the document's,
    /// or the default when a repository is set; none when turned off.
    pub fn effective_retention(&self) -> Option<Retention> {
        self.repository.as_ref()?;
        let r = self
            .retention
            .clone()
            .unwrap_or_else(Retention::default_policy);
        r.enabled.then_some(r)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    /// `stable` or `testing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// `manual` (the default): upgrades run when asked for, with
    /// `sparewall upgrade`. `windowed`: the pair's master (or a standalone
    /// node) upgrades by itself when `window` opens and the channel offers
    /// a newer image, through the same health-gated sequence (#84).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since-values" = {"windowed": 3}))]
    pub mode: Option<UpdateMode>,
    /// When a scheduled upgrade may start: a systemd calendar expression
    /// (`Sun *-*-* 03:00`), in the node's time zone (UTC unless set).
    /// Required with `mode: windowed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    /// How many minutes after the window opens an upgrade may still start
    /// (default 60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-since" = 3))]
    pub window_minutes: Option<u32>,
    /// Check the channel for a newer image every few hours, and log when
    /// one appears (on by default). `false` keeps the node from contacting
    /// the registry on its own, for an air-gapped site; `sparewall upgrade
    /// --check` still asks when run.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    #[schemars(extend("x-since" = 3))]
    pub check: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    Manual,
    Windowed,
}

// ---------------------------------------------------------------------------
// helpers

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == T::default()
}
