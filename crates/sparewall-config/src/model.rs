//! The configuration document, schema version 1.
//!
//! Struct field order is the canonical key order used by [`crate::canonical`].
//! Collections of named things are `BTreeMap`s keyed by name, so they export
//! sorted and merge one entry at a time.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The schema version this crate reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// A whole deployment: one node or an HA pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "Sparewall configuration document")]
pub struct Document {
    /// Schema version of this document.
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
    /// One node name (standalone) or two (an HA pair).
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
    /// VRRP virtual router ID (1-255), unique across the deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrid: Option<u8>,
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
    pub kind: ObjectKind,
    /// Static elements: addresses or prefixes for `ipv4`, ports or ranges for
    /// `port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<MatchItem>,
    /// Fill from a network's addresses instead (`ipv4` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    Ipv4,
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
    /// `tcp`, `udp`, `icmp` or another protocol name nft knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Source: an address, a prefix, a list of them, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Match>,
    /// Destination: an address, a prefix, a list of them, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<Match>,
    /// Source port(s): a number, `low-high`, a list, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sport: Option<Match>,
    /// Destination port(s): a number, `low-high`, a list, or `@object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dport: Option<Match>,
    /// ICMP type names, e.g. `echo-request` (proto `icmp`).
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

/// A match value: a scalar, a list, or an `@object` reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Match {
    Number(u32),
    Text(String),
    List(Vec<MatchItem>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
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
    pub addresses: Vec<Cidr>,
    /// Static endpoint, for site-to-site peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// WireGuard preshared key, a cluster secret: `secret:<name>`. The
    /// client must be configured with the same key (`wg genpsk`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
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
    /// `journal-upload` (the default). `syslog` is not built yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// URL or `host:port`.
    pub destination: String,
    /// `udp`, `tcp`, `relp` (syslog only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// `external`: `/metrics` answers the management network without a
    /// token, for an external Prometheus. `off`: not served. (Without a
    /// `metrics` section it needs a token.) `local` (a local Prometheus)
    /// is not built yet and is rejected.
    pub mode: MetricsMode,
    /// Local Prometheus retention, e.g. `15d`. Not built yet, with the
    /// local mode: rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    /// `stable` or `testing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// `manual` (the default): upgrades run when asked for, with
    /// `sparewall upgrade`. `windowed` (automatic upgrades in `window`) is
    /// not built yet and is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<UpdateMode>,
    /// Maintenance window as a systemd calendar expression. Not built yet,
    /// with the windowed mode: rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
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
