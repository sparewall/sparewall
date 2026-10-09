//! Renderers: pure functions from a document (and a node name) to the files
//! each daemon reads. Nothing here touches the system; `sparewall-core`
//! installs the files and reloads daemons.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sparewall_config::Document;
use sparewall_config::identity::Identity;

pub mod chrony;
pub mod conntrackd;
mod ini;
pub mod kea;
pub mod keepalived;
pub mod logging;
pub mod networkd;
pub mod nft;
pub mod sysctl;
pub mod unbound;

/// Where secrets and node keys are made available to daemons at runtime.
pub const KEY_DIR: &str = "/run/sparewall/keys";
/// The sync tunnel's private key (node secret).
pub const SYNC_KEY_FILE: &str = "/var/lib/sparewall/keys/sync.key";

/// Subsystems a rendered file belongs to, used to decide what to reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Subsystem {
    Networkd,
    Nft,
    Sysctl,
    Keepalived,
    Conntrackd,
    Dhcp,
    Dns,
    Ntp,
    Logging,
}

impl Subsystem {
    /// The directory (relative to a generation's `rendered/`) holding this
    /// subsystem's files.
    pub fn dir(self) -> &'static str {
        match self {
            Subsystem::Networkd => "network",
            Subsystem::Nft => "nftables",
            Subsystem::Sysctl => "sysctl",
            Subsystem::Keepalived => "keepalived",
            Subsystem::Conntrackd => "conntrackd",
            Subsystem::Dhcp => "dhcp",
            Subsystem::Dns => "dns",
            Subsystem::Ntp => "ntp",
            Subsystem::Logging => "logging",
        }
    }

    pub fn all() -> &'static [Subsystem] {
        &[
            Subsystem::Networkd,
            Subsystem::Nft,
            Subsystem::Sysctl,
            Subsystem::Keepalived,
            Subsystem::Conntrackd,
            Subsystem::Dhcp,
            Subsystem::Dns,
            Subsystem::Ntp,
            Subsystem::Logging,
        ]
    }
}

/// Everything rendered for one node and one generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendered {
    /// Relative path (`network/10-sparewall-uplink.link`) to content.
    pub files: BTreeMap<String, String>,
    /// Facts the apply step needs that are not files.
    pub meta: Meta,
}

/// A service a provider runs, and how the coordinator manages it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Provider name, e.g. `kea`.
    pub provider: String,
    /// The systemd unit (a Quadlet container or a host service).
    pub unit: String,
    /// The files this service reads.
    pub subsystem: Subsystem,
    /// Whether a config change can be applied with a reload rather than a
    /// restart.
    pub reload: bool,
    /// How to dry-run the rendered files with the daemon's own checker.
    pub check: Option<CheckSpec>,
}

/// A config test: run `command` with the subsystem's files available at
/// `mount`, either inside the provider's container image (`container`, the
/// Quadlet that names the image) or on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSpec {
    pub container: Option<String>,
    pub mount: String,
    pub command: Vec<String>,
    /// Files to check in place of the rendered ones, where the checker
    /// would reject something only true at runtime (e.g. a VLAN interface
    /// that does not exist until the change is applied).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// nft sets filled by networkd, which a reload must not delete.
    pub preserved_sets: Vec<String>,
    /// For each preserved set, the link whose reconfigure refills it.
    pub set_links: BTreeMap<String, String>,
    /// Interfaces that must be up for the node to be ready.
    pub required_links: Vec<String>,
    /// Interfaces that carry gateway addresses.
    pub vip_links: Vec<String>,
    /// Services this generation runs, by role (`dhcp`, `dns`, `ntp`).
    pub services: BTreeMap<String, Service>,
    /// Bootstrap mode (generation 0).
    pub bootstrap: bool,
}

impl Rendered {
    fn add(&mut self, sub: Subsystem, name: impl AsRef<str>, content: String) {
        self.files
            .insert(format!("{}/{}", sub.dir(), name.as_ref()), content);
    }

    /// Files belonging to one subsystem, by file name.
    pub fn subsystem(&self, sub: Subsystem) -> BTreeMap<&str, &str> {
        let prefix = format!("{}/", sub.dir());
        self.files
            .iter()
            .filter_map(|(k, v)| k.strip_prefix(&prefix).map(|n| (n, v.as_str())))
            .collect()
    }

    /// Subsystems whose files differ between two renderings.
    pub fn changed(&self, other: &Rendered) -> Vec<Subsystem> {
        Subsystem::all()
            .iter()
            .copied()
            .filter(|s| self.subsystem(*s) != other.subsystem(*s))
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("node {0:?} is not in cluster.nodes")]
    UnknownNode(String),
    #[error("{0}")]
    Invalid(String),
}

/// Render a validated document for one node.
pub fn render(doc: &Document, node: &str) -> Result<Rendered, Error> {
    if !doc.cluster.nodes.iter().any(|n| n == node) {
        return Err(Error::UnknownNode(node.to_string()));
    }
    let mut out = Rendered::default();
    networkd::render(doc, node, &mut out)?;
    nft::render(doc, node, &mut out)?;
    sysctl::render(doc, node, &mut out);
    kea::render(doc, node, &mut out)?;
    unbound::render(doc, node, &mut out)?;
    chrony::render(doc, node, &mut out);
    keepalived::render(doc, node, &mut out);
    conntrackd::render(doc, node, &mut out);
    logging::render(doc, &mut out);
    Ok(out)
}

/// Render the built-in bootstrap configuration from the node identity: only
/// the management port up, SSH on it, all forwarding dropped.
pub fn render_bootstrap(id: &Identity) -> Rendered {
    let mut out = Rendered::default();
    networkd::render_bootstrap(id, &mut out);
    nft::render_bootstrap(id, &mut out);
    sysctl::render_bootstrap(&mut out);
    chrony::render_bootstrap(&mut out);
    out.meta.bootstrap = true;
    out
}

pub(crate) const HEADER: &str =
    "# Generated by sparewalld. Do not edit: change the configuration document instead.\n";
