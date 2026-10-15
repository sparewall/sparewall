//! The service providers each role can use (design: "Service providers"),
//! what each can do, and the state it keeps. Validation, the renderers and
//! the coordinator all go by this table, so a provider is either built and
//! described here or rejected as not built yet; none is accepted and then
//! silently left out.

use crate::model::Document;

/// A role a provider fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Dhcp,
    Dns,
    LogForwarding,
    AcmeDns,
}

impl Role {
    /// The document path that chooses the provider.
    pub fn path(self) -> &'static str {
        match self {
            Role::Dhcp => "dhcp.provider",
            Role::Dns => "dns.provider",
            Role::LogForwarding => "logging.remote.provider",
            Role::AcmeDns => "acme.dns.provider",
        }
    }
}

/// State a provider keeps that a switch would lose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    /// What it is, for messages: "Kea's lease database".
    pub what: &'static str,
    /// Where it lives on the node, if the coordinator reads it (backups).
    pub path: Option<&'static str>,
    /// Providers that can import it; switching to any other loses it.
    pub moves_to: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    pub role: Role,
    pub name: &'static str,
    /// The provider used when the document names none.
    pub default: bool,
    /// Built into this release; otherwise rejected as not built yet.
    pub built: bool,
    /// Runs in an HA pair (both nodes serve, with failover).
    pub ha: bool,
    pub state: Option<State>,
}

/// Kea's lease file in its named volume.
pub const KEA_LEASES: &str =
    "/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv";

pub const PROVIDERS: &[Provider] = &[
    Provider {
        role: Role::Dhcp,
        name: "kea",
        default: true,
        built: true,
        ha: true,
        state: Some(State {
            what: "Kea's lease database",
            path: Some(KEA_LEASES),
            moves_to: &["kea"],
        }),
    },
    Provider {
        role: Role::Dhcp,
        name: "networkd",
        default: false,
        built: false,
        ha: false,
        state: Some(State {
            what: "networkd's DHCP server leases",
            path: None,
            moves_to: &["networkd"],
        }),
    },
    Provider {
        role: Role::Dns,
        name: "unbound",
        default: true,
        built: true,
        ha: true,
        state: None,
    },
    Provider {
        role: Role::LogForwarding,
        name: "journal-upload",
        default: true,
        built: true,
        ha: true,
        state: None,
    },
    Provider {
        role: Role::LogForwarding,
        name: "syslog",
        default: false,
        built: false,
        ha: true,
        state: None,
    },
    Provider {
        role: Role::AcmeDns,
        name: "rfc2136",
        default: true,
        built: true,
        ha: true,
        state: None,
    },
];

/// A provider of `role` by name.
pub fn find(role: Role, name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.role == role && p.name == name)
}

/// The names of `role`'s providers, built ones first, for messages.
pub fn names(role: Role) -> Vec<&'static str> {
    let mut v: Vec<&Provider> = PROVIDERS.iter().filter(|p| p.role == role).collect();
    v.sort_by_key(|p| !p.built);
    v.into_iter().map(|p| p.name).collect()
}

/// The provider a role uses when the document names none.
pub fn chosen_default(role: Role) -> &'static str {
    PROVIDERS
        .iter()
        .find(|p| p.role == role && p.default)
        .map_or("", |p| p.name)
}

/// The provider a document chooses for a role it uses (`None` when the
/// role is not used, or for ACME, which chooses one per certificate).
pub fn chosen(doc: &Document, role: Role) -> Option<&str> {
    let named = match role {
        Role::Dhcp => doc.dhcp.as_ref()?.provider.as_deref(),
        Role::Dns => doc.dns.as_ref()?.provider.as_deref(),
        Role::LogForwarding => doc.logging.as_ref()?.remote.as_ref()?.provider.as_deref(),
        Role::AcmeDns => return None,
    };
    Some(named.unwrap_or_else(|| chosen_default(role)))
}

/// Warnings for state a change of provider loses: one per role whose
/// provider changes away from one keeping state the new one cannot
/// import.
pub fn switch_warnings(old: &Document, new: &Document) -> Vec<String> {
    let mut out = Vec::new();
    for role in [Role::Dhcp, Role::Dns, Role::LogForwarding] {
        let (Some(from), Some(to)) = (chosen(old, role), chosen(new, role)) else {
            continue;
        };
        if from == to {
            continue;
        }
        if let Some(s) = find(role, from).and_then(|p| p.state)
            && !s.moves_to.contains(&to)
        {
            out.push(format!(
                "{}: switching from {from} to {to} does not carry over {}; it starts empty",
                role.path(),
                s.what
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_built_default_per_role() {
        for role in [Role::Dhcp, Role::Dns, Role::LogForwarding, Role::AcmeDns] {
            let defaults: Vec<_> = PROVIDERS
                .iter()
                .filter(|p| p.role == role && p.default)
                .collect();
            assert_eq!(defaults.len(), 1, "{role:?}");
            assert!(defaults[0].built, "{role:?}");
        }
    }
}
