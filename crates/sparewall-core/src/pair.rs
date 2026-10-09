//! Pair sync states (design: "Pair sync states").
//!
//! Each node reports a desired hash (the generation it holds) and an
//! applied hash (what its daemons verifiably run). Lease replication,
//! connection-state sync and image versions never count toward this.

use serde::{Deserialize, Serialize};

/// What one node reports about its configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeView {
    pub node: String,
    pub active: u64,
    pub desired: String,
    pub applied: Option<String>,
    /// `(id, hash)` from the active generation back through each base.
    pub lineage: Vec<(u64, String)>,
    /// An activation is in progress.
    #[serde(default)]
    pub applying: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SyncState {
    /// All four hashes equal.
    InSync,
    /// Desired equal, an applied hash differs, apply in progress.
    Applying,
    /// Desired equal but a node runs other config after its apply finished.
    ApplyFailed {
        node: String,
    },
    /// The peer's generation is an ancestor of the local one: push pending.
    PeerBehind,
    /// The local generation is an ancestor of the peer's.
    LocalBehind,
    /// Desired hashes differ and neither descends from the other.
    Diverged,
    PeerUnreachable,
    /// Standalone, or the sync keys are not in the document yet.
    Unpaired,
}

impl SyncState {
    pub fn name(&self) -> &'static str {
        match self {
            SyncState::InSync => "in-sync",
            SyncState::Applying => "applying",
            SyncState::ApplyFailed { .. } => "apply-failed",
            SyncState::PeerBehind => "peer-behind",
            SyncState::LocalBehind => "local-behind",
            SyncState::Diverged => "diverged",
            SyncState::PeerUnreachable => "peer-unreachable",
            SyncState::Unpaired => "unpaired",
        }
    }
}

fn descends(newer: &NodeView, older: &NodeView) -> bool {
    newer
        .lineage
        .iter()
        .any(|(id, hash)| *id == older.active && *hash == older.desired)
}

pub fn sync_state(local: &NodeView, peer: Option<&NodeView>) -> SyncState {
    let Some(peer) = peer else {
        return SyncState::PeerUnreachable;
    };
    if local.desired == peer.desired {
        for n in [local, peer] {
            if n.applied.as_deref() != Some(n.desired.as_str()) {
                return if n.applying {
                    SyncState::Applying
                } else {
                    SyncState::ApplyFailed {
                        node: n.node.clone(),
                    }
                };
            }
        }
        return SyncState::InSync;
    }
    if descends(local, peer) {
        SyncState::PeerBehind
    } else if descends(peer, local) {
        SyncState::LocalBehind
    } else {
        SyncState::Diverged
    }
}

/// The generations to push, oldest first, to bring a peer at `peer_active`
/// up to `local`: those after `peer_active` in the local lineage. `None`
/// when the peer is not an ancestor.
pub fn push_plan(local: &NodeView, peer_active: u64, peer_hash: &str) -> Option<Vec<u64>> {
    let pos = local
        .lineage
        .iter()
        .position(|(id, h)| *id == peer_active && h == peer_hash)?;
    Some(
        local.lineage[..pos]
            .iter()
            .rev()
            .map(|(id, _)| *id)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(node: &str, chain: &[(u64, &str)], applied: Option<&str>) -> NodeView {
        let mut lineage: Vec<(u64, String)> =
            chain.iter().map(|(i, h)| (*i, h.to_string())).collect();
        lineage.push((0, String::new()));
        NodeView {
            node: node.into(),
            active: chain.first().map_or(0, |c| c.0),
            desired: chain.first().map_or(String::new(), |c| c.1.to_string()),
            applied: applied.map(String::from),
            lineage,
            applying: false,
        }
    }

    #[test]
    fn states() {
        let a = view("fw1", &[(3, "c"), (2, "b"), (1, "a")], Some("c"));
        let b = view("fw2", &[(3, "c"), (2, "b"), (1, "a")], Some("c"));
        assert_eq!(sync_state(&a, Some(&b)), SyncState::InSync);
        assert_eq!(sync_state(&a, None), SyncState::PeerUnreachable);

        let mut b2 = b.clone();
        b2.applied = Some("b".into());
        assert_eq!(
            sync_state(&a, Some(&b2)),
            SyncState::ApplyFailed { node: "fw2".into() }
        );
        b2.applying = true;
        assert_eq!(sync_state(&a, Some(&b2)), SyncState::Applying);

        let behind = view("fw2", &[(2, "b"), (1, "a")], Some("b"));
        assert_eq!(sync_state(&a, Some(&behind)), SyncState::PeerBehind);
        assert_eq!(sync_state(&behind, Some(&a)), SyncState::LocalBehind);
        assert_eq!(push_plan(&a, 2, "b"), Some(vec![3]));
        assert_eq!(push_plan(&a, 1, "a"), Some(vec![2, 3]));
        assert_eq!(push_plan(&a, 0, ""), Some(vec![1, 2, 3]));

        let forked = view("fw2", &[(3, "x"), (2, "b"), (1, "a")], Some("x"));
        assert_eq!(sync_state(&a, Some(&forked)), SyncState::Diverged);
        assert_eq!(push_plan(&a, 3, "x"), None);
    }
}
