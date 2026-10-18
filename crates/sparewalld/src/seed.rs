//! A configuration supplied at install time (#46), applied by the node
//! itself so that it can come up configured with no one at the console.
//!
//! The same channels as the identity carry it: the `sparewall.config`
//! credential, or `/etc/sparewall/config.{json,yaml}` (written by
//! `sparewall init --config`, which a seed stick runs). While the node is
//! in bootstrap mode (generation 0), a seed not tried before is applied
//! like any other change, with a confirm window, and the node confirms it
//! itself once its health has stayed out of `failed` for a few checks.
//! Otherwise the window closes and the node returns to bootstrap mode.
//! A seed that is refused or reverts shows in health until the node is
//! configured. Once it is, seeds are ignored.
//!
//! Each source remembers the content it last tried, so a seed is tried
//! once: a corrected seed stick is tried when it is put back in, but the
//! same stick left in, or a credential delivered again at each boot, is
//! not tried again.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sparewall_core::{ApplyOptions, Check, Coordinator, Error, Level, System};
use tokio::sync::broadcast;

use crate::service::{Core, with_core_raw};

/// The systemd credential carrying a seed (`ImportCredential=sparewall.*`).
pub const CREDENTIAL: &str = "sparewall.config";
/// Where `sparewall init --config` drops a seed.
pub const DROPS: &[&str] = &["/etc/sparewall/config.json", "/etc/sparewall/config.yaml"];
/// What was tried, under the state directory.
const RECORD: &str = "seed.json";
/// The confirm window of a seeded generation.
const WINDOW: u32 = 600;
/// Consecutive checks out of `failed` before the node confirms.
const HEALTHY_CHECKS: u32 = 3;
const POLL: Duration = Duration::from_secs(5);
const AUTHOR: &str = "seed";

/// Where seeds come from, in order.
pub fn sources(credentials: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = DROPS.iter().map(PathBuf::from).collect();
    if let Some(dir) = credentials {
        v.push(dir.join(CREDENTIAL));
    }
    v
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The last seed tried from each source.
    #[serde(default)]
    tried: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
enum Outcome {
    /// Applied, waiting to be confirmed.
    Pending {
        id: u64,
        healthy: u32,
    },
    Confirmed {
        id: u64,
    },
    /// Not applied (unreadable, or invalid for this node).
    Refused {
        source: String,
        reason: String,
    },
    /// Applied, but its confirm window closed first.
    Reverted {
        id: u64,
    },
}

/// A seed not tried before.
#[derive(Debug, Clone)]
pub struct Seed {
    source: String,
    fingerprint: String,
    text: String,
}

/// The first source holding a seed it has not tried.
fn find(sources: &[PathBuf], rec: &Record) -> Option<Seed> {
    sources.iter().find_map(|p| {
        let text = std::fs::read_to_string(p).ok()?;
        let source = p.display().to_string();
        let fingerprint = hex::encode(Sha256::digest(text.as_bytes()));
        (rec.tried.get(&source) != Some(&fingerprint)).then_some(Seed {
            source,
            fingerprint,
            text,
        })
    })
}

/// Try a new seed, then move a pending one along: confirm it once health
/// has held, or note that it reverted.
fn step<S: System>(
    c: &mut Coordinator<S>,
    rec: &mut Record,
    seed: Option<Seed>,
) -> Result<(), Error> {
    if let Some(s) = seed {
        rec.tried.insert(s.source.clone(), s.fingerprint);
        let st = c.state()?;
        if st.active != 0 || st.pending.is_some() {
            tracing::warn!(source = %s.source, active = st.active, "ignoring a seeded configuration: this node is configured already");
        } else {
            let format = sparewall_config::Format::detect(Some(&s.source), &s.text);
            let applied = sparewall_config::parse_value(&s.text, format)
                .map_err(|e| Error::Validation(vec![e.to_string()]))
                .and_then(|v| {
                    c.apply(
                        v,
                        &ApplyOptions {
                            base: 0,
                            confirm_seconds: Some(WINDOW),
                            author: AUTHOR.into(),
                            dry_run: false,
                            note: Some(format!("seeded from {}", s.source)),
                            stage_sync_link: false,
                        },
                    )
                });
            rec.outcome = Some(match applied {
                Ok(r) => {
                    tracing::info!(id = r.generation.id, source = %s.source, "applied the seeded configuration; confirming once healthy");
                    Outcome::Pending {
                        id: r.generation.id,
                        healthy: 0,
                    }
                }
                Err(e) => {
                    tracing::error!(source = %s.source, error = %e, "refused the seeded configuration");
                    Outcome::Refused {
                        source: s.source,
                        reason: e.to_string(),
                    }
                }
            });
            return Ok(());
        }
    }
    let Some(Outcome::Pending { id, healthy }) = rec.outcome.clone() else {
        return Ok(());
    };
    let st = c.state()?;
    rec.outcome = Some(match st.pending {
        Some(p) if p.id == id => {
            let healthy = if c.health()?.level == Level::Failed {
                0
            } else {
                healthy + 1
            };
            if healthy >= HEALTHY_CHECKS {
                c.confirm(id)?;
                tracing::info!(id, "confirmed the seeded configuration");
                Outcome::Confirmed { id }
            } else {
                Outcome::Pending { id, healthy }
            }
        }
        // Confirmed by an admin.
        None if st.active == id => Outcome::Confirmed { id },
        _ => {
            tracing::warn!(id, "the seeded configuration reverted");
            Outcome::Reverted { id }
        }
    });
    Ok(())
}

/// A seed that did not take, while the node is still in bootstrap mode.
fn checks(rec: &Record, active: u64) -> Vec<Check> {
    if active != 0 {
        return vec![];
    }
    match &rec.outcome {
        Some(Outcome::Refused { source, reason }) => vec![Check::new(
            "seed",
            Level::Degraded,
            format!("the configuration in {source} was refused: {reason}"),
        )],
        Some(Outcome::Reverted { id }) => vec![Check::new(
            "seed",
            Level::Degraded,
            format!(
                "the seeded configuration (generation {id}) reverted: \
                 health stayed failed until its confirm window closed"
            ),
        )],
        _ => vec![],
    }
}

/// Look for seeds and see them through, every few seconds.
pub async fn seed_loop(
    core: Core,
    events: broadcast::Sender<Value>,
    state: PathBuf,
    sources: Vec<PathBuf>,
) {
    let path = state.join(RECORD);
    let mut rec: Record = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    loop {
        let seed = find(&sources, &rec);
        let before = rec.clone();
        let r = with_core_raw(&core, &events, move |c| {
            let mut rec = rec;
            step(c, &mut rec, seed)?;
            c.set_named_checks("seed", checks(&rec, c.active()?));
            Ok(rec)
        })
        .await;
        rec = match r {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "seeded configuration");
                before.clone()
            }
        };
        if rec != before
            && let Err(e) = sparewall_core::store::write_atomic(
                &path,
                &serde_json::to_vec_pretty(&rec).unwrap_or_default(),
            )
        {
            tracing::error!(error = %e, path = %path.display(), "cannot record the seed");
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use sparewall_config::identity::{BootstrapPort, Identity};
    use sparewall_core::Store;
    use sparewall_core::system::Fake;

    use super::*;

    const SITE: &str = "\
schema: 1
cluster: { nodes: [fw1] }
management: { network: mgmt }
ports:
  fw1:
    uplink: { nic: \"pci-0000:00:05.0\" }
networks:
  mgmt: { port: uplink, role: management, dhcp_client: true }
zones:
  mgmt: { networks: [mgmt] }
";

    struct T {
        dir: tempfile::TempDir,
        c: Coordinator<Fake>,
        rec: Record,
    }

    fn setup() -> T {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let id = Identity {
            node: "fw1".into(),
            ssh_keys: vec![],
            password_hash: None,
            management: BootstrapPort {
                nic: "52:54:00:aa:00:01".into(),
                vlan: None,
                address: None,
                gateway: None,
                dns: vec![],
            },
        };
        let mut c = Coordinator::new(store, Fake::default(), id);
        c.boot(false).unwrap();
        T {
            dir,
            c,
            rec: Record::default(),
        }
    }

    impl T {
        fn drop_seed(&self, text: &str) -> Vec<PathBuf> {
            let p = self.dir.path().join("config.yaml");
            std::fs::write(&p, text).unwrap();
            vec![p]
        }
        fn step(&mut self, sources: &[PathBuf]) {
            let seed = find(sources, &self.rec);
            step(&mut self.c, &mut self.rec, seed).unwrap();
        }
    }

    #[test]
    fn a_seed_is_applied_and_confirmed_once_healthy() {
        let mut t = setup();
        let src = t.drop_seed(SITE);
        t.step(&src);
        let st = t.c.state().unwrap();
        assert_eq!((st.active, st.confirmed), (1, 0));
        assert_eq!(t.c.generation(1).unwrap().author, AUTHOR);
        // The port is not up yet: health is failed, so it waits.
        for _ in 0..2 * HEALTHY_CHECKS {
            t.step(&src);
        }
        assert_eq!(t.c.health().unwrap().level, Level::Failed);
        assert!(t.c.state().unwrap().pending.is_some());
        t.c.system().links.insert("uplink".into(), "up".into());
        for _ in 1..HEALTHY_CHECKS {
            t.step(&src);
            assert!(t.c.state().unwrap().pending.is_some());
        }
        t.step(&src);
        let st = t.c.state().unwrap();
        assert_eq!((st.active, st.confirmed), (1, 1));
        assert_eq!(t.rec.outcome, Some(Outcome::Confirmed { id: 1 }));
        // Tried once: the same file is not applied again.
        t.step(&src);
        assert_eq!(t.c.state().unwrap().active, 1);
    }

    #[test]
    fn an_invalid_seed_leaves_bootstrap_mode_and_says_why() {
        let mut t = setup();
        let src =
            t.drop_seed(&SITE.replace("cluster: { nodes: [fw1] }", "cluster: { nodes: [fw9] }"));
        t.step(&src);
        assert_eq!(t.c.state().unwrap().active, 0);
        let c = checks(&t.rec, 0);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].level, Level::Degraded);
        assert!(c[0].message.contains("refused"), "{}", c[0].message);
    }

    #[test]
    fn a_seed_that_reverts_is_reported_and_a_new_one_is_tried() {
        let mut t = setup();
        let src = t.drop_seed(SITE);
        t.step(&src);
        // The window closes before health holds.
        t.c.tick(i64::MAX).unwrap();
        t.step(&src);
        assert_eq!(t.rec.outcome, Some(Outcome::Reverted { id: 1 }));
        assert_eq!(t.c.state().unwrap().active, 0);
        assert!(checks(&t.rec, 0)[0].message.contains("reverted"));
        // The same seed again (a stick left in, at the next boot): not
        // tried again.
        let src = t.drop_seed(SITE);
        t.step(&src);
        assert_eq!(t.rec.outcome, Some(Outcome::Reverted { id: 1 }));
        assert_eq!(t.c.state().unwrap().active, 0);
        // A corrected one, in bootstrap mode: tried.
        let src = t.drop_seed(&SITE.replace("dhcp_client: true", "dhcp_client: true, mtu: 1400"));
        t.step(&src);
        assert!(matches!(t.rec.outcome, Some(Outcome::Pending { .. })));
        assert!(t.c.state().unwrap().active > 0);
    }

    #[test]
    fn a_seed_is_ignored_once_the_node_is_configured() {
        let mut t = setup();
        t.c.system().links.insert("uplink".into(), "up".into());
        let src = t.drop_seed(SITE);
        for _ in 0..=HEALTHY_CHECKS {
            t.step(&src);
        }
        assert_eq!(t.c.state().unwrap().confirmed, 1);
        let src = t.drop_seed(&SITE.replace("dhcp_client: true", "dhcp_client: true, mtu: 1400"));
        t.step(&src);
        assert_eq!(t.c.state().unwrap().active, 1);
        assert!(checks(&t.rec, 1).is_empty());
    }

    #[test]
    fn a_seed_is_new_only_when_its_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(CREDENTIAL);
        std::fs::write(&p, SITE).unwrap();
        let src = [p.clone()];
        let mut rec = Record::default();
        let s = find(&src, &rec).unwrap();
        rec.tried.insert(s.source, s.fingerprint);
        // Written again, as at each boot.
        std::fs::write(&p, SITE).unwrap();
        assert!(find(&src, &rec).is_none());
        std::fs::write(&p, format!("{SITE}\n")).unwrap();
        assert!(find(&src, &rec).is_some());
    }
}
