//! Validate, render, dry-run, activate, and confirm or revert (design:
//! "Apply, confirm, roll back").

use std::time::Instant;

use serde::Serialize;
use serde_json::Value;
use sparewall_config::identity::Identity;
use sparewall_config::{Document, validate};
use sparewall_render::{Rendered, Subsystem, nft};

use crate::Error;
use crate::health::{Check, Health, Level};
use crate::store::{Generation, Pending, State, Store};
use crate::system::{Files, System};

/// Subsystems whose files a provider service reads from /run/sparewall.
const PROVIDER_SUBSYSTEMS: &[Subsystem] = &[Subsystem::Dhcp, Subsystem::Dns, Subsystem::Ntp];

fn subsystem_files(r: &Rendered, s: Subsystem) -> Files {
    r.subsystem(s)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Generations kept on disk.
pub const DEFAULT_KEEP: usize = 50;

/// Options common to every mutation.
#[derive(Debug, Clone)]
pub struct ApplyOptions {
    /// The generation the change was derived from.
    pub base: u64,
    /// Revert unless confirmed within this many seconds (`None` or 0:
    /// confirmed at once).
    pub confirm_seconds: Option<u32>,
    pub author: String,
    /// Validate, render and check only.
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub generation: Generation,
    /// Subsystems whose configuration changed.
    pub changed: Vec<String>,
    /// One line per changed document path.
    pub diff: Vec<String>,
    pub warnings: Vec<String>,
    /// The document equals the active one; nothing was done.
    pub unchanged: bool,
    pub dry_run: bool,
}

/// Things that happened, for subscribers and the journal.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Event {
    Applied {
        id: u64,
        hash: String,
        author: String,
        pending: bool,
    },
    Confirmed {
        id: u64,
    },
    RolledBack {
        to: u64,
        from: u64,
        reason: String,
    },
    ApplyFailed {
        id: u64,
        error: String,
    },
}

pub struct Coordinator<S: System> {
    store: Store,
    sys: S,
    identity: Identity,
    applied_hash: Option<String>,
    last_error: Option<String>,
    last_apply_ms: Option<u128>,
    events: Vec<Event>,
    keep: usize,
}

fn now_unix() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn bootstrap_generation() -> Generation {
    Generation {
        id: 0,
        hash: String::new(),
        base: None,
        schema: sparewall_config::SCHEMA_VERSION,
        author: "bootstrap".into(),
        created: String::new(),
        summary: vec![],
    }
}

impl<S: System> Coordinator<S> {
    pub fn new(store: Store, sys: S, identity: Identity) -> Self {
        Coordinator {
            store,
            sys,
            identity,
            applied_hash: None,
            last_error: None,
            last_apply_ms: None,
            events: Vec::new(),
            keep: DEFAULT_KEEP,
        }
    }

    pub fn node(&self) -> &str {
        &self.identity.node
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn system(&mut self) -> &mut S {
        &mut self.sys
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Events since the last call.
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    pub fn state(&self) -> Result<State, Error> {
        self.store.state()
    }

    /// The live generation id.
    pub fn active(&self) -> Result<u64, Error> {
        Ok(self.store.state()?.active)
    }

    pub fn generation(&self, id: u64) -> Result<Generation, Error> {
        if id == 0 {
            Ok(bootstrap_generation())
        } else {
            self.store.meta(id)
        }
    }

    fn rendered_for(&self, id: u64) -> Result<Rendered, Error> {
        if id == 0 {
            return Ok(sparewall_render::render_bootstrap(&self.identity));
        }
        match self.store.rendered(id) {
            Ok(r) => Ok(r),
            // Restored from a bundle, which carries documents only.
            Err(Error::Io { .. }) if self.store.exists(id) => {
                let doc = self.store.document(id)?;
                let r = sparewall_render::render(&doc, self.node())
                    .map_err(|e| Error::Internal(format!("re-rendering generation {id}: {e}")))?;
                self.store.set_rendered(id, &r)?;
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    /// The document of a generation as a value (`{}` for bootstrap).
    pub fn document_value(&self, id: u64) -> Result<Value, Error> {
        if id == 0 {
            Ok(Value::Object(Default::default()))
        } else {
            Ok(sparewall_config::to_value(&self.store.document(id)?))
        }
    }

    /// Bring the system in line with the stored state at startup. A change
    /// still waiting for confirmation when the node went down is reverted.
    /// With `early`, only files are installed and nft loaded (before udev
    /// and networkd start).
    pub fn boot(&mut self, early: bool) -> Result<u64, Error> {
        let mut state = self.store.state()?;
        if let Some(p) = state.pending.take() {
            tracing::warn!(
                pending = p.id,
                revert_to = p.revert_to,
                "unconfirmed generation at boot; reverting"
            );
            self.events.push(Event::RolledBack {
                to: p.revert_to,
                from: p.id,
                reason: "unconfirmed at boot".into(),
            });
            state.active = p.revert_to;
            self.store.set_state(&state)?;
        }
        if state.active != 0 && !self.store.exists(state.active) {
            tracing::error!(
                id = state.active,
                "active generation missing; using bootstrap"
            );
            state.active = 0;
            state.confirmed = 0;
            self.store.set_state(&state)?;
        }
        // Re-render with this image's renderers: an upgraded image may
        // render the same document differently.
        if state.active != 0 {
            let doc = self.store.document(state.active)?;
            match sparewall_render::render(&doc, self.node()) {
                Ok(r) => {
                    if self.store.rendered(state.active).ok().as_ref() != Some(&r) {
                        tracing::info!(id = state.active, "renderers changed; re-rendering");
                        self.store.set_rendered(state.active, &r)?;
                    }
                }
                Err(e) => tracing::error!(error = %e, "cannot re-render active generation"),
            }
        }
        self.activate(state.active, None, early)?;
        Ok(state.active)
    }

    /// Parse and check a document for this node.
    pub fn check(&self, value: Value) -> Result<(Document, Vec<String>, Rendered), Error> {
        let doc = sparewall_config::from_value(value)
            .map_err(|e| Error::Validation(vec![e.to_string()]))?;
        let issues = validate(&doc);
        let errors = validate::errors(&issues);
        if !errors.is_empty() {
            return Err(Error::Validation(errors));
        }
        if !doc.cluster.nodes.iter().any(|n| n == self.node()) {
            return Err(Error::Validation(vec![format!(
                "cluster.nodes: this node ({}) is not listed",
                self.node()
            )]));
        }
        let rendered = sparewall_render::render(&doc, self.node())
            .map_err(|e| Error::Validation(vec![e.to_string()]))?;
        Ok((doc, validate::warnings(&issues), rendered))
    }

    /// Validate only: schema, semantics, rendering and the nft dry run.
    pub fn validate(&mut self, value: Value) -> Result<Vec<String>, Error> {
        let (_, warnings, rendered) = self.check(value)?;
        let active = self.rendered_for(self.active()?)?;
        self.dry_run(&rendered, Some(&active))?;
        Ok(warnings)
    }

    /// Check every artifact with its own checker: nft, and each provider
    /// whose files differ from `old`.
    fn dry_run(&mut self, r: &Rendered, old: Option<&Rendered>) -> Result<(), Error> {
        let body = r
            .files
            .get(&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT))
            .ok_or_else(|| Error::Internal("no nft script rendered".into()))?;
        self.sys.nft_check(body, &r.meta.preserved_sets)?;
        for svc in r.meta.services.values() {
            let changed =
                old.is_none_or(|o| o.subsystem(svc.subsystem) != r.subsystem(svc.subsystem));
            if let (true, Some(spec)) = (changed, &svc.check) {
                self.sys
                    .service_check(spec, &subsystem_files(r, svc.subsystem))
                    .map_err(|e| Error::Check(format!("{}: {e}", svc.provider)))?;
            }
        }
        Ok(())
    }

    fn check_base(&self, base: u64) -> Result<State, Error> {
        let state = self.store.state()?;
        if base != state.active {
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        Ok(state)
    }

    /// Replace the whole document.
    pub fn apply(&mut self, value: Value, opts: &ApplyOptions) -> Result<ApplyResult, Error> {
        let state = self.check_base(opts.base)?;
        let (doc, warnings, rendered) = self.check(value)?;
        let hash = sparewall_config::hash(&doc);
        let active_gen = self.generation(state.active)?;
        let old_value = self.document_value(state.active)?;
        let new_value = sparewall_config::to_value(&doc);
        let diff = sparewall_config::diff_summary(&old_value, &new_value);
        let old_rendered = self.rendered_for(state.active)?;
        let changed: Vec<String> = old_rendered
            .changed(&rendered)
            .iter()
            .map(|s| s.dir().to_string())
            .collect();

        if hash == active_gen.hash && state.pending.is_none() {
            return Ok(ApplyResult {
                generation: active_gen,
                changed: vec![],
                diff: vec![],
                warnings,
                unchanged: true,
                dry_run: opts.dry_run,
            });
        }
        self.dry_run(&rendered, Some(&old_rendered))?;

        let mut summary = diff.clone();
        summary.truncate(200);
        let g = Generation {
            id: self.store.next_id()?.max(state.active + 1),
            hash: hash.clone(),
            base: Some(state.active),
            schema: doc.schema,
            author: opts.author.clone(),
            created: jiff::Timestamp::now().to_string(),
            summary,
        };
        if opts.dry_run {
            return Ok(ApplyResult {
                generation: g,
                changed,
                diff,
                warnings,
                unchanged: false,
                dry_run: true,
            });
        }

        self.store.save(&g, &doc, &rendered)?;
        if let Err(e) = self.activate(g.id, Some(&old_rendered), false) {
            tracing::error!(id = g.id, error = %e, "activation failed; restoring previous generation");
            self.events.push(Event::ApplyFailed {
                id: g.id,
                error: e.to_string(),
            });
            if let Err(e2) = self.activate(state.active, Some(&rendered), false) {
                tracing::error!(error = %e2, "restoring the previous generation also failed");
            }
            return Err(e);
        }

        let mut new_state = state.clone();
        new_state.active = g.id;
        let window = opts.confirm_seconds.unwrap_or(0);
        if window > 0 {
            let revert_to = state
                .pending
                .as_ref()
                .map_or(state.confirmed, |p| p.revert_to);
            new_state.pending = Some(Pending {
                id: g.id,
                revert_to,
                deadline: now_unix() + i64::from(window),
            });
        } else {
            new_state.confirmed = g.id;
            new_state.pending = None;
        }
        self.store.set_state(&new_state)?;
        let protect: Vec<u64> = [new_state.active, new_state.confirmed]
            .into_iter()
            .chain(new_state.pending.as_ref().map(|p| p.revert_to))
            .collect();
        self.store.prune(self.keep, &protect)?;
        tracing::info!(
            id = g.id,
            hash = %g.hash,
            author = %g.author,
            changed = ?changed,
            "applied generation"
        );
        self.events.push(Event::Applied {
            id: g.id,
            hash,
            author: g.author.clone(),
            pending: window > 0,
        });
        Ok(ApplyResult {
            generation: g,
            changed,
            diff,
            warnings,
            unchanged: false,
            dry_run: false,
        })
    }

    /// Merge a partial document (RFC 7386) into the active one.
    pub fn merge(&mut self, patch: &Value, opts: &ApplyOptions) -> Result<ApplyResult, Error> {
        let state = self.check_base(opts.base)?;
        let mut v = self.document_value(state.active)?;
        sparewall_config::merge_patch(&mut v, patch);
        self.apply(v, opts)
    }

    /// Apply RFC 6902 operations to the active document.
    pub fn patch(&mut self, ops: &Value, opts: &ApplyOptions) -> Result<ApplyResult, Error> {
        let state = self.check_base(opts.base)?;
        let mut v = self.document_value(state.active)?;
        sparewall_config::json_patch(&mut v, ops)
            .map_err(|e| Error::Validation(vec![e.to_string()]))?;
        self.apply(v, opts)
    }

    /// Confirm a pending generation.
    pub fn confirm(&mut self, id: u64) -> Result<(), Error> {
        let mut state = self.store.state()?;
        match &state.pending {
            Some(p) if p.id == id => {
                state.confirmed = id;
                state.pending = None;
                self.store.set_state(&state)?;
                tracing::info!(id, "confirmed generation");
                self.events.push(Event::Confirmed { id });
                Ok(())
            }
            None if state.active == id => Ok(()),
            _ => Err(Error::NotPending(id)),
        }
    }

    /// Revert an expired pending generation. Returns the generation it
    /// returned to.
    pub fn tick(&mut self, now: i64) -> Result<Option<u64>, Error> {
        let state = self.store.state()?;
        let Some(p) = state.pending.clone() else {
            return Ok(None);
        };
        if now < p.deadline {
            return Ok(None);
        }
        tracing::warn!(
            id = p.id,
            revert_to = p.revert_to,
            "confirm window expired; reverting"
        );
        let from = state.active;
        self.switch_to(p.revert_to, "confirm window expired")?;
        self.events.push(Event::RolledBack {
            to: p.revert_to,
            from,
            reason: "confirm window expired".into(),
        });
        Ok(Some(p.revert_to))
    }

    /// Seconds until the pending window closes.
    pub fn pending_remaining(&self) -> Result<Option<(u64, i64)>, Error> {
        Ok(self
            .store
            .state()?
            .pending
            .map(|p| (p.id, (p.deadline - now_unix()).max(0))))
    }

    /// Return to a generation: the given one, or by default the pending
    /// change's revert target or the active generation's base.
    pub fn rollback(&mut self, id: Option<u64>) -> Result<Generation, Error> {
        let state = self.store.state()?;
        let target = match id {
            Some(t) => t,
            None => match &state.pending {
                Some(p) => p.revert_to,
                None => self.generation(state.active)?.base.unwrap_or(0),
            },
        };
        if target != 0 && !self.store.exists(target) {
            return Err(Error::NotFound(target));
        }
        let from = state.active;
        self.switch_to(target, "rollback")?;
        self.events.push(Event::RolledBack {
            to: target,
            from,
            reason: "rollback".into(),
        });
        self.generation(target)
    }

    fn switch_to(&mut self, target: u64, why: &str) -> Result<(), Error> {
        let old = self.rendered_for(self.store.state()?.active)?;
        self.switch_from(&old, target, why)
    }

    /// Switch to `target`, reloading what differs from `old`.
    fn switch_from(&mut self, old: &Rendered, target: u64, why: &str) -> Result<(), Error> {
        let state = self.store.state()?;
        self.activate(target, Some(old), false)?;
        let new_state = State {
            active: target,
            confirmed: target,
            pending: None,
        };
        self.store.set_state(&new_state)?;
        tracing::info!(to = target, from = state.active, why, "switched generation");
        Ok(())
    }

    /// The chain of `(id, hash)` from the active generation back through
    /// each `base`, newest first (bootstrap, id 0, last).
    pub fn lineage(&self) -> Result<Vec<(u64, String)>, Error> {
        let mut out = Vec::new();
        let mut id = Some(self.active()?);
        while let Some(i) = id {
            if i == 0 || !self.store.exists(i) {
                break;
            }
            let g = self.store.meta(i)?;
            out.push((g.id, g.hash.clone()));
            id = g.base;
            if out.len() > 10_000 {
                break;
            }
        }
        out.push((0, String::new()));
        Ok(out)
    }

    /// What this node reports to its peer.
    pub fn view(&self) -> Result<crate::pair::NodeView, Error> {
        let state = self.store.state()?;
        Ok(crate::pair::NodeView {
            node: self.node().to_string(),
            active: state.active,
            desired: self.generation(state.active)?.hash,
            applied: self.applied_hash.clone(),
            lineage: self.lineage()?,
            applying: false,
        })
    }

    /// Accept a generation pushed by the peer. It keeps the peer's id and
    /// is refused unless its `base` is this node's active generation, so a
    /// push never overwrites a change this node has not seen.
    pub fn receive(&mut self, g: &Generation, value: Value) -> Result<(), Error> {
        let state = self.store.state()?;
        if self.store.exists(g.id) {
            let have = self.store.meta(g.id)?;
            if have.hash == g.hash {
                if state.active != g.id {
                    self.switch_to(g.id, "peer push")?;
                }
                return Ok(());
            }
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        if state.pending.is_some() || g.base != Some(state.active) {
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        self.install_foreign(g, value, "peer push")
    }

    /// Take the peer's generation regardless of history (`sync --from`).
    /// A local generation with the same id but other content is set aside.
    pub fn adopt(&mut self, g: &Generation, value: Value) -> Result<(), Error> {
        if self.store.exists(g.id) {
            let have = self.store.meta(g.id)?;
            if have.hash == g.hash {
                return self.switch_to(g.id, "sync");
            }
        }
        self.install_foreign(g, value, "sync")
    }

    fn install_foreign(&mut self, g: &Generation, value: Value, why: &str) -> Result<(), Error> {
        let (doc, _, rendered) = self.check(value)?;
        if sparewall_config::hash(&doc) != g.hash {
            return Err(Error::Validation(vec![format!(
                "generation {} does not match its hash",
                g.id
            )]));
        }
        let from = self.active()?;
        let old_rendered = self.rendered_for(from)?;
        self.dry_run(&rendered, Some(&old_rendered))?;
        if self.store.exists(g.id) {
            // Only `adopt` gets here: keep the diverged generation aside.
            let to = self.store.set_aside(g.id)?;
            tracing::warn!(id = g.id, kept = %to.display(), "set aside a diverged generation");
        }
        self.store.save(g, &doc, &rendered)?;
        self.switch_from(&old_rendered, g.id, why)?;
        self.events.push(Event::Applied {
            id: g.id,
            hash: g.hash.clone(),
            author: g.author.clone(),
            pending: false,
        });
        tracing::info!(id = g.id, from, why, "installed the peer's generation");
        Ok(())
    }

    /// Generations, newest first.
    pub fn history(&self, limit: Option<usize>) -> Result<Vec<Generation>, Error> {
        let mut ids = self.store.ids()?;
        ids.reverse();
        if let Some(l) = limit {
            ids.truncate(l);
        }
        ids.into_iter().map(|id| self.store.meta(id)).collect()
    }

    /// Install a generation's rendered files and reload what changed.
    fn activate(&mut self, id: u64, old: Option<&Rendered>, early: bool) -> Result<(), Error> {
        let t0 = Instant::now();
        let r = self.rendered_for(id)?;
        let files = subsystem_files;
        let changed = |s: Subsystem| old.is_none_or(|o| o.subsystem(s) != r.subsystem(s));
        let changed_list: Vec<Subsystem> = Subsystem::all()
            .iter()
            .copied()
            .filter(|s| changed(*s))
            .collect();
        let result = (|| -> Result<(), Error> {
            // Firewall first, so new interfaces are covered as they appear.
            let mut new_sets = Vec::new();
            if changed(Subsystem::Nft) || old.is_none() {
                let body = r
                    .files
                    .get(&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT))
                    .ok_or_else(|| Error::Internal("no nft script".into()))?;
                new_sets = self.sys.nft_load(body, &r.meta.preserved_sets)?;
            }
            let sysctl = r
                .subsystem(Subsystem::Sysctl)
                .values()
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            if changed(Subsystem::Sysctl) || old.is_none() {
                self.sys.sysctl_apply(&sysctl)?;
            }
            if changed(Subsystem::Networkd) || old.is_none() {
                let old_net = old
                    .map(|o| files(o, Subsystem::Networkd))
                    .unwrap_or_default();
                self.sys
                    .networkd_apply(&old_net, &files(&r, Subsystem::Networkd), early)?;
                if !early {
                    // Interface-specific keys for links that just appeared.
                    self.sys.sysctl_apply(&sysctl)?;
                }
            }
            for sub in PROVIDER_SUBSYSTEMS {
                if changed(*sub) {
                    self.sys.install_files(*sub, &files(&r, *sub))?;
                }
            }
            if !early {
                let links: Vec<String> = new_sets
                    .iter()
                    .filter_map(|s| r.meta.set_links.get(s).cloned())
                    .collect();
                if !links.is_empty() {
                    self.sys.networkd_reconfigure(&links)?;
                }
                self.sys.services_apply(&r.meta, &changed_list)?;
            }
            Ok(())
        })();
        match &result {
            Ok(()) => {
                self.applied_hash = Some(self.generation(id)?.hash);
                self.last_error = None;
            }
            Err(e) => {
                self.applied_hash = None;
                self.last_error = Some(e.to_string());
            }
        }
        self.last_apply_ms = Some(t0.elapsed().as_millis());
        result
    }

    pub fn last_apply_ms(&self) -> Option<u128> {
        self.last_apply_ms
    }

    /// The one health model (design: "Health endpoints").
    pub fn health(&mut self) -> Result<Health, Error> {
        let state = self.store.state()?;
        let desired = self.generation(state.active)?;
        let r = self.rendered_for(state.active)?;
        let mut checks = Vec::new();

        checks.push(if state.active == 0 {
            Check::new(
                "generation",
                Level::Degraded,
                "bootstrap mode: no configuration applied",
            )
        } else {
            Check::new(
                "generation",
                Level::Ok,
                format!("generation {}", state.active),
            )
        });

        if let Some(p) = &state.pending {
            checks.push(Check::new(
                "confirm",
                Level::Degraded,
                format!(
                    "generation {} reverts in {}s unless confirmed",
                    p.id,
                    (p.deadline - now_unix()).max(0)
                ),
            ));
        }

        checks.push(match (&self.applied_hash, &self.last_error) {
            (_, Some(e)) => Check::new("applied", Level::Failed, format!("last apply failed: {e}")),
            (Some(h), None) if *h == desired.hash => {
                Check::new("applied", Level::Ok, "running the desired configuration")
            }
            _ => Check::new(
                "applied",
                Level::Failed,
                "running configuration differs from the desired one",
            ),
        });

        let expected_chains: Vec<String> = r
            .files
            .get(&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT))
            .map(|b| {
                b.lines()
                    .filter_map(|l| l.trim().strip_prefix("chain "))
                    .map(|l| l.trim_end_matches(" {").to_string())
                    .collect()
            })
            .unwrap_or_default();
        checks.push(match self.sys.nft_chains() {
            Ok(Some(live)) => {
                let missing: Vec<&String> = expected_chains
                    .iter()
                    .filter(|c| !live.contains(c))
                    .collect();
                if missing.is_empty() {
                    Check::new("nft", Level::Ok, format!("{} chains loaded", live.len()))
                } else {
                    Check::new("nft", Level::Failed, format!("missing chains: {missing:?}"))
                }
            }
            Ok(None) => Check::new("nft", Level::Failed, "table inet sparewall is not loaded"),
            Err(e) => Check::new("nft", Level::Failed, format!("cannot read ruleset: {e}")),
        });

        let states = self.sys.link_states();
        let mut down = Vec::new();
        for l in &r.meta.required_links {
            match states.get(l).map(String::as_str) {
                Some("up" | "unknown") => {}
                Some(s) => down.push(format!("{l} is {s}")),
                None => down.push(format!("{l} is missing")),
            }
        }
        checks.push(if down.is_empty() {
            Check::new(
                "links",
                Level::Ok,
                format!("{} required links up", r.meta.required_links.len()),
            )
        } else {
            Check::new("links", Level::Failed, down.join(", "))
        });

        let units: Vec<String> = r.meta.services.values().map(|s| s.unit.clone()).collect();
        if !units.is_empty() {
            let states = self.sys.unit_states(&units);
            let bad: Vec<String> = states
                .iter()
                .filter(|(_, st)| st.as_str() != "active")
                .map(|(u, st)| format!("{u} is {st}"))
                .collect();
            checks.push(if bad.is_empty() {
                Check::new(
                    "services",
                    Level::Ok,
                    format!("{} services running", units.len()),
                )
            } else {
                Check::new("services", Level::Failed, bad.join(", "))
            });
        }

        Ok(Health::from_checks(checks))
    }

    /// Desired and applied configuration hashes.
    pub fn hashes(&self) -> Result<(String, Option<String>), Error> {
        let state = self.store.state()?;
        Ok((
            self.generation(state.active)?.hash,
            self.applied_hash.clone(),
        ))
    }
}
