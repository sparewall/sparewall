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
use crate::store::{LinkDecision, WriteFailure};
use crate::system::{Files, System};
use crate::tokens::Role;

/// Subsystems whose files a provider service reads from /run/sparewall.
const PROVIDER_SUBSYSTEMS: &[Subsystem] = &[
    Subsystem::Dhcp,
    Subsystem::Dns,
    Subsystem::Ntp,
    Subsystem::Keepalived,
    Subsystem::Conntrackd,
    Subsystem::Logging,
    Subsystem::Ssh,
];

fn subsystem_files(r: &Rendered, s: Subsystem) -> Files {
    r.subsystem(s)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Generations kept on disk.
pub const DEFAULT_KEEP: usize = 50;

/// Options common to every mutation.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// The generation the change was derived from.
    pub base: u64,
    /// Revert unless confirmed within this many seconds (`None` or 0:
    /// confirmed at once).
    pub confirm_seconds: Option<u32>,
    pub author: String,
    /// Validate, render and check only.
    pub dry_run: bool,
    /// A line put before the diff in the generation's summary.
    pub note: Option<String>,
    /// In a pair, store a change that alters the sync link without
    /// running it ([`ApplyResult::staged`]): it must reach the peer first,
    /// through the link it changes ([`Coordinator::activate_staged`]).
    pub stage_sync_link: bool,
    /// The role of a caller on the restricted socket; `None` for root.
    pub role: Option<Role>,
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
    /// Stored but not run: it changes the sync link (see
    /// [`ApplyOptions::stage_sync_link`]).
    pub staged: bool,
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

/// How long a generation pushed by the peer may run before the peer
/// confirms it.
pub const PEER_CONFIRM_SECONDS: i64 = 120;

/// How a generation received from the peer is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerGate {
    /// Confirmed as soon as it runs: an older peer, which never confirms,
    /// or a generation this node fetched itself (`sync --from <peer>`).
    Immediate,
    /// Pending until the peer confirms it over the sync tunnel, within
    /// [`PEER_CONFIRM_SECONDS`]; reverted (and rejected) otherwise.
    PeerConfirms,
}

/// What health compares the live firewall with.
#[derive(Debug, Clone, Default)]
enum NftBaseline {
    /// Nothing loaded by this process yet.
    #[default]
    None,
    /// The live table as listed right after the last load.
    Recorded(crate::nft_state::Components),
    /// Loaded, but not read back: unverifiable until the next load. Never
    /// learned later from the live table, which may have drifted by then.
    Unverified(String),
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
    /// Checks the daemon contributes (pair sync, TLS), by source.
    extra_checks: std::collections::BTreeMap<String, Vec<Check>>,
    /// The live table as it was right after the last load (normalized),
    /// which health compares with the table as it is now.
    nft_loaded: NftBaseline,
    /// The state record may say a sync-link change was kept, but writing
    /// it did not complete: until it is known to be on disk, the peer is
    /// told the decision is still pending.
    decision_unsure: bool,
    /// The generations this release cannot read, and why (#169): the
    /// active one, and the one an in-doubt sync-link change runs in its
    /// place. Boot runs the bootstrap configuration instead of either,
    /// which keeps the management network and SSH up, and health reports
    /// it failed. Kept for the process's life: a revert to one, at the end
    /// of a confirm window, runs the bootstrap configuration again.
    unreadable: std::collections::BTreeMap<u64, String>,
}

/// How much longer than the peer this node waits for the peer to
/// confirm a sync-link change, so that it sees the peer's outcome before
/// its own deadline: never kept here while the peer reverted.
pub const SYNC_LINK_MARGIN_SECONDS: i64 = 30;

/// Whether a document pairs two nodes over a sync tunnel.
fn paired(doc: &Value) -> bool {
    let c = &doc["cluster"];
    c["nodes"].as_array().is_some_and(|n| n.len() > 1)
        && c["sync_network"].is_string()
        && c["nodes"].as_array().is_some_and(|n| {
            n.iter()
                .all(|n| n.as_str().is_some_and(|n| c["sync_keys"].get(n).is_some()))
        })
}

/// What the sync tunnel depends on: the cluster's nodes and sync
/// settings, the sync network, and each node's port carrying it.
fn sync_link(doc: &Value) -> Value {
    let c = &doc["cluster"];
    let network = c["sync_network"]
        .as_str()
        .map_or(Value::Null, |n| doc["networks"][n].clone());
    let ports: serde_json::Map<String, Value> = match network["port"].as_str() {
        Some(p) => c["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|n| (n.to_string(), doc["ports"][n][p].clone()))
            .collect(),
        None => Default::default(),
    };
    serde_json::json!({
        "nodes": c["nodes"],
        "sync_network": c["sync_network"],
        "sync_port": c["sync_port"],
        "sync_keys": c["sync_keys"],
        "network": network,
        "ports": ports,
    })
}

/// The document without what [`sync_link`] covers (in `also`'s terms
/// too, for a sync network or port that was renamed).
fn without_sync_link(doc: &Value, also: &Value) -> Value {
    let mut d = doc.clone();
    for c in [doc, also] {
        let net = c["cluster"]["sync_network"].as_str();
        let port = net.and_then(|n| c["networks"][n]["port"].as_str());
        if let Some(n) = net
            && let Some(m) = d["networks"].as_object_mut()
        {
            m.remove(n);
        }
        if let (Some(p), Some(nodes)) = (port, d["ports"].as_object_mut()) {
            for ports in nodes.values_mut() {
                if let Some(m) = ports.as_object_mut() {
                    m.remove(p);
                }
            }
        }
    }
    if let Some(m) = d["cluster"].as_object_mut() {
        for k in ["nodes", "sync_network", "sync_port", "sync_keys"] {
            m.remove(k);
        }
    }
    d
}

/// Whether a pair's document changes the sync link from `old` to `new`.
fn link_change(old: &Value, new: &Value) -> bool {
    paired(old) && sync_link(old) != sync_link(new)
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
            extra_checks: Default::default(),
            nft_loaded: NftBaseline::None,
            decision_unsure: false,
            unreadable: Default::default(),
        }
    }

    /// The generation that runs for `id`: the bootstrap configuration in
    /// place of one this release cannot read.
    pub(crate) fn runs(&self, id: u64) -> u64 {
        if self.unreadable.contains_key(&id) {
            0
        } else {
            id
        }
    }

    /// Refuse a partial change to a generation this release cannot read:
    /// there is no document to change. A whole document, or a rollback,
    /// replaces it.
    fn readable_base(&self, id: u64) -> Result<(), Error> {
        match self.unreadable.get(&id) {
            Some(e) => Err(Error::Validation(vec![format!(
                "generation {id} cannot be read ({e}): apply a whole document \
                 (sparewall apply -f) or roll back to a generation this release can read"
            )])),
            None => Ok(()),
        }
    }

    /// The generations this release could not read at boot, and why.
    pub fn unreadable(&self) -> impl Iterator<Item = (u64, &str)> {
        self.unreadable.iter().map(|(id, e)| (*id, e.as_str()))
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

    /// Make the node name the hostname, so that shell prompts and the
    /// journal tell the nodes apart.
    pub fn apply_hostname(&mut self) -> Result<(), Error> {
        let node = self.node().to_string();
        if self.system().set_hostname(&node)? {
            tracing::info!(hostname = %node, "set the hostname");
        }
        Ok(())
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
        let id = self.runs(id);
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
        // A restart is no proof that a failed sync of the state record
        // completed: sync it before telling the peer any decision.
        if let Err(e) = self.store.sync_state() {
            tracing::error!(error = %e, "cannot sync the state record; withholding decisions");
            self.decision_unsure = true;
        }
        let mut state = self.store.state()?;
        if state.pending.as_ref().is_some_and(|p| p.prepared) {
            // In doubt: kept until the peer's decision is known.
            tracing::warn!(
                id = state.active,
                live = self.live_id(&state),
                "a sync-link change is in doubt at boot"
            );
        } else if let Some(p) = state.pending.take() {
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
            let mut with = state.clone();
            with.pending = Some(p.clone());
            state.link_decision = self.decision(&with, false)?;
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
        // What runs: the active generation, or the one before an in-doubt
        // sync-link change while it looks for the peer on the old link.
        let live = self.live_id(&state);
        // Re-render with this image's renderers: an upgraded image may
        // render the same document differently.
        let mut ids = vec![state.active, live];
        ids.dedup();
        ids.retain(|&i| i != 0);
        // A document this release cannot read (a newer release's, after a
        // rollback of the image, or a damaged file) must not stop the node
        // from booting: that would leave even the management network down.
        // Run the bootstrap configuration instead, and say why in health.
        self.unreadable.clear();
        for &id in &ids {
            if let Err(e) = self.store.document(id) {
                tracing::error!(
                    id,
                    error = %e,
                    "cannot read the generation; running the bootstrap configuration"
                );
                self.unreadable.insert(id, e.to_string());
            }
        }
        for id in ids.into_iter().filter(|i| !self.unreadable.contains_key(i)) {
            let doc = self.store.document(id)?;
            match sparewall_render::render(&doc, self.node()) {
                Ok(r) => {
                    if self.store.rendered(id).ok().as_ref() != Some(&r) {
                        tracing::info!(id, "renderers changed; re-rendering");
                        self.store.set_rendered(id, &r)?;
                    }
                }
                Err(e) => tracing::error!(id, error = %e, "cannot re-render a generation"),
            }
        }
        if let Ok(Some(doc)) = self.live_document()
            && let Err(e) = self.install_vpn_keys(&doc)
        {
            tracing::error!(error = %e, "cannot install remote-access keys");
        }
        self.activate(live, None, early)?;
        Ok(state.active)
    }

    /// Parse and check a document for this node, to run it.
    pub fn check(&self, value: Value) -> Result<(Document, Vec<String>, Rendered), Error> {
        self.check_with(value, validate)
    }

    /// Parse and check a document only to keep it in history: settings
    /// earlier versions accepted and this one no longer runs are allowed,
    /// since it will not run unless checked again.
    fn check_history(&self, value: Value) -> Result<(Document, Vec<String>, Rendered), Error> {
        self.check_with(value, validate::validate_history)
    }

    fn check_with(
        &self,
        value: Value,
        validate: fn(&Document) -> Vec<validate::Issue>,
    ) -> Result<(Document, Vec<String>, Rendered), Error> {
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
        self.link_change_in_progress(&state)?;
        let (doc, mut warnings, rendered) = self.check(value)?;
        self.check_anti_lockout(&doc, opts.role)?;
        if let Some(old) = self.active_document()? {
            warnings.extend(sparewall_config::providers::switch_warnings(&old, &doc));
        }
        warnings.extend(missing_psk_messages(&self.missing_vpn_psks(&doc)?));
        let hash = sparewall_config::hash(&doc);
        let active_gen = self.generation(state.active)?;
        let old_value = self.document_value(self.runs(state.active))?;
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
                staged: false,
            });
        }
        self.dry_run(&rendered, Some(&old_rendered))?;

        let mut summary: Vec<String> = opts.note.iter().cloned().chain(diff.clone()).collect();
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
                staged: false,
            });
        }

        self.ensure_vpn_keys(&doc)?;
        if opts.stage_sync_link && link_change(&old_value, &new_value) {
            if let Some(p) = &state.pending {
                return Err(Error::Validation(vec![format!(
                    "the sync link cannot change while generation {} is pending; confirm it or roll it back first",
                    p.id
                )]));
            }
            if without_sync_link(&old_value, &new_value)
                != without_sync_link(&new_value, &old_value)
            {
                return Err(Error::Validation(vec![
                    "a change to the sync link must change nothing else (the peer may switch \
                     between the old and new link until it learns the outcome): make the \
                     other changes separately"
                        .into(),
                ]));
            }
            self.store.save(&g, &doc, &rendered)?;
            tracing::info!(
                id = g.id,
                "stored a change to the sync link; the peer takes it first"
            );
            return Ok(ApplyResult {
                generation: g,
                changed,
                diff,
                warnings,
                unchanged: false,
                dry_run: false,
                staged: true,
            });
        }
        self.install_vpn_keys(&doc)?;
        self.store.save(&g, &doc, &rendered)?;
        if let Err(e) = self.activate(g.id, Some(&old_rendered), false) {
            return Err(self.undo_apply(g.id, &rendered, state.active, e));
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
                ..Default::default()
            });
        } else {
            new_state.confirmed = g.id;
            new_state.pending = None;
        }
        if let Err(f) = self.store.try_set_state(&new_state) {
            let (e, unreferenced) = self.reconcile_commit(g.id, &rendered, &state, f);
            if unreferenced {
                self.set_aside_failed(g.id);
            }
            return Err(e);
        }
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
            staged: false,
        })
    }

    /// Undo generation `id` after it failed to activate, or ran but could
    /// not be recorded in `state.json`: activate `to` again, against what
    /// `id` may have changed, and report the failure. Returns `e`.
    fn restore(&mut self, id: u64, new: &Rendered, to: u64, e: Error) -> Error {
        tracing::error!(id, error = %e, "applying failed; restoring generation {to}");
        self.events.push(Event::ApplyFailed {
            id,
            error: e.to_string(),
        });
        if let Err(e2) = self.activate(to, Some(new), false) {
            tracing::error!(error = %e2, "restoring the previous generation also failed");
        }
        e
    }

    /// [`Self::restore`] for a local change, which then never ran: keep it
    /// out of history and free its id.
    fn undo_apply(&mut self, id: u64, new: &Rendered, to: u64, e: Error) -> Error {
        let e = self.restore(id, new, to, e);
        self.set_aside_failed(id);
        e
    }

    fn set_aside_failed(&mut self, id: u64) {
        match self.store.set_aside(id, "failed") {
            Ok(to) => tracing::info!(id, kept = %to.display(), "set aside the failed generation"),
            Err(e2) => tracing::error!(id, error = %e2, "cannot set aside the failed generation"),
        }
    }

    /// Writing the state record that makes `id` active failed after `id`
    /// was activated. Before the rename, the previous record stands:
    /// restore what it names, and `id` was never referenced. After it
    /// (syncing the directory failed), the new record is visible and may
    /// or may not reach the disk: record `prev` again, then run what the
    /// visible record names. Returns the error, and whether `id` is
    /// unreferenced, so it may be set aside or rejected: not while a
    /// record naming it may still reach the disk.
    fn reconcile_commit(
        &mut self,
        id: u64,
        new: &Rendered,
        prev: &State,
        failure: WriteFailure<Error>,
    ) -> (Error, bool) {
        let e = failure.error;
        if !failure.replaced {
            return (self.restore(id, new, prev.active, e), true);
        }
        let recorded = match self.store.set_state(prev) {
            Ok(()) => true,
            Err(e2) => {
                tracing::error!(id, error = %e2, "cannot record the previous state again");
                false
            }
        };
        // Run what the readable record names: the previous generation,
        // or `id` itself if the record naming it could not be replaced
        // (its confirm window or the peer's confirmation still applies).
        match self.store.state() {
            Ok(v) => (self.restore(id, new, v.active, e), recorded),
            Err(e2) => {
                tracing::error!(error = %e2, "cannot read the state record back");
                (self.restore(id, new, prev.active, e), false)
            }
        }
    }

    /// Merge a partial document (RFC 7386) into the active one.
    pub fn merge(&mut self, patch: &Value, opts: &ApplyOptions) -> Result<ApplyResult, Error> {
        let state = self.check_base(opts.base)?;
        self.readable_base(state.active)?;
        let mut v = self.document_value(state.active)?;
        sparewall_config::merge_patch(&mut v, patch);
        self.apply(v, opts)
    }

    /// Apply RFC 6902 operations to the active document.
    pub fn patch(&mut self, ops: &Value, opts: &ApplyOptions) -> Result<ApplyResult, Error> {
        let state = self.check_base(opts.base)?;
        self.readable_base(state.active)?;
        let mut v = self.document_value(state.active)?;
        sparewall_config::json_patch(&mut v, ops)
            .map_err(|e| Error::Validation(vec![e.to_string()]))?;
        self.apply(v, opts)
    }

    /// Run a change to the sync link that [`Self::apply`] stored
    /// ([`ApplyResult::staged`]) once the peer runs it, pushed through the
    /// current link. It runs pending until the peer confirms it over the
    /// new link ([`Self::peer_confirmed`]) and, with an `admin_window`,
    /// the admin confirms it too; otherwise it reverts at the deadline,
    /// which outlasts the peer's own so that both end on the same link.
    pub fn activate_staged(&mut self, id: u64, admin_window: u32) -> Result<(), Error> {
        let state = self.store.state()?;
        let g = self.generation(id)?;
        if state.pending.is_some() || g.base != Some(state.active) {
            self.discard_staged(id)?;
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        let doc = self.store.document(id)?;
        let rendered = self.rendered_for(id)?;
        let old = self.rendered_for(state.active)?;
        self.install_vpn_keys(&doc)?;
        if let Err(e) = self.activate(id, Some(&old), false) {
            return Err(self.undo_apply(id, &rendered, state.active, e));
        }
        let mut new_state = state.clone();
        new_state.active = id;
        new_state.pending = Some(Pending {
            id,
            revert_to: state.confirmed,
            deadline: now_unix()
                + i64::from(admin_window).max(PEER_CONFIRM_SECONDS + SYNC_LINK_MARGIN_SECONDS),
            peer_gate: true,
            needs_admin: admin_window > 0,
            decides_link: true,
            ..Default::default()
        });
        if let Err(f) = self.store.try_set_state(&new_state) {
            let (e, unreferenced) = self.reconcile_commit(id, &rendered, &state, f);
            if unreferenced {
                self.set_aside_failed(id);
            }
            return Err(e);
        }
        tracing::info!(id, "running the sync-link change; waiting for the peer");
        self.events.push(Event::Applied {
            id,
            hash: g.hash,
            author: g.author,
            pending: true,
        });
        Ok(())
    }

    /// Drop a staged change the peer did not take; it never ran here.
    pub fn discard_staged(&mut self, id: u64) -> Result<(), Error> {
        let st = self.store.state()?;
        let named = id == st.active
            || id == st.confirmed
            || st.pending.as_ref().is_some_and(|p| p.revert_to == id);
        if !named && self.store.exists(id) {
            let to = self.store.set_aside(id, "unsent")?;
            tracing::info!(id, kept = %to.display(), "set aside a sync-link change the peer did not take");
        }
        Ok(())
    }

    /// The peer confirmed a sync-link change over the new link. It is
    /// kept, unless the admin's confirmation is still awaited.
    pub fn peer_confirmed(&mut self, id: u64) -> Result<(), Error> {
        let mut state = self.store.state()?;
        // Also once the peer's part is done: a decision whose recording
        // failed is retried this way.
        let Some(p) = state
            .pending
            .as_mut()
            .filter(|p| p.id == id && p.decides_link)
        else {
            return Ok(());
        };
        if !p.peer_gate && p.needs_admin {
            return Ok(());
        }
        p.peer_gate = false;
        if p.needs_admin {
            self.store.set_state(&state)?;
            tracing::info!(
                id,
                "the peer confirmed the sync-link change; waiting for the admin"
            );
            return Ok(());
        }
        self.finish_confirm(state, id)
    }

    /// The generation whose configuration runs: the active one, or while
    /// an in-doubt sync-link change looks for the peer on the old link,
    /// the one it would revert to.
    fn live_id(&self, state: &State) -> u64 {
        match &state.pending {
            Some(p) if p.prepared && p.trying_old => p.revert_to,
            _ => state.active,
        }
    }

    /// The document whose configuration runs (see [`Self::live_id`]): the
    /// one the sync tunnel is set up from.
    pub fn live_document(&self) -> Result<Option<Document>, Error> {
        let id = self.runs(self.live_id(&self.store.state()?));
        if id == 0 {
            return Ok(None);
        }
        Ok(Some(self.store.document(id)?))
    }

    /// Refuse an ordinary change while a sync-link change is in progress:
    /// this node's, waiting for the peer and the admin (they confirm or
    /// roll it back), or the peer's, which only the peer decides (`sync
    /// --from` is the explicit way out).
    /// Only an admin may turn the anti-lockout rule off (design: "Roles").
    /// Bootstrap counts as on.
    fn check_anti_lockout(&self, doc: &Document, role: Option<Role>) -> Result<(), Error> {
        let Some(role) = role.filter(|r| !r.allows(Role::Admin)) else {
            return Ok(());
        };
        let was_on = self
            .active_document()?
            .is_none_or(|d| d.management.anti_lockout);
        if was_on && !doc.management.anti_lockout {
            return Err(Error::Denied {
                role: role.as_str().into(),
                reason: "only an admin may turn off management.anti_lockout".into(),
            });
        }
        Ok(())
    }

    fn link_change_in_progress(&self, state: &State) -> Result<(), Error> {
        match &state.pending {
            Some(p) if p.decides_link => Err(Error::Validation(vec![format!(
                "the sync-link change {} is waiting for the peer; confirm it or roll it back first",
                p.id
            )])),
            Some(p) if p.link_change => Err(Error::Validation(vec![format!(
                "the peer's sync-link change {} is in progress; the peer decides it (or take \
                 the peer's configuration with sparewall sync --from <peer>)",
                p.id
            )])),
            _ => Ok(()),
        }
    }

    /// Whether running a document pushed by the peer would change this
    /// node's sync link (it then answers the push before running it).
    pub fn changes_sync_link(&self, value: &Value) -> Result<bool, Error> {
        let active = self.store.state()?.active;
        if self.runs(active) == 0 {
            return Ok(false);
        }
        Ok(link_change(&self.document_value(active)?, value))
    }

    /// Whether the peer is told a change is pending here: one is, or a
    /// kept sync-link change is not yet known to be on disk.
    pub fn publishes_pending(&self) -> Result<bool, Error> {
        Ok(self.decision_unsure || self.store.state()?.pending.is_some())
    }

    /// The sync-link decision the peer is told, once it is on disk.
    pub fn published_link_decision(&self) -> Result<Option<LinkDecision>, Error> {
        if self.decision_unsure {
            return Ok(None);
        }
        Ok(self.store.state()?.link_decision)
    }

    /// The peer has nothing pending: it followed the last sync-link
    /// decision (or never held the change), so the record can go.
    pub fn peer_followed(&mut self) -> Result<(), Error> {
        let mut state = self.store.state()?;
        if self.decision_unsure || state.pending.is_some() || state.link_decision.is_none() {
            return Ok(());
        }
        state.link_decision = None;
        self.store.set_state(&state)
    }

    /// The peer's sync-link change this node runs in doubt: its id and
    /// hash, and whether it is on the old link looking for the peer.
    pub fn in_doubt(&self) -> Result<Option<(u64, String, bool)>, Error> {
        let state = self.store.state()?;
        let Some(p) = state.pending.filter(|p| p.prepared) else {
            return Ok(None);
        };
        Ok(Some((p.id, self.generation(p.id)?.hash, p.trying_old)))
    }

    /// The peer decided an in-doubt sync-link change: keep it (`commit`),
    /// or return to the generation before it, as the peer did.
    pub fn resolve_in_doubt(&mut self, commit: bool) -> Result<(), Error> {
        let state = self.store.state()?;
        let Some(p) = state.pending.clone().filter(|p| p.prepared) else {
            return Ok(());
        };
        let live = self.rendered_for(self.live_id(&state))?;
        if commit {
            if p.trying_old {
                self.activate(p.id, Some(&live), false)?;
            }
            tracing::info!(id = p.id, "the peer kept the sync-link change");
            return self.finish_confirm(state, p.id);
        }
        self.switch_from(&live, p.revert_to, "the peer reverted the sync-link change")?;
        self.events.push(Event::RolledBack {
            to: p.revert_to,
            from: p.id,
            reason: "the peer reverted the sync-link change".into(),
        });
        Ok(())
    }

    /// In doubt and the peer unreachable: run the other link (old or new)
    /// to look for it there. Only the sync link differs between them.
    pub fn alternate_in_doubt(&mut self) -> Result<(), Error> {
        let mut state = self.store.state()?;
        let Some(p) = state.pending.as_mut().filter(|p| p.prepared) else {
            return Ok(());
        };
        let (from, to) = if p.trying_old {
            (p.revert_to, p.id)
        } else {
            (p.id, p.revert_to)
        };
        p.trying_old = !p.trying_old;
        let old = self.rendered_for(from)?;
        self.activate(to, Some(&old), false)?;
        self.store.set_state(&state)?;
        tracing::info!(running = to, "looking for the peer on the other sync link");
        Ok(())
    }

    /// The record of how a sync-link change this node decides ended, if
    /// `state`'s pending change is one; else the record it already has.
    fn decision(&self, state: &State, kept: bool) -> Result<Option<LinkDecision>, Error> {
        Ok(match state.pending.as_ref().filter(|p| p.decides_link) {
            Some(p) => Some(LinkDecision {
                id: p.id,
                hash: self.generation(p.id)?.hash,
                kept,
            }),
            None => state.link_decision.clone(),
        })
    }

    fn finish_confirm(&mut self, state: State, id: u64) -> Result<(), Error> {
        let before = state.clone();
        let mut state = state;
        state.link_decision = self.decision(&before, true)?;
        state.confirmed = id;
        state.pending = None;
        if let Err(f) = self.store.try_set_state(&state) {
            // Keeping a sync-link change is final for both nodes once the
            // peer sees it, so it must not be seen before it is on disk.
            if f.replaced
                && before.pending.as_ref().is_some_and(|p| p.decides_link)
                && let Err(e2) = self.store.set_state(&before)
            {
                tracing::error!(id, error = %e2, "cannot record the pending change again");
                self.decision_unsure = true;
            }
            return Err(f.error);
        }
        tracing::info!(id, "confirmed generation");
        self.events.push(Event::Confirmed { id });
        Ok(())
    }

    /// Confirm a pending generation. A sync-link change still waiting for
    /// the peer is only marked confirmed by the admin.
    pub fn confirm(&mut self, id: u64) -> Result<(), Error> {
        let mut state = self.store.state()?;
        if state.pending.as_ref().is_some_and(|p| p.link_change) {
            self.link_change_in_progress(&state)?;
        }
        if let Some(p) = state.pending.as_mut().filter(|p| p.id == id && p.peer_gate) {
            p.needs_admin = false;
            self.store.set_state(&state)?;
            tracing::info!(
                id,
                "the admin confirmed the sync-link change; waiting for the peer"
            );
            return Ok(());
        }
        match &state.pending {
            Some(p) if p.id == id => self.finish_confirm(state, id),
            None if state.active == id => Ok(()),
            _ => Err(Error::NotPending(id)),
        }
    }

    /// Revert an expired pending generation. Returns the generation it
    /// returned to.
    pub fn tick(&mut self, now: i64) -> Result<Option<u64>, Error> {
        if self.decision_unsure && self.store.sync_state().is_ok() {
            tracing::info!("the sync-link decision is on disk");
            self.decision_unsure = false;
        }
        let state = self.store.state()?;
        let Some(p) = state.pending.clone() else {
            return Ok(None);
        };
        if now < p.deadline || p.prepared {
            return Ok(None);
        }
        tracing::warn!(
            id = p.id,
            revert_to = p.revert_to,
            "confirm window expired; reverting"
        );
        let from = state.active;
        let reason = if p.from_peer || p.peer_gate {
            "the peer did not confirm it in time"
        } else {
            "confirm window expired"
        };
        let g = self.generation(p.id)?;
        self.switch_to(p.revert_to, reason)?;
        if p.from_peer {
            self.reject(&g, reason)?;
        }
        self.events.push(Event::RolledBack {
            to: p.revert_to,
            from,
            reason: reason.into(),
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

    /// Return to an earlier configuration: generation `id`, or by default
    /// the pending change's revert target or the active generation's base.
    ///
    /// A pending change is discarded first; it never left this node, so
    /// returning to its revert target needs no new generation. Any other
    /// rollback makes the target's document a new generation on top of the
    /// active one: the rolled-back generation stays in history, and a peer
    /// receives the rollback as an ordinary change. Reactivating the old
    /// generation instead would make this node look behind its peer, which
    /// would push the newer generation straight back.
    ///
    /// Rolling back to bootstrap (generation 0), which has no document,
    /// reactivates it.
    /// Whether `rollback(id)` would only discard an unconfirmed change,
    /// which never left this node (so it involves no peer). Decide and
    /// roll back under the same lock: a confirm window expiring or a
    /// confirmation in between changes the answer.
    pub fn rollback_is_local(&self, id: Option<u64>) -> Result<bool, Error> {
        Ok(self
            .store
            .state()?
            .pending
            .is_some_and(|p| id.is_none_or(|t| t == p.revert_to)))
    }

    pub fn rollback(&mut self, id: Option<u64>, author: &str) -> Result<Generation, Error> {
        self.rollback_staging(id, author, false, None)
            .map(|(g, _)| g)
    }

    /// [`Self::rollback`], staging it like [`ApplyOptions::stage_sync_link`]
    /// when it changes the sync link; returns whether it was staged.
    /// `role` is the caller's on the restricted socket, as in
    /// [`ApplyOptions::role`].
    pub fn rollback_staging(
        &mut self,
        id: Option<u64>,
        author: &str,
        stage_sync_link: bool,
        role: Option<Role>,
    ) -> Result<(Generation, bool), Error> {
        let state = self.store.state()?;
        if state.pending.as_ref().is_some_and(|p| p.link_change) {
            self.link_change_in_progress(&state)?;
        }
        if let Some(target) = id
            && target != 0
            && !self.store.exists(target)
        {
            return Err(Error::NotFound(target));
        }
        if let Some(p) = &state.pending {
            let from = state.active;
            self.switch_to(p.revert_to, "rollback")?;
            self.events.push(Event::RolledBack {
                to: p.revert_to,
                from,
                reason: "rollback of an unconfirmed change".into(),
            });
            if id.is_none_or(|t| t == p.revert_to) {
                return Ok((self.generation(p.revert_to)?, false));
            }
        }
        let state = self.store.state()?;
        let target = match id {
            Some(t) => t,
            None => self.generation(state.active)?.base.unwrap_or(0),
        };
        let from = state.active;
        if target == 0 {
            self.switch_to(0, "rollback")?;
            self.events.push(Event::RolledBack {
                to: 0,
                from,
                reason: "rollback to bootstrap".into(),
            });
            return Ok((self.generation(0)?, false));
        }
        let value = self.document_value(target)?;
        let r = self.apply(
            value,
            &ApplyOptions {
                base: from,
                author: author.to_string(),
                note: Some(format!("rollback to generation {target}")),
                stage_sync_link,
                role,
                ..Default::default()
            },
        )?;
        if !r.unchanged && !r.staged {
            self.events.push(Event::RolledBack {
                to: r.generation.id,
                from,
                reason: format!("rollback to generation {target}"),
            });
        }
        Ok((r.generation, r.staged))
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
            rejected: state.rejected.clone(),
            link_decision: self.decision(&state, false)?,
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

    /// Replace the pair checks contributed from outside the core.
    pub fn set_extra_checks(&mut self, checks: Vec<Check>) {
        self.set_named_checks("pair", checks);
    }

    /// Replace the checks one outside source contributes.
    pub fn set_named_checks(&mut self, source: &str, checks: Vec<Check>) {
        self.extra_checks.insert(source.to_string(), checks);
    }

    /// The live document, if any.
    pub fn active_document(&self) -> Result<Option<Document>, Error> {
        match self.runs(self.active()?) {
            0 => Ok(None),
            id => self.store.document(id).map(Some),
        }
    }

    /// What this node reports to its peer.
    pub fn view(&mut self) -> Result<crate::pair::NodeView, Error> {
        let state = self.store.state()?;
        // A generation from the peer is not reported applied until the
        // peer has confirmed it (`applied`): until then the pair is
        // "applying".
        Ok(crate::pair::NodeView {
            node: self.node().to_string(),
            active: state.active,
            desired: self.generation(state.active)?.hash,
            applied: self.applied()?,
            lineage: self.lineage()?,
            applying: self.awaiting_peer()?.is_some(),
        })
    }

    /// The live table, normalized, or `None` when it is not loaded.
    fn nft_live(
        &mut self,
        preserved: &[String],
    ) -> Result<Option<crate::nft_state::Components>, Error> {
        Ok(self
            .sys
            .nft_json()?
            .map(|v| crate::nft_state::normalize(&v, preserved)))
    }

    /// Why the live firewall cannot be trusted to be what was loaded: it
    /// differs, or it could not be verified since the load. `None` when it
    /// matches (or this process has loaded nothing yet).
    pub fn nft_drift(&mut self) -> Result<Option<String>, Error> {
        let loaded = match self.nft_loaded.clone() {
            NftBaseline::None => return Ok(None),
            NftBaseline::Unverified(why) => {
                return Ok(Some(format!(
                    "cannot verify the live firewall ({why}); reloading it (restart sparewalld, or apply a change) verifies it again"
                )));
            }
            NftBaseline::Recorded(c) => c,
        };
        let active = self.active()?;
        let preserved = self.rendered_for(active)?.meta.preserved_sets;
        Ok(match self.nft_live(&preserved) {
            Ok(Some(live)) => crate::nft_state::drift(&loaded, &live)
                .map(|d| format!("live ruleset differs from what generation {active} loaded: {d}")),
            Ok(None) => Some("table inet sparewall is not loaded".into()),
            Err(e) => Some(format!("cannot read the ruleset: {e}")),
        })
    }

    /// The hash of the configuration this node verifiably runs: the last
    /// one activated, unless the live firewall has drifted from it since.
    /// A generation pushed by the peer counts as applied only once the
    /// peer has confirmed it: until then status, metrics and the peer view
    /// all report nothing applied.
    pub fn applied(&mut self) -> Result<Option<String>, Error> {
        if self.awaiting_peer()?.is_some() {
            return Ok(None);
        }
        if self.applied_hash.is_some() && self.nft_drift()?.is_some() {
            return Ok(None);
        }
        Ok(self.applied_hash.clone())
    }

    /// The generation from the peer that runs pending its confirmation.
    fn awaiting_peer(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .store
            .state()?
            .pending
            .filter(|p| p.from_peer)
            .map(|p| p.id))
    }

    /// Accept a generation pushed by the peer and run it. It keeps the
    /// peer's id and is refused unless its `base` is this node's active
    /// generation, or reaches it through generations received with
    /// [`Self::receive_history`], so a push never overwrites a change this
    /// node has not seen. A generation rejected here before is refused
    /// until something newer replaces it.
    pub fn receive(&mut self, g: &Generation, value: Value, gate: PeerGate) -> Result<(), Error> {
        let state = self.store.state()?;
        if let Some(r) = &state.rejected
            && r.id == g.id
            && r.hash == g.hash
        {
            return Err(Error::Apply(format!(
                "generation {} was rejected here: {}. Make a new change, or run `sparewall sync --from <peer>` on this node to retry it",
                g.id, r.reason
            )));
        }
        if self.store.exists(g.id) {
            let have = self.store.meta(g.id)?;
            if have.hash == g.hash {
                if state.active != g.id {
                    self.check(self.document_value(g.id)?)?;
                    let old = self.rendered_for(state.active)?;
                    self.run_foreign(g, &old, gate, "peer push")?;
                }
                return Ok(());
            }
        }
        // A local generation with this id and other content never ran here
        // (a failed apply, a crash before `state.json` named it, history or
        // a rejected push from the peer), so `install_foreign` sets it
        // aside. One that ran is divergence.
        if state.pending.is_some() || !self.follows_active(g)? {
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        self.install_foreign(g, value, gate, "peer push")
    }

    /// Store a generation pushed by the peer without running it: one the
    /// peer has passed through on the way to the generation it runs (a
    /// change followed by its rollback), so the history matches without
    /// this node ever running the rolled-back configuration.
    pub fn receive_history(&mut self, g: &Generation, value: Value) -> Result<(), Error> {
        let state = self.store.state()?;
        let replace = self.store.exists(g.id);
        if replace && self.store.meta(g.id)?.hash == g.hash {
            return Ok(());
        }
        // As in `receive`: a different local generation with this id
        // never ran here.
        if state.pending.is_some() || !self.follows_active(g)? {
            return Err(Error::Conflict {
                current: state.active,
            });
        }
        let (doc, _, rendered) = self.check_history(value)?;
        if sparewall_config::hash(&doc) != g.hash {
            return Err(Error::Validation(vec![format!(
                "generation {} does not match its hash",
                g.id
            )]));
        }
        if replace {
            let to = self.store.set_aside(g.id, "diverged")?;
            tracing::warn!(id = g.id, kept = %to.display(), "set aside a generation that never ran");
        }
        self.store.save(g, &doc, &rendered)?;
        tracing::info!(id = g.id, "stored the peer's generation in history");
        Ok(())
    }

    /// Whether a pushed generation comes after the active one: its base is
    /// the active generation or leads back to it, and its id is above its
    /// base, so above the active one too. Only then may it replace a local
    /// generation with its id; the metadata is the peer's word, not
    /// covered by the hash.
    fn follows_active(&self, g: &Generation) -> Result<bool, Error> {
        Ok(g.base.is_some_and(|b| b < g.id) && self.extends_active(g.base)?)
    }

    /// Whether `base` is the active generation, or a generation stored
    /// after it whose bases lead back to it.
    fn extends_active(&self, base: Option<u64>) -> Result<bool, Error> {
        let active = self.store.state()?.active;
        let mut id = base;
        for _ in 0..10_000 {
            match id {
                Some(i) if i == active => return Ok(true),
                Some(i) if i > active && self.store.exists(i) => id = self.store.meta(i)?.base,
                _ => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Take the peer's generation regardless of history (`sync --from`).
    /// A local generation with the same id but other content is set aside.
    /// An explicit sync retries a generation rejected before.
    pub fn adopt(&mut self, g: &Generation, value: Value, gate: PeerGate) -> Result<(), Error> {
        let mut state = self.store.state()?;
        if state.rejected.take().is_some() {
            self.store.set_state(&state)?;
        }
        if self.store.exists(g.id) {
            let have = self.store.meta(g.id)?;
            if have.hash == g.hash {
                if state.active == g.id {
                    return Ok(());
                }
                // Stored as history, or by an earlier version: check it
                // as this one would before running it.
                self.check(self.document_value(g.id)?)?;
                let old = self.rendered_for(state.active)?;
                return self.run_foreign(g, &old, gate, "sync");
            }
        }
        self.install_foreign(g, value, gate, "sync")
    }

    fn install_foreign(
        &mut self,
        g: &Generation,
        value: Value,
        gate: PeerGate,
        why: &str,
    ) -> Result<(), Error> {
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
            // `adopt`, or a push replacing one that never ran here: keep
            // the local generation aside.
            let to = self.store.set_aside(g.id, "diverged")?;
            tracing::warn!(id = g.id, kept = %to.display(), "set aside a diverged generation");
        }
        self.install_vpn_keys(&doc)?;
        self.store.save(g, &doc, &rendered)?;
        self.run_foreign(g, &old_rendered, gate, why)
    }

    /// What currently fails, per resource a change could break: each
    /// required link that is not up (`link wan`), each provider unit that
    /// is not active (`service sparewall-kea.service`), and every other
    /// failed check by name (`check nft`). A fault that was there before a
    /// change is told apart from a new one of the same kind.
    fn failures(&mut self) -> Result<Vec<String>, Error> {
        let failed: Vec<String> = self
            .health()?
            .checks
            .into_iter()
            .filter(|c| c.level == Level::Failed)
            .map(|c| c.name)
            .collect();
        let r = self.rendered_for(self.active()?)?;
        let mut out = Vec::new();
        for name in failed {
            match name.as_str() {
                "links" => {
                    let states = self.sys.link_states();
                    for l in &r.meta.required_links {
                        if !matches!(states.get(l).map(String::as_str), Some("up" | "unknown")) {
                            out.push(format!("link {l}"));
                        }
                    }
                }
                "services" => {
                    let units: Vec<String> =
                        r.meta.services.values().map(|s| s.unit.clone()).collect();
                    for (u, st) in self.sys.unit_states(&units) {
                        if st != "active" {
                            out.push(format!("service {u}"));
                        }
                    }
                }
                other => out.push(format!("check {other}")),
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Run a stored generation from the peer. If activation fails partway
    /// (after nft, links or providers changed), the generation that was
    /// running is activated again, as for a local apply, and the peer's
    /// generation is rejected so it is not pushed into the same failure
    /// over and over. With [`PeerGate::PeerConfirms`] it then runs pending
    /// until the peer confirms it (see [`Self::confirm_received`]).
    fn run_foreign(
        &mut self,
        g: &Generation,
        old: &Rendered,
        gate: PeerGate,
        why: &str,
    ) -> Result<(), Error> {
        // Durable before any state record names it, even if stored by an
        // earlier attempt whose sync failed.
        self.store.sync_generation(g.id)?;
        let state = self.store.state()?;
        let from = state.active;
        let failed_before = match gate {
            PeerGate::PeerConfirms => self.failures()?,
            PeerGate::Immediate => vec![],
        };
        let changes_link = gate == PeerGate::PeerConfirms
            && link_change(&self.document_value(from)?, &self.document_value(g.id)?);
        if let Err(e) = self.activate(g.id, Some(old), false) {
            return Err(self.undo_foreign(g, from, "activating it failed", e));
        }
        let mut st = state.clone();
        st.active = g.id;
        st.rejected = None;
        match gate {
            PeerGate::Immediate => {
                st.confirmed = g.id;
                st.pending = None;
            }
            PeerGate::PeerConfirms => {
                st.pending = Some(Pending {
                    id: g.id,
                    revert_to: state.pending.as_ref().map_or(from, |p| p.revert_to),
                    deadline: now_unix() + PEER_CONFIRM_SECONDS,
                    from_peer: true,
                    failed_before,
                    link_change: changes_link,
                    ..Default::default()
                });
            }
        }
        if let Err(f) = self.store.try_set_state(&st) {
            let new = self.rendered_for(g.id)?;
            let (e, unreferenced) = self.reconcile_commit(g.id, &new, &state, f);
            if unreferenced && let Err(e2) = self.reject(g, &format!("recording it failed: {e}")) {
                tracing::error!(id = g.id, error = %e2, "cannot record the rejection");
            }
            return Err(e);
        }
        self.events.push(Event::Applied {
            id: g.id,
            hash: g.hash.clone(),
            author: g.author.clone(),
            pending: gate == PeerGate::PeerConfirms,
        });
        tracing::info!(
            id = g.id,
            from,
            why,
            ?gate,
            "installed the peer's generation"
        );
        Ok(())
    }

    /// [`Self::restore`] for the peer's generation, which is then
    /// rejected so it is not pushed into the same failure again.
    fn undo_foreign(&mut self, g: &Generation, to: u64, what: &str, e: Error) -> Error {
        let e = match self.rendered_for(g.id) {
            Ok(new) => self.restore(g.id, &new, to, e),
            Err(e2) => {
                tracing::error!(id = g.id, error = %e2, "cannot read the generation to restore from");
                e
            }
        };
        if let Err(e2) = self.reject(g, &format!("{what}: {e}")) {
            tracing::error!(id = g.id, error = %e2, "cannot record the rejection");
        }
        e
    }

    fn reject(&mut self, g: &Generation, reason: &str) -> Result<(), Error> {
        let mut st = self.store.state()?;
        st.rejected = Some(crate::store::Rejected {
            id: g.id,
            hash: g.hash.clone(),
            reason: reason.to_string(),
        });
        self.store.set_state(&st)?;
        tracing::warn!(id = g.id, reason, "rejected the peer's generation");
        Ok(())
    }

    /// The peer confirms a generation it pushed, over a new connection
    /// through the sync tunnel, so the change has left the tunnel working.
    /// It is confirmed only if it made no further health check fail than
    /// had failed before it ran; otherwise it stays pending (the peer
    /// retries while links settle) and reverts at its deadline.
    pub fn confirm_received(&mut self, id: u64) -> Result<(), Error> {
        let mut state = self.store.state()?;
        let Some(p) = state.pending.clone().filter(|p| p.from_peer && p.id == id) else {
            // A repeated confirmation.
            if state.pending.is_none() && state.active == id {
                return Ok(());
            }
            return Err(Error::NotPending(id));
        };
        let newly: Vec<String> = self
            .failures()?
            .into_iter()
            .filter(|c| !p.failed_before.contains(c))
            .collect();
        if !newly.is_empty() {
            return Err(Error::Apply(format!(
                "generation {id} is not confirmed: it fails what did not fail before: {}",
                newly.join(", ")
            )));
        }
        if p.link_change {
            // The peer decides; this node keeps or reverts it as the peer
            // did, whatever happens to this reply or this node.
            if !p.prepared {
                if let Some(q) = state.pending.as_mut() {
                    q.prepared = true;
                }
                self.store.set_state(&state)?;
                tracing::info!(id, "the sync-link change works here; the peer decides");
            }
            return Ok(());
        }
        state.confirmed = id;
        state.pending = None;
        self.store.set_state(&state)?;
        tracing::info!(id, "the peer confirmed its generation");
        self.events.push(Event::Confirmed { id });
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
        // A table that drifted since its load is reloaded with any change.
        let drifted = old.is_some() && self.nft_drift()?.is_some();
        let changed_list: Vec<Subsystem> = Subsystem::all()
            .iter()
            .copied()
            .filter(|s| changed(*s))
            .collect();
        let result = (|| -> Result<(), Error> {
            // Firewall first, so new interfaces are covered as they appear.
            let mut new_sets = Vec::new();
            if changed(Subsystem::Nft) || old.is_none() || drifted {
                let body = r
                    .files
                    .get(&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT))
                    .ok_or_else(|| Error::Internal("no nft script".into()))?;
                new_sets = self.sys.nft_load(body, &r.meta.preserved_sets)?;
                self.nft_loaded = match self.nft_live(&r.meta.preserved_sets) {
                    Ok(Some(c)) => NftBaseline::Recorded(c),
                    Ok(None) => NftBaseline::Unverified(
                        "the table was not listed right after loading it".into(),
                    ),
                    Err(e) => {
                        NftBaseline::Unverified(format!("cannot read back the loaded table: {e}"))
                    }
                };
                if let NftBaseline::Unverified(why) = &self.nft_loaded {
                    tracing::error!(why, "the loaded firewall cannot be verified");
                }
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
                self.applied_hash = Some(self.generation(self.runs(id))?.hash);
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

        checks.push(
            // The active generation, or the one running in its place.
            if let Some((id, e)) = [state.active, self.live_id(&state)]
                .into_iter()
                .find_map(|i| self.unreadable.get(&i).map(|e| (i, e)))
            {
                Check::new(
                    "generation",
                    Level::Failed,
                    format!(
                        "generation {id} cannot be read ({e}); running the bootstrap configuration \
                     (management only): roll back to an earlier generation or apply a document"
                    ),
                )
            } else if state.active == 0 {
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
            },
        );

        // Degraded, not failed: a held pair must still confirm and sync.
        if self.active_document()?.is_some_and(|d| d.cluster.hold) {
            checks.push(Check::new(
                "held",
                Level::Degraded,
                "holding: no gateway address is claimed and DHCP offers nothing \
                 (cluster.hold); cut over with sparewall set cluster.hold=false",
            ));
        }

        if let Some(p) = &state.pending {
            checks.push(Check::new(
                "confirm",
                Level::Degraded,
                format!(
                    "generation {}{} reverts in {}s unless {}",
                    p.id,
                    if p.from_peer { " from the peer" } else { "" },
                    (p.deadline - now_unix()).max(0),
                    match (p.from_peer, p.peer_gate, p.needs_admin) {
                        (true, ..) => "the peer confirms it",
                        (_, true, true) =>
                            "the peer confirms it over the new sync link and you confirm it",
                        (_, true, false) => "the peer confirms it over the new sync link",
                        _ => "confirmed",
                    }
                ),
            ));
        }
        if let Some(r) = &state.rejected {
            checks.push(Check::new(
                "peer-generation",
                Level::Degraded,
                format!("rejected the peer's generation {}: {}", r.id, r.reason),
            ));
        }

        let drift = self.nft_drift()?;
        let awaiting = self.awaiting_peer()?;
        let in_doubt = state.pending.as_ref().filter(|p| p.prepared);
        let live_hash = self.generation(self.live_id(&state))?.hash;
        checks.push(match (&self.applied_hash, &self.last_error, &drift) {
            // In doubt, on either link: degraded, so it neither moves the
            // gateway addresses nor stops the search for the peer.
            (Some(h), None, None) if *h == live_hash && in_doubt.is_some() => Check::new(
                "applied",
                Level::Degraded,
                format!(
                    "the peer's sync-link change {} is in doubt until the peer's decision is known{}",
                    state.active,
                    if in_doubt.is_some_and(|p| p.trying_old) {
                        "; looking for the peer on the old link"
                    } else {
                        ""
                    }
                ),
            ),
            // Degraded, not failed: a failed check would block the very
            // confirmation it waits for, and lower VRRP priority.
            (Some(h), None, None) if *h == desired.hash && awaiting.is_some() => Check::new(
                "applied",
                Level::Degraded,
                format!(
                    "running generation {} from the peer, awaiting its confirmation",
                    state.active
                ),
            ),
            (_, Some(e), _) => {
                Check::new("applied", Level::Failed, format!("last apply failed: {e}"))
            }
            (Some(_), None, Some(_)) => Check::new(
                "applied",
                Level::Failed,
                "the live firewall is not verifiably the desired configuration",
            ),
            (Some(h), None, None) if *h == desired.hash => {
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
        checks.push(match (&drift, self.sys.nft_chains()) {
            (Some(d), _) => Check::new("nft", Level::Failed, d.clone()),
            (None, Ok(Some(live))) => {
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
            (None, Ok(None)) => {
                Check::new("nft", Level::Failed, "table inet sparewall is not loaded")
            }
            (None, Err(e)) => Check::new("nft", Level::Failed, format!("cannot read ruleset: {e}")),
        });

        let states = self.sys.link_states();
        let not_up = |links: &[String]| -> Vec<String> {
            links
                .iter()
                .filter_map(|l| match states.get(l).map(String::as_str) {
                    Some("up" | "unknown") => None,
                    Some(s) => Some(format!("{l} is {s}")),
                    None => Some(format!("{l} is missing")),
                })
                .collect()
        };
        let down = not_up(&r.meta.required_links);
        checks.push(if down.is_empty() {
            Check::new(
                "links",
                Level::Ok,
                format!("{} required links up", r.meta.required_links.len()),
            )
        } else {
            Check::new("links", Level::Failed, down.join(", "))
        });
        // Links carrying only replication: losing one stops the pair
        // replicating, but traffic still flows, so it degrades and never
        // fails health (which would move the gateway addresses).
        if !r.meta.replication_links.is_empty() {
            let down = not_up(&r.meta.replication_links);
            checks.push(if down.is_empty() {
                Check::new(
                    "replication",
                    Level::Ok,
                    format!("{} replication links up", r.meta.replication_links.len()),
                )
            } else {
                Check::new(
                    "replication",
                    Level::Degraded,
                    format!(
                        "{} (the pair is not replicating; traffic is unaffected)",
                        down.join(", ")
                    ),
                )
            });
        }

        // A bond with a member down still carries traffic, without the
        // redundancy it was built for.
        if !r.meta.bonds.is_empty() {
            let short: Vec<String> = r
                .meta
                .bonds
                .iter()
                .filter_map(|(bond, &want)| {
                    let members = self.sys.bond_members(bond);
                    let down: Vec<&str> = members
                        .iter()
                        .filter(|(_, up)| !up)
                        .map(|(m, _)| m.as_str())
                        .collect();
                    let up = members.len() - down.len();
                    (up < want).then(|| {
                        let mut s = format!("{bond}: {up} of {want} members up");
                        if !down.is_empty() {
                            s.push_str(&format!(" ({} down)", down.join(", ")));
                        }
                        s
                    })
                })
                .collect();
            checks.push(if short.is_empty() {
                Check::new(
                    "bonds",
                    Level::Ok,
                    format!("{} bonds with every member up", r.meta.bonds.len()),
                )
            } else {
                Check::new("bonds", Level::Degraded, short.join("; "))
            });
        }

        if let Some(doc) = self.active_document()? {
            let missing = missing_psk_messages(&self.missing_vpn_psks(&doc)?);
            if !missing.is_empty() {
                checks.push(Check::new("vpn", Level::Degraded, missing.join("; ")));
            }
        }

        checks.extend(self.extra_checks.values().flatten().cloned());

        let units: Vec<String> = r.meta.services.values().map(|s| s.unit.clone()).collect();
        if !units.is_empty() {
            let states = self.sys.unit_states(&units);
            let management = |u: &str| {
                r.meta
                    .services
                    .values()
                    .any(|s| s.unit == u && s.management)
            };
            let bad: Vec<(bool, String)> = states
                .iter()
                .filter(|(_, st)| st.as_str() != "active")
                .map(|(u, st)| (management(u), format!("{u} is {st}")))
                .collect();
            let words = |b: &[(bool, String)]| {
                b.iter()
                    .map(|(_, w)| w.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            // A management service down (the web UI) leaves traffic
            // flowing, so it never moves the gateway address.
            checks.push(if bad.is_empty() {
                Check::new(
                    "services",
                    Level::Ok,
                    format!("{} services running", units.len()),
                )
            } else if bad.iter().all(|(m, _)| *m) {
                Check::new("services", Level::Degraded, words(&bad))
            } else {
                Check::new("services", Level::Failed, words(&bad))
            });
        }

        Ok(Health::from_checks(checks))
    }

    /// Desired and applied configuration hashes.
    /// The desired hash, and the applied one (`None` while the live
    /// firewall has drifted from it).
    pub fn hashes(&mut self) -> Result<(String, Option<String>), Error> {
        let state = self.store.state()?;
        Ok((self.generation(state.active)?.hash, self.applied()?))
    }
}

/// What to say about preshared keys the document references but the
/// store lacks.
fn missing_psk_messages(missing: &[(String, String, String)]) -> Vec<String> {
    missing
        .iter()
        .map(|(name, peer, secret)| {
            format!(
                "vpn.{name}.peers.{peer}: preshared key secret {secret:?} is not set, so the peer \
                 cannot connect (sparewall secret set {secret})"
            )
        })
        .collect()
}
