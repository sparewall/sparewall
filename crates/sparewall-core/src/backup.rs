//! The backup bundle (design: "Backup and restore").
//!
//! One `.tar.gz` per node holding the active document, the newest
//! generations, the cluster secrets (sealed with the backup password), a
//! DHCP lease export, the running image digest and the node's identity.
//! Node private keys are never included: a rebuilt node generates new
//! ones and is re-paired.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::coordinator::Coordinator;
use crate::secrets::SharedSecret;
use crate::store::{State, write_atomic};
use crate::system::System;

/// Bundle format version.
pub const FORMAT: u32 = 1;
/// Generations included by default.
pub const DEFAULT_GENERATIONS: usize = 20;
/// The cluster secret that seals the secrets in a bundle and is restic's
/// repository password. Operators keep a copy outside Sparewall.
pub const PASSWORD_SECRET: &str = "backup-password";
const SECRETS: &str = "secrets.sealed";
/// Bundles kept on the node; the repository keeps the history.
pub const KEEP_LOCAL: usize = 5;
const LAST: &str = "last.json";

/// The outcome of the newest backup run, kept beside the bundles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Last {
    pub time: String,
    pub bundle: Option<String>,
    /// The restic snapshot, when the bundle was sent to a repository.
    pub snapshot: Option<String>,
    pub error: Option<String>,
    /// The newest run that succeeded.
    pub success: Option<String>,
}

pub fn read_last(state_dir: &Path) -> Option<Last> {
    serde_json::from_slice(&fs::read(state_dir.join("backups").join(LAST)).ok()?).ok()
}

/// Record a run; a failure keeps the time of the last success.
pub fn record(
    state_dir: &Path,
    bundle: Option<&Path>,
    snapshot: Option<String>,
    error: Option<String>,
) -> Result<Last, Error> {
    let now = jiff::Timestamp::now().to_string();
    let prev = read_last(state_dir).and_then(|l| l.success);
    let last = Last {
        time: now.clone(),
        bundle: bundle.map(|b| b.display().to_string()),
        snapshot,
        success: if error.is_none() { Some(now) } else { prev },
        error,
    };
    let p = state_dir.join("backups").join(LAST);
    write_atomic(&p, &serde_json::to_vec_pretty(&last).expect("json"))
        .map_err(|e| Error::io(&p, e))?;
    Ok(last)
}

/// Remove all but the newest `keep` bundles in `dir`.
/// The bundles in a directory, oldest first.
fn bundles(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return vec![];
    };
    let mut bundles: Vec<(std::time::SystemTime, PathBuf)> = rd
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with("sparewall-") && n.ends_with(".tar.gz")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    bundles.sort();
    bundles.into_iter().map(|(_, p)| p).collect()
}

/// The newest bundle in a directory (the node keeps them in
/// `backups/` under its state directory).
pub fn newest(dir: &Path) -> Option<PathBuf> {
    bundles(dir).pop()
}

fn prune(dir: &Path, keep: usize) {
    let bundles = bundles(dir);
    let n = bundles.len().saturating_sub(keep);
    for p in bundles.into_iter().take(n) {
        let _ = fs::remove_file(p);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: u32,
    pub node: String,
    pub created: String,
    pub schema: u32,
    pub active: u64,
    pub generations: Vec<u64>,
    /// `bootc status` image digest, when known.
    pub image: Option<String>,
    pub leases: bool,
    /// Names of the sealed cluster secrets.
    #[serde(default)]
    pub secrets: Vec<String>,
}

/// Where the bundle sources live on a node.
pub struct Sources {
    /// The DHCP provider's lease file, if it keeps one the coordinator
    /// can read (`providers::State::path`).
    pub leases: Option<PathBuf>,
    pub out_dir: PathBuf,
    pub image_digest: Option<String>,
}

fn add(tar: &mut tar::Builder<GzEncoder<fs::File>>, name: &str, data: &[u8]) -> Result<(), Error> {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o600);
    h.set_mtime(jiff::Timestamp::now().as_second().max(0) as u64);
    h.set_cksum();
    tar.append_data(&mut h, name, data)
        .map_err(|e| Error::Internal(format!("bundle: {e}")))
}

impl<S: System> Coordinator<S> {
    /// Write a bundle; returns its path and SHA-256.
    pub fn backup(
        &mut self,
        src: &Sources,
        generations: usize,
    ) -> Result<(PathBuf, String), Error> {
        let state = self.state()?;
        let mut ids = self.store().ids()?;
        ids.reverse();
        ids.truncate(generations);
        if state.active != 0 && !ids.contains(&state.active) {
            ids.push(state.active);
        }
        ids.sort_unstable();
        let leases = src.leases.as_ref().and_then(|p| fs::read(p).ok());
        let password = self.secret_get(PASSWORD_SECRET)?;
        let secrets = match &password {
            Some(_) => self.cluster_secrets()?,
            None => {
                tracing::warn!(
                    "no {PASSWORD_SECRET} secret: the bundle leaves out the cluster secrets"
                );
                vec![]
            }
        };
        let now = jiff::Timestamp::now();
        let manifest = Manifest {
            format: FORMAT,
            node: self.node().to_string(),
            created: now.to_string(),
            schema: sparewall_config::SCHEMA_VERSION,
            active: state.active,
            generations: ids.clone(),
            image: src.image_digest.clone(),
            leases: leases.is_some(),
            secrets: secrets.iter().map(|s| s.info.name.clone()).collect(),
        };
        fs::create_dir_all(&src.out_dir).map_err(|e| Error::io(&src.out_dir, e))?;
        let name = format!(
            "sparewall-{}-g{}-{}.tar.gz",
            self.node(),
            state.active,
            now.strftime("%Y%m%dT%H%M%SZ")
        );
        let path = src.out_dir.join(&name);
        let tmp = src.out_dir.join(format!(".{name}.tmp"));
        {
            let f = fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
            let mut tar = tar::Builder::new(GzEncoder::new(f, Compression::default()));
            add(
                &mut tar,
                "manifest.json",
                &serde_json::to_vec_pretty(&manifest).expect("json"),
            )?;
            add(
                &mut tar,
                "state.json",
                &serde_json::to_vec_pretty(&state).expect("json"),
            )?;
            if let Some(id) = self.store().identity()? {
                add(
                    &mut tar,
                    "identity.json",
                    &serde_json::to_vec_pretty(&id).expect("json"),
                )?;
            }
            // The export is for reading; a restore uses the generations'
            // own files. A generation this release cannot read has none
            // (#169), and its files below still go into the bundle.
            if self.runs(state.active) != 0 {
                let doc = self.store().document(state.active)?;
                let text = sparewall_config::export(&doc, sparewall_config::Format::Yaml);
                add(&mut tar, "document.yaml", text.as_bytes())?;
            }
            for id in &ids {
                let dir = self.store().root().join("generations").join(id.to_string());
                for f in ["meta.json", "document.json"] {
                    let p = dir.join(f);
                    let data = fs::read(&p).map_err(|e| Error::io(&p, e))?;
                    add(&mut tar, &format!("generations/{id}/{f}"), &data)?;
                }
            }
            if let Some(pw) = &password {
                let plain = serde_json::to_vec(&secrets).expect("json");
                add(&mut tar, SECRETS, &crate::seal::seal(pw, &plain)?)?;
            }
            if let Some(l) = &leases {
                add(&mut tar, "leases/kea-leases4.csv", l)?;
            }
            let gz = tar
                .into_inner()
                .map_err(|e| Error::Internal(format!("bundle: {e}")))?;
            let f = gz
                .finish()
                .map_err(|e| Error::Internal(format!("bundle: {e}")))?;
            f.sync_all().map_err(|e| Error::io(&tmp, e))?;
        }
        fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
        prune(&src.out_dir, KEEP_LOCAL);
        let digest = hex::encode(Sha256::digest(
            fs::read(&path).map_err(|e| Error::io(&path, e))?,
        ));
        tracing::info!(path = %path.display(), digest, "wrote backup bundle");
        Ok((path, digest))
    }
}

/// Read a bundle's manifest.
pub fn manifest(bundle: &Path) -> Result<Manifest, Error> {
    let f = fs::File::open(bundle).map_err(|e| Error::io(bundle, e))?;
    let mut ar = tar::Archive::new(GzDecoder::new(f));
    for e in ar.entries().map_err(|e| Error::Internal(e.to_string()))? {
        let mut e = e.map_err(|e| Error::Internal(e.to_string()))?;
        if e.path().ok().as_deref() == Some(Path::new("manifest.json")) {
            let mut s = String::new();
            e.read_to_string(&mut s)
                .map_err(|e| Error::Internal(e.to_string()))?;
            return serde_json::from_str(&s).map_err(|e| Error::Internal(e.to_string()));
        }
    }
    Err(Error::Internal("bundle has no manifest".into()))
}

/// Whether `password` opens a bundle's sealed secrets, writing nothing:
/// the names of the secrets it opens.
pub fn check_password(bundle: &Path, password: &[u8]) -> Result<Vec<String>, Error> {
    let f = fs::File::open(bundle).map_err(|e| Error::io(bundle, e))?;
    let mut ar = tar::Archive::new(GzDecoder::new(f));
    for e in ar.entries().map_err(|e| Error::Internal(e.to_string()))? {
        let mut e = e.map_err(|e| Error::Internal(e.to_string()))?;
        if e.path().ok().as_deref() != Some(Path::new(SECRETS)) {
            continue;
        }
        let mut data = Vec::new();
        e.read_to_end(&mut data)
            .map_err(|e| Error::Internal(e.to_string()))?;
        let secrets: Vec<SharedSecret> =
            serde_json::from_slice(&crate::seal::open(password, &data)?)
                .map_err(|e| Error::Internal(format!("{SECRETS}: {e}")))?;
        return Ok(secrets.into_iter().map(|s| s.info.name).collect());
    }
    Err(Error::Validation(vec![format!(
        "the bundle has no secrets: it was written without a {PASSWORD_SECRET} secret"
    )]))
}

/// Restore a bundle into a state directory (with sparewalld stopped,
/// before services first start). The generation that was active becomes
/// active and confirmed; the lease file goes to `leases` if given. The
/// cluster secrets are unsealed with `password` and returned for the
/// caller to store (encrypting them for this node); without a password
/// they are skipped.
pub fn restore(
    bundle: &Path,
    state_dir: &Path,
    leases: Option<&Path>,
    password: Option<&[u8]>,
) -> Result<(Manifest, Vec<SharedSecret>), Error> {
    let m = manifest(bundle)?;
    let mut secrets = Vec::new();
    if m.format > FORMAT {
        return Err(Error::Validation(vec![format!(
            "bundle format {} is newer than this coordinator understands ({FORMAT})",
            m.format
        )]));
    }
    if m.schema > sparewall_config::SCHEMA_VERSION {
        return Err(Error::Validation(vec![format!(
            "bundle schema {} is newer than this coordinator reads ({})",
            m.schema,
            sparewall_config::SCHEMA_VERSION
        )]));
    }
    // Read everything first, so a wrong password changes nothing.
    let f = fs::File::open(bundle).map_err(|e| Error::io(bundle, e))?;
    let mut ar = tar::Archive::new(GzDecoder::new(f));
    let mut entries = Vec::new();
    for e in ar.entries().map_err(|e| Error::Internal(e.to_string()))? {
        let mut e = e.map_err(|e| Error::Internal(e.to_string()))?;
        let p = e
            .path()
            .map_err(|e| Error::Internal(e.to_string()))?
            .into_owned();
        let mut data = Vec::new();
        e.read_to_end(&mut data)
            .map_err(|e| Error::Internal(e.to_string()))?;
        if p == Path::new(SECRETS) {
            if let Some(pw) = password {
                secrets = serde_json::from_slice(&crate::seal::open(pw, &data)?)
                    .map_err(|e| Error::Internal(format!("{SECRETS}: {e}")))?;
            }
            continue;
        }
        entries.push((p, data));
    }
    for (p, data) in entries {
        // Only known names; never follow paths out of the state directory.
        let ok_gen = p.starts_with("generations")
            && p.components().count() == 3
            && p.components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        let dest = match p.to_str().unwrap_or_default() {
            "state.json" => Some(state_dir.join(&p)),
            // A reinstalled node keeps the identity it was installed with
            // (its management port may have a new MAC).
            "identity.json" if !state_dir.join(&p).exists() => Some(state_dir.join(&p)),
            "leases/kea-leases4.csv" => leases.map(Path::to_path_buf),
            _ if ok_gen => Some(state_dir.join(&p)),
            _ => None,
        };
        if let Some(d) = dest {
            write_atomic(&d, &data).map_err(|e| Error::io(&d, e))?;
        }
    }
    // Whatever was pending at backup time is not pending now.
    let st = State {
        rejected: None,
        active: m.active,
        confirmed: m.active,
        pending: None,
        link_decision: None,
    };
    let mut data = serde_json::to_vec_pretty(&st).expect("json");
    data.push(b'\n');
    let p = state_dir.join("state.json");
    write_atomic(&p, &data).map_err(|e| Error::io(&p, e))?;
    Ok((m, secrets))
}
