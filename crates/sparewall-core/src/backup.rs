//! The backup bundle (design: "Backup and restore").
//!
//! One `.tar.gz` per node holding the active document, the newest
//! generations, a DHCP lease export, the running image digest and the
//! node's identity. Node private keys are never included: a rebuilt node
//! generates new ones and is re-paired.

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
use crate::store::{State, write_atomic};
use crate::system::System;

/// Bundle format version.
pub const FORMAT: u32 = 1;
/// Generations included by default.
pub const DEFAULT_GENERATIONS: usize = 20;

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
}

/// Where the bundle sources live on a node.
pub struct Sources {
    /// Kea's lease file.
    pub leases: PathBuf,
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
        let leases = fs::read(&src.leases).ok();
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
            if state.active != 0 {
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

/// Restore a bundle into a state directory (with sparewalld stopped,
/// before services first start). The generation that was active becomes
/// active and confirmed; the lease file goes to `leases` if given.
pub fn restore(bundle: &Path, state_dir: &Path, leases: Option<&Path>) -> Result<Manifest, Error> {
    let m = manifest(bundle)?;
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
    let f = fs::File::open(bundle).map_err(|e| Error::io(bundle, e))?;
    let mut ar = tar::Archive::new(GzDecoder::new(f));
    for e in ar.entries().map_err(|e| Error::Internal(e.to_string()))? {
        let mut e = e.map_err(|e| Error::Internal(e.to_string()))?;
        let p = e
            .path()
            .map_err(|e| Error::Internal(e.to_string()))?
            .into_owned();
        // Only known names; never follow paths out of the state directory.
        let ok_gen = p.starts_with("generations")
            && p.components().count() == 3
            && p.components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        let mut data = Vec::new();
        e.read_to_end(&mut data)
            .map_err(|e| Error::Internal(e.to_string()))?;
        let dest = match p.to_str().unwrap_or_default() {
            "state.json" | "identity.json" => Some(state_dir.join(&p)),
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
        active: m.active,
        confirmed: m.active,
        pending: None,
    };
    let mut data = serde_json::to_vec_pretty(&st).expect("json");
    data.push(b'\n');
    let p = state_dir.join("state.json");
    write_atomic(&p, &data).map_err(|e| Error::io(&p, e))?;
    Ok(m)
}
