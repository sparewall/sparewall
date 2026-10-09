//! Configuration generations on disk (design: "Configuration lifecycle").
//!
//! ```text
//! <state>/generations/<id>/meta.json       Generation metadata
//! <state>/generations/<id>/document.json   The canonical document
//! <state>/generations/<id>/rendered.json   Rendered files and metadata
//! <state>/state.json                       Which generation is live
//! <state>/identity.json                    Install-time node identity
//! ```
//!
//! Generation 0 is bootstrap mode; it has no document and is rendered from
//! the identity whenever it is needed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sparewall_config::Document;
use sparewall_config::identity::Identity;
use sparewall_render::Rendered;

use crate::Error;

/// One numbered configuration change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub id: u64,
    /// SHA-256 of the canonical document.
    pub hash: String,
    /// The generation this one was derived from.
    pub base: Option<u64>,
    pub schema: u32,
    pub author: String,
    /// When it was created (RFC 3339).
    pub created: String,
    /// One line per changed path.
    #[serde(default)]
    pub summary: Vec<String>,
}

/// A change waiting for `Confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: u64,
    /// Generation to return to if the window expires.
    pub revert_to: u64,
    /// Unix time (seconds) the window closes.
    pub deadline: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The generation that is live (confirmed or pending).
    pub active: u64,
    /// The newest confirmed generation.
    pub confirmed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}

pub struct Store {
    root: PathBuf,
}

/// Write a file atomically: temp file, fsync, rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().expect("absolute path");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    let text = fs::read(path).map_err(|e| Error::io(path, e))?;
    serde_json::from_slice(&text).map_err(|e| Error::Internal(format!("{}: {e}", path.display())))
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<(), Error> {
    let mut data = serde_json::to_vec_pretty(v).expect("serializable");
    data.push(b'\n');
    write_atomic(path, &data).map_err(|e| Error::io(path, e))
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Store, Error> {
        let root = root.into();
        fs::create_dir_all(root.join("generations")).map_err(|e| Error::io(&root, e))?;
        Ok(Store { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn gen_dir(&self, id: u64) -> PathBuf {
        self.root.join("generations").join(id.to_string())
    }

    pub fn state(&self) -> Result<State, Error> {
        let p = self.root.join("state.json");
        if p.exists() {
            read_json(&p)
        } else {
            Ok(State::default())
        }
    }

    pub fn set_state(&self, s: &State) -> Result<(), Error> {
        write_json(&self.root.join("state.json"), s)
    }

    pub fn identity(&self) -> Result<Option<Identity>, Error> {
        let p = self.root.join("identity.json");
        if p.exists() {
            read_json(&p).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn set_identity(&self, id: &Identity) -> Result<(), Error> {
        write_json(&self.root.join("identity.json"), id)
    }

    /// All stored generation ids, ascending (bootstrap excluded).
    pub fn ids(&self) -> Result<Vec<u64>, Error> {
        let dir = self.root.join("generations");
        let mut ids: Vec<u64> = fs::read_dir(&dir)
            .map_err(|e| Error::io(&dir, e))?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|id| self.gen_dir(*id).join("meta.json").exists())
            .collect();
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn next_id(&self) -> Result<u64, Error> {
        Ok(self.ids()?.last().copied().unwrap_or(0) + 1)
    }

    pub fn exists(&self, id: u64) -> bool {
        self.gen_dir(id).join("meta.json").exists()
    }

    /// Save a generation. `meta.json` is written last, so a crash midway
    /// leaves no half-visible generation.
    pub fn save(&self, g: &Generation, doc: &Document, rendered: &Rendered) -> Result<(), Error> {
        let dir = self.gen_dir(g.id);
        if dir.join("meta.json").exists() {
            return Err(Error::Internal(format!(
                "generation {} already exists",
                g.id
            )));
        }
        let canonical = sparewall_config::export(doc, sparewall_config::Format::Json);
        write_atomic(&dir.join("document.json"), canonical.as_bytes())
            .map_err(|e| Error::io(&dir, e))?;
        write_json(&dir.join("rendered.json"), rendered)?;
        write_json(&dir.join("meta.json"), g)
    }

    pub fn meta(&self, id: u64) -> Result<Generation, Error> {
        if !self.exists(id) {
            return Err(Error::NotFound(id));
        }
        read_json(&self.gen_dir(id).join("meta.json"))
    }

    pub fn document(&self, id: u64) -> Result<Document, Error> {
        if !self.exists(id) {
            return Err(Error::NotFound(id));
        }
        let p = self.gen_dir(id).join("document.json");
        let text = fs::read_to_string(&p).map_err(|e| Error::io(&p, e))?;
        sparewall_config::parse(&text, sparewall_config::Format::Json)
            .map_err(|e| Error::Internal(format!("{}: {e}", p.display())))
    }

    pub fn rendered(&self, id: u64) -> Result<Rendered, Error> {
        if !self.exists(id) {
            return Err(Error::NotFound(id));
        }
        read_json(&self.gen_dir(id).join("rendered.json"))
    }

    /// Replace a generation's rendering (after an image upgrade changes
    /// what the renderers produce for the same document).
    pub fn set_rendered(&self, id: u64, r: &Rendered) -> Result<(), Error> {
        write_json(&self.gen_dir(id).join("rendered.json"), r)
    }

    /// Delete the oldest generations beyond `keep`, never touching the
    /// ones listed in `protect`.
    pub fn prune(&self, keep: usize, protect: &[u64]) -> Result<Vec<u64>, Error> {
        let ids = self.ids()?;
        let mut removed = Vec::new();
        if ids.len() <= keep {
            return Ok(removed);
        }
        for id in &ids[..ids.len() - keep] {
            if protect.contains(id) {
                continue;
            }
            let d = self.gen_dir(*id);
            fs::remove_dir_all(&d).map_err(|e| Error::io(&d, e))?;
            removed.push(*id);
        }
        Ok(removed)
    }
}
