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
use std::sync::Mutex;

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: u64,
    /// Generation to return to if the window expires.
    pub revert_to: u64,
    /// Unix time (seconds) the window closes.
    pub deadline: i64,
    /// Pushed by the peer, which confirms it over the sync tunnel once it
    /// runs here (see `Coordinator::confirm_received`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_peer: bool,
    /// What already failed before it was activated, per resource (`link
    /// wan`, `service …`, `check nft`): confirming a pushed generation
    /// requires that nothing else fails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_before: Vec<String>,
}

/// A generation from the peer that failed to activate, or was reverted
/// unconfirmed. It is not taken again until a newer generation or an
/// explicit `sync` replaces it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejected {
    pub id: u64,
    pub hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The generation that is live (confirmed or pending).
    pub active: u64,
    /// The newest confirmed generation.
    pub confirmed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected: Option<Rejected>,
}

pub struct Store {
    root: PathBuf,
    /// Tests: decides, per directory about to be synced, whether that
    /// sync fails (`EIO`), to inject faults at each durability boundary.
    sync_faults: Mutex<Option<SyncFaults>>,
}

type SyncFaults = Box<dyn FnMut(&Path) -> bool + Send>;

/// Write a file atomically and durably: temp file, fsync, rename, then
/// fsync the directory so the rename survives a power loss (and its
/// parent too if the directory is new).
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, data, &mut sync_dir).map_err(|f| f.error)
}

/// A failed [`write_atomic`]: `replaced` once the rename put the new
/// content in place (only syncing the directory failed), so readers see
/// it, though it may not survive a power loss.
pub struct WriteFailure<E = std::io::Error> {
    pub replaced: bool,
    pub error: E,
}

fn write_atomic_with(
    path: &Path,
    data: &[u8],
    sync_dir: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> Result<(), WriteFailure> {
    let before = |error| WriteFailure {
        replaced: false,
        error,
    };
    write_new(path, data, sync_dir).map_err(before)?;
    let dir = path.parent().expect("absolute path");
    sync_dir(dir).map_err(|error| WriteFailure {
        replaced: true,
        error,
    })
}

/// [`write_atomic_with`] up to the rename.
fn write_new(
    path: &Path,
    data: &[u8],
    sync_dir: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let dir = path.parent().expect("absolute path");
    let created = !dir.exists();
    fs::create_dir_all(dir)?;
    if created && let Some(parent) = dir.parent() {
        sync_dir(parent)?;
    }
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

/// fsync a directory, making the entries just created, renamed or
/// removed in it durable.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    let text = fs::read(path).map_err(|e| Error::io(path, e))?;
    serde_json::from_slice(&text).map_err(|e| Error::Internal(format!("{}: {e}", path.display())))
}

fn to_json<T: Serialize>(v: &T) -> Vec<u8> {
    let mut data = serde_json::to_vec_pretty(v).expect("serializable");
    data.push(b'\n');
    data
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Store, Error> {
        let root = root.into();
        fs::create_dir_all(root.join("generations")).map_err(|e| Error::io(&root, e))?;
        Ok(Store {
            root,
            sync_faults: Mutex::new(None),
        })
    }

    /// Tests: make the directory syncs `fail` picks return `EIO`.
    pub fn inject_sync_faults(&self, fail: impl FnMut(&Path) -> bool + Send + 'static) {
        *self.sync_faults.lock().unwrap_or_else(|p| p.into_inner()) = Some(Box::new(fail));
    }

    fn sync(&self, dir: &Path) -> std::io::Result<()> {
        if let Some(fail) = self
            .sync_faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
            && fail(dir)
        {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        sync_dir(dir)
    }

    fn write(&self, path: &Path, data: &[u8]) -> Result<(), Error> {
        self.try_write(path, data).map_err(|f| f.error)
    }

    fn try_write(&self, path: &Path, data: &[u8]) -> Result<(), WriteFailure<Error>> {
        write_atomic_with(path, data, &mut |d| self.sync(d)).map_err(|f| WriteFailure {
            replaced: f.replaced,
            error: Error::io(path, f.error),
        })
    }

    fn write_json<T: Serialize>(&self, path: &Path, v: &T) -> Result<(), Error> {
        self.write(path, &to_json(v))
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
        self.try_set_state(s).map_err(|f| f.error)
    }

    /// [`Self::set_state`], telling a failure that left the previous
    /// record in place from one after the new record replaced it.
    pub fn try_set_state(&self, s: &State) -> Result<(), WriteFailure<Error>> {
        self.try_write(&self.root.join("state.json"), &to_json(s))
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
        self.write_json(&self.root.join("identity.json"), id)
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
        self.write(&dir.join("document.json"), canonical.as_bytes())?;
        self.write_json(&dir.join("rendered.json"), rendered)?;
        self.write_json(&dir.join("meta.json"), g)?;
        self.sync_generation(g.id)
    }

    /// Make a stored generation durable: its directory's entries and its
    /// own entry in `generations/`. Done whether or not an earlier sync
    /// succeeded (a file that exists may not have reached the disk), so
    /// a generation is durable before any state record names it.
    pub fn sync_generation(&self, id: u64) -> Result<(), Error> {
        for dir in [self.gen_dir(id), self.root.join("generations")] {
            self.sync(&dir).map_err(|e| Error::io(&dir, e))?;
        }
        Ok(())
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
        self.write_json(&self.gen_dir(id).join("rendered.json"), r)
    }

    /// Move a generation out of the numbered sequence (kept on disk as
    /// `generations/<id>.<why>-<hash>`, with a counter if that is taken),
    /// freeing its id: for the peer's generation (`diverged`), or after
    /// it failed to run (`failed`).
    pub fn set_aside(&self, id: u64, why: &str) -> Result<PathBuf, Error> {
        let g = self.meta(id)?;
        let base = format!("{id}.{why}-{}", &g.hash[..g.hash.len().min(12)]);
        let dir = self.root.join("generations");
        let to = (0..)
            .map(|n| match n {
                0 => dir.join(&base),
                n => dir.join(format!("{base}.{n}")),
            })
            .find(|p| !p.exists())
            .expect("a free name");
        fs::rename(self.gen_dir(id), &to).map_err(|e| Error::io(&to, e))?;
        self.sync(&dir).map_err(|e| Error::io(&dir, e))?;
        Ok(to)
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
