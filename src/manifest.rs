//! The manifest: an encrypted index from vault paths to objects. File names
//! and directory structure live only in here, so on disk a vault shows just
//! how many objects it holds and roughly how big they are.
//!
//! Layout:
//!
//! ```text
//! MAGIC ([u8; 8]) || FORMAT_VERSION (u16 LE) || nonce ([u8; 24]) || ciphertext || tag (16)
//! ciphertext = XChaCha20-Poly1305(key, nonce, aad = MAGIC || version, postcard(Manifest))
//! key = HKDF(MK, "vlt v1 manifest")
//! ```
//!
//! A fresh random nonce per write. Rewritten whole, atomically, on every change.
//!
//! Vault paths are `/`-separated UTF-8 with no empty, `.` or `..`
//! components, so nothing extracted from a vault can escape its target.
//! Directories are implicit: `a/b` exists as a directory as long as some
//! file lives under it.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{self, random_bytes},
    object::ObjectId,
    vault::Vault,
};

pub const MAGIC: [u8; 8] = *b"VLTmani\0";
pub const FORMAT_VERSION: u16 = 1;
/// Upper bound on the encrypted manifest, read into memory before it can
/// be authenticated.
pub const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;
pub const MAX_PATH_LEN: usize = 4096;

const PREFIX_LEN: usize = MAGIC.len() + size_of::<u16>();
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub object: ObjectId,
    /// Plaintext size
    pub size: u64,
    /// When the file was last modified, if known.
    pub mtime: Option<Mtime>,
    /// Permission bits (`0o777` at most), if known. setuid/setgid/sticky are
    /// never stored, so extracting can't create a setuid binary.
    pub mode: Option<u32>,
}

/// A point in time relative to the Unix epoch (`secs` may be negative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mtime {
    pub secs: i64,
    pub nanos: u32,
}

impl Mtime {
    pub fn from_system(t: SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Self {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                // Before the epoch: floor to whole seconds, nanos counting up.
                let d = e.duration();
                let (secs, nanos) = match d.subsec_nanos() {
                    0 => (-(d.as_secs() as i64), 0),
                    n => (-(d.as_secs() as i64) - 1, 1_000_000_000 - n),
                };
                Self { secs, nanos }
            }
        }
    }

    pub fn to_system(self) -> Option<SystemTime> {
        let base = if self.secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_secs(self.secs as u64))?
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(self.secs.unsigned_abs()))?
        };
        base.checked_add(Duration::from_nanos(self.nanos.into()))
    }
}

/// One line of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing<'a> {
    File { name: &'a str, size: u64 },
    Dir { name: &'a str },
}

impl Manifest {
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.entries.iter().map(|(p, e)| (p.as_str(), e))
    }

    /// Whether `insert(path, _, replace)` would succeed. Lets callers fail
    /// before doing expensive work (like encrypting the file).
    pub fn check_insert(&self, path: &str, replace: bool) -> Result<()> {
        // Normalized paths are checked already; this catches ones built by
        // `rename` from a long prefix.
        if path.len() > MAX_PATH_LEN {
            return Err(Error::BadPath("path too long"));
        }
        if self.entries.contains_key(path) {
            return if replace {
                Ok(())
            } else {
                Err(Error::PathExists)
            };
        }
        // A file can't also be a directory, either way round.
        if ancestors(path).any(|a| self.entries.contains_key(a)) {
            return Err(Error::BadPath("a parent of this path is a file"));
        }
        if self.children(path).next().is_some() {
            return Err(Error::PathExists);
        }
        Ok(())
    }

    /// Add or (with `replace`) overwrite a file. Returns the entry it replaced.
    pub fn insert(&mut self, path: String, entry: Entry, replace: bool) -> Result<Option<Entry>> {
        self.check_insert(&path, replace)?;
        Ok(self.entries.insert(path, entry))
    }

    pub fn remove(&mut self, path: &str) -> Result<Entry> {
        self.entries.remove(path).ok_or(Error::NoSuchPath)
    }

    /// Remove every file under directory `dir`. Refuses the root.
    pub fn remove_dir(&mut self, dir: &str) -> Result<Vec<Entry>> {
        if dir.is_empty() {
            return Err(Error::BadPath("refusing to remove the whole vault"));
        }
        let paths: Vec<String> = self.children(dir).map(|(p, _)| p.to_owned()).collect();
        if paths.is_empty() {
            return Err(Error::NoSuchPath);
        }
        Ok(paths
            .iter()
            .map(|p| self.entries.remove(p).expect("just listed"))
            .collect())
    }

    /// Rename a file, or a directory with everything under it. `to` must not
    /// exist yet: nothing is ever merged or overwritten. All or nothing.
    /// Returns how many files moved.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<usize> {
        if from.is_empty() || to.is_empty() {
            return Err(Error::BadPath("can't move the root"));
        }
        if to == from || to.starts_with(&format!("{from}/")) {
            return Err(Error::BadPath("can't move something into itself"));
        }
        let moving: Vec<(String, Entry)> = match self.entries.get(from) {
            Some(e) => vec![(from.to_owned(), *e)],
            None => self
                .children(from)
                .map(|(p, e)| (p.to_owned(), *e))
                .collect(),
        };
        if moving.is_empty() {
            return Err(Error::NoSuchPath);
        }
        // Checked up front for a clear error; the inserts below would catch
        // it too, but as "a parent is a file" when `to` is a file.
        if self.entries.contains_key(to) || self.children(to).next().is_some() {
            return Err(Error::PathExists);
        }
        let mut next = self.clone();
        for (path, _) in &moving {
            next.entries.remove(path);
        }
        for (path, entry) in &moving {
            next.insert(format!("{to}{}", &path[from.len()..]), *entry, false)?;
        }
        *self = next;
        Ok(moving.len())
    }

    /// Every file under directory `dir` (`""` for all), with its path
    /// relative to `dir`.
    pub fn files_under<'a>(&'a self, dir: &str) -> impl Iterator<Item = (&'a str, &'a Entry)> {
        let skip = if dir.is_empty() { 0 } else { dir.len() + 1 };
        self.children(dir).map(move |(p, e)| (&p[skip..], e))
    }

    /// Immediate children of directory `dir` (`""` for the root), or the
    /// file itself if `dir` names one.
    pub fn list(&self, dir: &str) -> Result<Vec<Listing<'_>>> {
        if let Some((name, e)) = self.entries.get_key_value(dir) {
            return Ok(vec![Listing::File { name, size: e.size }]);
        }
        let mut out: Vec<Listing> = Vec::new();
        for (path, e) in self.children(dir) {
            let rest = if dir.is_empty() {
                path
            } else {
                &path[dir.len() + 1..]
            };
            match rest.split_once('/') {
                Some((sub, _)) => {
                    // Sorted keys keep a directory's files together, so a
                    // duplicate can only ever be the previous line.
                    if out.last() != Some(&Listing::Dir { name: sub }) {
                        out.push(Listing::Dir { name: sub });
                    }
                }
                None => out.push(Listing::File {
                    name: rest,
                    size: e.size,
                }),
            }
        }
        if out.is_empty() && !dir.is_empty() {
            return Err(Error::NoSuchPath);
        }
        Ok(out)
    }

    /// Everything under directory `dir`, in key order.
    fn children<'a>(&'a self, dir: &str) -> impl Iterator<Item = (&'a str, &'a Entry)> {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        self.entries
            .range(prefix.clone()..)
            .take_while(move |(p, _)| p.starts_with(&prefix))
            .map(|(p, e)| (p.as_str(), e))
    }

    pub fn seal(&self, vault: &Vault) -> Vec<u8> {
        let plaintext = Zeroizing::new(
            postcard::to_allocvec(self).expect("manifest serialization is infallible"),
        );
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let mut out = Vec::with_capacity(PREFIX_LEN + NONCE_LEN + plaintext.len() + 16);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        let ciphertext = crypto::seal(&key(vault), &nonce, &out, &plaintext);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn open(vault: &Vault, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PREFIX_LEN || bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::BadManifest);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let (aad, rest) = bytes.split_at(PREFIX_LEN);
        let Some((nonce, ciphertext)) = rest.split_first_chunk::<NONCE_LEN>() else {
            return Err(Error::BadManifest);
        };
        let plaintext =
            crypto::open(&key(vault), nonce, aad, ciphertext).ok_or(Error::BadManifest)?;
        let (manifest, rest) =
            postcard::take_from_bytes(&plaintext).map_err(|_| Error::BadManifest)?;
        if !rest.is_empty() {
            return Err(Error::BadManifest);
        }
        Ok(manifest)
    }
}

fn key(vault: &Vault) -> crypto::SecretKey {
    vault.derive_key(&[b"vlt v1 manifest"])
}

/// `a/b/c` -> `a`, `a/b`
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// Normalize a path naming a file: leading/trailing `/` dropped, must not
/// be empty.
pub fn file_path(path: &str) -> Result<String> {
    let p = dir_path(path)?;
    if p.is_empty() {
        return Err(Error::BadPath("empty path"));
    }
    Ok(p)
}

/// Normalize a path naming a directory; `""` (or `/`) is the root.
pub fn dir_path(path: &str) -> Result<String> {
    let p = path.trim_matches('/');
    if p.len() > MAX_PATH_LEN {
        return Err(Error::BadPath("path too long"));
    }
    if p.is_empty() {
        return Ok(String::new());
    }
    for c in p.split('/') {
        match c {
            "" => return Err(Error::BadPath("empty path component")),
            "." | ".." => return Err(Error::BadPath("`.` and `..` aren't allowed")),
            // `\` would be a separator when extracting on Windows.
            _ if c.contains(['\\', '\0']) => {
                return Err(Error::BadPath("`\\` and NUL aren't allowed"));
            }
            _ => {}
        }
    }
    Ok(p.to_owned())
}
