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

use std::collections::BTreeMap;

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
