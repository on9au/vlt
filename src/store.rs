//! A vault on disk: a directory holding the header, the manifest and the
//! encrypted objects.
//!
//! ```text
//! my.vault/
//!   header              keyslots (see `header`)
//!   manifest            encrypted index (see `manifest`)
//!   objects/3f/3fa9…    one encrypted object per file (see `object`)
//! ```
//!
//! Write ordering keeps the manifest from ever pointing at a missing object:
//! adding writes the object before the manifest, removing updates the
//! manifest before deleting the object. A crash can leave an orphaned
//! object behind, never a dangling entry.

use std::{
    fs::{self as stdfs, File},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    Error, Result,
    crypto::RecoveryKey,
    fs,
    header::KdfParams,
    manifest::{self, Entry, Listing, Manifest},
    object::{self, Encryptor, ObjectId},
    ops,
    vault::Vault,
};

const HEADER: &str = "header";
const MANIFEST: &str = "manifest";
const OBJECTS: &str = "objects";

/// Where the keyslot header of the vault at `root` lives.
pub fn header_path(root: &Path) -> PathBuf {
    root.join(HEADER)
}

/// An unlocked vault directory.
pub struct Store {
    root: PathBuf,
    vault: Vault,
    manifest: Manifest,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.root)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// Create a vault directory at `root`, which must not exist yet. The
/// recovery key is returned exactly once.
pub fn init(
    root: impl AsRef<Path>,
    password: &[u8],
    kdf: KdfParams,
) -> Result<(Store, RecoveryKey)> {
    let root = root.as_ref().to_path_buf();
    fs::create_private_dir(&root)?;
    fs::create_private_dir(&root.join(OBJECTS))?;
    let (vault, recovery) = ops::init(header_path(&root), password, kdf)?;
    let manifest = Manifest::default();
    fs::write_new(&root.join(MANIFEST), &manifest.seal(&vault))?;
    Ok((
        Store {
            root,
            vault,
            manifest,
        },
        recovery,
    ))
}

impl Store {
    /// `vault` must have been unlocked from `header_path(root)`; anything
    /// else won't decrypt the manifest.
    pub fn open(root: impl AsRef<Path>, vault: Vault) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let bytes = fs::read_capped(
            &root.join(MANIFEST),
            manifest::MAX_MANIFEST_LEN,
            Error::BadManifest,
        )?;
        let manifest = Manifest::open(&vault, &bytes)?;
        Ok(Self {
            root,
            vault,
            manifest,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn list(&self, dir: &str) -> Result<Vec<Listing<'_>>> {
        self.manifest.list(&manifest::dir_path(dir)?)
    }

    /// Encrypt `src` into the vault at `path`. Refuses to overwrite unless
    /// `replace`; the replaced object is deleted once the manifest no longer
    /// points at it. Returns the plaintext size.
    pub fn add(&mut self, path: &str, src: impl Read, replace: bool) -> Result<u64> {
        let path = manifest::file_path(path)?;
        // Fail before encrypting anything, so a bad path leaves no orphan.
        self.manifest.check_insert(&path, replace)?;

        let enc = Encryptor::new(&self.vault);
        let id = enc.id();
        let object = self.object_path(&id);
        fs::ensure_private_dir(object.parent().expect("objects/xx/<id>"))?;
        let size = fs::stream_new(&object, |w| enc.encrypt(src, w))?;

        let mut next = self.manifest.clone();
        let old = next.insert(path, Entry { object: id, size }, replace)?;
        if let Err(e) = self.save(next) {
            let _ = stdfs::remove_file(&object);
            return Err(e);
        }
        if let Some(old) = old {
            self.delete_object(&old.object);
        }
        Ok(size)
    }

    /// Decrypt `path` into `dst`. Streams, so on `Err` whatever reached `dst`
    /// is an incomplete prefix: see `get_to_file` for the safe version.
    pub fn get(&self, path: &str, dst: impl Write) -> Result<u64> {
        let entry = *self
            .manifest
            .get(&manifest::file_path(path)?)
            .ok_or(Error::NoSuchPath)?;
        let src = BufReader::new(File::open(self.object_path(&entry.object))?);
        let size = object::decrypt(&self.vault, &entry.object, src, dst)?;
        if size != entry.size {
            return Err(Error::BadObject);
        }
        Ok(size)
    }

    /// Decrypt `path` to a new file at `dest`. Refuses to overwrite, and
    /// `dest` only appears once the whole object has authenticated.
    pub fn get_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        fs::stream_new(dest, |w| self.get(path, w))
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        let mut next = self.manifest.clone();
        let old = next.remove(&manifest::file_path(path)?)?;
        self.save(next)?;
        self.delete_object(&old.object);
        Ok(())
    }

    // TODO: no file lock around the manifest's read-modify-write. Two
    // concurrent `add`s both succeed and the last write wins (the loser's
    // object is orphaned).
    fn save(&mut self, next: Manifest) -> Result<()> {
        fs::replace_file(&self.root.join(MANIFEST), &next.seal(&self.vault))?;
        self.manifest = next;
        Ok(())
    }

    /// Best effort: the manifest no longer points here, so a failure only
    /// leaves an orphan, not an inconsistency.
    fn delete_object(&self, id: &ObjectId) {
        let path = self.object_path(id);
        let _ = stdfs::remove_file(&path);
        // Only succeeds once the fan-out dir is empty.
        let _ = stdfs::remove_dir(path.parent().expect("objects/xx/<id>"));
    }

    /// `objects/<first byte>/<id>`, so no single directory gets huge.
    fn object_path(&self, id: &ObjectId) -> PathBuf {
        let hex = id.to_string();
        self.root.join(OBJECTS).join(&hex[..2]).join(hex)
    }
}
