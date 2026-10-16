//! A vault on disk: a directory holding the header, the manifest and the
//! encrypted objects.
//!
//! ```text
//! my.vault/
//!   header              keyslots (see `header`)
//!   manifest            encrypted index (see `manifest`)
//!   lock                held (advisory, exclusive) while a `Store` is open
//!   objects/3f/3fa9…    one encrypted object per file (see `object`)
//! ```
//!
//! Write ordering keeps the manifest from ever pointing at a missing object:
//! adding writes the object before the manifest, removing updates the
//! manifest before deleting the object. A crash can leave an orphaned
//! object behind (`gc` cleans those up), never a dangling entry.

use std::{
    collections::HashSet,
    fs::{self as stdfs, File},
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    Error, Result,
    crypto::RecoveryKey,
    fs,
    header::KdfParams,
    manifest::{self, Entry, Listing, Manifest, Mtime},
    object::{self, Encryptor, ObjectId},
    ops,
    vault::Vault,
};

const HEADER: &str = "header";
const MANIFEST: &str = "manifest";
const OBJECTS: &str = "objects";
const LOCK: &str = "lock";

/// Where the keyslot header of the vault at `root` lives.
pub fn header_path(root: &Path) -> PathBuf {
    root.join(HEADER)
}

/// Lock the vault at `root` against other `vlt` processes until the guard is
/// dropped. `Store` does this itself; take it by hand around anything else
/// that rewrites the vault (like changing a password).
pub fn lock(root: &Path) -> Result<fs::DirLock> {
    // Don't litter a `lock` file into a directory that isn't a vault.
    if !header_path(root).is_file() {
        return Err(
            io::Error::new(io::ErrorKind::NotFound, "no vault header in that directory").into(),
        );
    }
    fs::lock(&root.join(LOCK))
}

/// File metadata worth keeping.
#[derive(Debug, Clone, Copy, Default)]
pub struct Meta {
    pub mtime: Option<SystemTime>,
    /// Only the `0o777` bits are kept.
    pub mode: Option<u32>,
}

impl Meta {
    pub fn of(md: &stdfs::Metadata) -> Self {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(md.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let mode = None;
        Self {
            mtime: md.modified().ok(),
            mode,
        }
    }
}

/// An unlocked vault directory. Holds the vault's lock while it lives.
pub struct Store {
    root: PathBuf,
    vault: Vault,
    manifest: Manifest,
    _lock: fs::DirLock,
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
    let lock = fs::lock(&root.join(LOCK))?;
    let (vault, recovery) = ops::init(header_path(&root), password, kdf)?;
    let manifest = Manifest::default();
    fs::write_new(&root.join(MANIFEST), &manifest.seal(&vault))?;
    Ok((
        Store {
            root,
            vault,
            manifest,
            _lock: lock,
        },
        recovery,
    ))
}

/// What `add_tree` did.
#[derive(Debug, Default)]
pub struct TreeReport {
    pub files: usize,
    pub bytes: u64,
    /// Symlinks, special files, and names a vault path can't hold.
    /// Empty directories aren't listed: the vault has no way to store them.
    pub skipped: Vec<PathBuf>,
}

/// What `check` found (or `gc` deleted).
#[derive(Debug, Default)]
pub struct Report {
    /// Vault paths whose object file is missing. Not fixable: the data is gone.
    pub missing: Vec<String>,
    /// Objects no manifest entry points at, e.g. left by a crash.
    pub orphans: Vec<PathBuf>,
    /// Leftover temp files from interrupted writes.
    pub temps: Vec<PathBuf>,
    /// Files vlt didn't create. Reported, never deleted.
    pub unknown: Vec<PathBuf>,
    /// With `verify`: vault paths whose object failed to decrypt, and why.
    pub corrupt: Vec<(String, Error)>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.orphans.is_empty()
            && self.temps.is_empty()
            && self.unknown.is_empty()
            && self.corrupt.is_empty()
    }
}

impl Store {
    /// `vault` must have been unlocked from `header_path(root)`; anything
    /// else won't decrypt the manifest. Fails with `Error::Locked` if
    /// another process has the vault open.
    pub fn open(root: impl AsRef<Path>, vault: Vault) -> Result<Self> {
        let lock = lock(root.as_ref())?;
        Self::with_lock(root, vault, lock)
    }

    /// Like `open`, with a lock already taken by `lock(root)`, e.g. before
    /// prompting for a password so a busy vault fails fast.
    pub fn with_lock(root: impl AsRef<Path>, vault: Vault, lock: fs::DirLock) -> Result<Self> {
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
            _lock: lock,
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

    /// Stage changes; they reach the disk in one manifest write on `commit`.
    pub fn begin(&mut self) -> Tx<'_> {
        Tx {
            next: self.manifest.clone(),
            store: self,
            written: Vec::new(),
            freed: Vec::new(),
            committed: false,
        }
    }

    /// `begin` + `Tx::add` (without metadata) + `commit`.
    pub fn add(&mut self, path: &str, src: impl Read, replace: bool) -> Result<u64> {
        let mut tx = self.begin();
        let size = tx.add(path, src, Meta::default(), replace)?;
        tx.commit()?;
        Ok(size)
    }

    /// `begin` + `Tx::remove` + `commit`.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let mut tx = self.begin();
        tx.remove(path)?;
        tx.commit()
    }

    /// Decrypt `path` into `dst`. Streams, so on `Err` whatever reached `dst`
    /// is an incomplete prefix: see `get_to_file` for the safe version.
    pub fn get(&self, path: &str, dst: impl Write) -> Result<u64> {
        let entry = *self
            .manifest
            .get(&manifest::file_path(path)?)
            .ok_or(Error::NoSuchPath)?;
        self.decrypt(&entry, dst)
    }

    /// Decrypt `path` to a new file at `dest`, restoring its mtime and mode.
    /// Refuses to overwrite, and `dest` only appears once the whole object
    /// has authenticated.
    pub fn get_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let entry = *self
            .manifest
            .get(&manifest::file_path(path)?)
            .ok_or(Error::NoSuchPath)?;
        self.extract(&entry, dest)
    }

    /// Decrypt every file under `dir` (`""` for the whole vault) into a new
    /// directory `out`, keeping the layout. Refuses if `out` exists. Returns
    /// how many files and bytes were written.
    ///
    /// Stops at the first failure: the files written before it are complete
    /// and authentic, the rest are missing.
    pub fn get_tree(&self, dir: &str, out: &Path) -> Result<(usize, u64)> {
        let dir = manifest::dir_path(dir)?;
        let files: Vec<(&str, Entry)> = self
            .manifest
            .files_under(&dir)
            .map(|(rel, e)| (rel, *e))
            .collect();
        if files.is_empty() {
            return Err(Error::NoSuchPath);
        }
        fs::create_private_dir(out)?;
        let mut bytes = 0;
        for (rel, entry) in &files {
            // Vault paths have no `..`, `.` or empty components, so this
            // can't leave `out`.
            let dest: PathBuf = std::iter::once(out.as_os_str())
                .chain(rel.split('/').map(std::ffi::OsStr::new))
                .collect();
            fs::ensure_private_dir(dest.parent().expect("under out"))?;
            bytes += self.extract(entry, &dest)?;
        }
        Ok((files.len(), bytes))
    }

    /// Compare `objects/` against the manifest. With `verify`, also decrypt
    /// every object in full.
    pub fn check(&self, verify: bool) -> Result<Report> {
        let mut report = Report::default();
        let referenced: HashSet<ObjectId> =
            self.manifest.entries().map(|(_, e)| e.object).collect();
        let mut present = HashSet::new();

        for fan in sorted_dir(&self.root.join(OBJECTS))? {
            let name = file_name(&fan);
            if !is_fanout(&fan) {
                classify_stray(fan, &mut report);
                continue;
            }
            for path in sorted_dir(&fan)? {
                let id = ObjectId::from_hex(file_name(&path))
                    .filter(|id| path.is_file() && id.to_string().starts_with(name));
                match id {
                    Some(id) if referenced.contains(&id) => {
                        present.insert(id);
                    }
                    Some(_) => report.orphans.push(path),
                    None => classify_stray(path, &mut report),
                }
            }
        }
        for name in [HEADER, MANIFEST] {
            let tmp = fs::tmp_path(&self.root.join(name));
            if tmp.exists() {
                report.temps.push(tmp);
            }
        }

        for (path, entry) in self.manifest.entries() {
            if !present.contains(&entry.object) {
                report.missing.push(path.to_owned());
            } else if verify && let Err(e) = self.decrypt(entry, io::sink()) {
                report.corrupt.push((path.to_owned(), e));
            }
        }
        Ok(report)
    }

    /// Delete orphaned objects and leftover temp files, and prune empty
    /// fan-out dirs. Safe because the lock keeps every other writer out.
    /// Returns what it found; `orphans` and `temps` are what it deleted.
    pub fn gc(&mut self) -> Result<Report> {
        let report = self.check(false)?;
        for path in report.orphans.iter().chain(&report.temps) {
            stdfs::remove_file(path)?;
        }
        for fan in sorted_dir(&self.root.join(OBJECTS))? {
            // Only our own fan-out dirs, and only succeeds when empty.
            if is_fanout(&fan) {
                let _ = stdfs::remove_dir(fan);
            }
        }
        Ok(report)
    }

    fn decrypt(&self, entry: &Entry, dst: impl Write) -> Result<u64> {
        let src = BufReader::new(File::open(self.object_path(&entry.object))?);
        let size = object::decrypt(&self.vault, &entry.object, src, dst)?;
        if size != entry.size {
            return Err(Error::BadObject);
        }
        Ok(size)
    }

    fn extract(&self, entry: &Entry, dest: &Path) -> Result<u64> {
        let size = fs::stream_new(dest, |w| self.decrypt(entry, w))?;
        fs::apply_meta(dest, entry.mtime.and_then(Mtime::to_system), entry.mode)?;
        Ok(size)
    }

    fn save(&mut self, next: Manifest) -> Result<()> {
        fs::replace_file(&self.root.join(MANIFEST), &next.seal(&self.vault))?;
        self.manifest = next;
        Ok(())
    }

    /// Best effort: nothing points here any more, so a failure only leaves
    /// an orphan for `gc`, not an inconsistency.
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

/// Staged changes to a `Store`. Objects are written as you go; the manifest
/// only on `commit`, so either every change lands or none does. Dropping
/// without committing deletes the objects this transaction wrote.
#[must_use = "changes are discarded unless committed"]
pub struct Tx<'s> {
    store: &'s mut Store,
    next: Manifest,
    /// Objects this transaction wrote: deleted if it never commits.
    written: Vec<ObjectId>,
    /// Objects it unreferenced: deleted once it commits.
    freed: Vec<ObjectId>,
    committed: bool,
}

impl Tx<'_> {
    /// Encrypt `src` into the vault at `path`. Refuses to overwrite unless
    /// `replace`. Returns the plaintext size.
    pub fn add(&mut self, path: &str, src: impl Read, meta: Meta, replace: bool) -> Result<u64> {
        let path = manifest::file_path(path)?;
        // Fail before encrypting anything.
        self.next.check_insert(&path, replace)?;

        let enc = Encryptor::new(&self.store.vault);
        let id = enc.id();
        let object = self.store.object_path(&id);
        fs::ensure_private_dir(object.parent().expect("objects/xx/<id>"))?;
        let size = fs::stream_new(&object, |w| enc.encrypt(src, w))?;
        self.written.push(id);

        let entry = Entry {
            object: id,
            size,
            mtime: meta.mtime.map(Mtime::from_system),
            mode: meta.mode.map(|m| m & 0o777),
        };
        if let Some(old) = self.next.insert(path, entry, replace)? {
            self.freed.push(old.object);
        }
        Ok(size)
    }

    /// Add every regular file under `src` at `dest/<relative path>`, with
    /// its metadata. Symlinks are never followed. Every path is checked
    /// before anything is encrypted.
    pub fn add_tree(&mut self, src: &Path, dest: &str, replace: bool) -> Result<TreeReport> {
        let dest = manifest::dir_path(dest)?;
        let mut plan = Vec::new();
        let mut report = TreeReport::default();
        walk(src, &dest, &mut plan, &mut report.skipped)?;
        for (path, _, _) in &plan {
            self.next.check_insert(path, replace)?;
        }
        for (path, fs_path, meta) in plan {
            let src = BufReader::new(File::open(&fs_path)?);
            report.bytes += self.add(&path, src, meta, replace)?;
            report.files += 1;
        }
        Ok(report)
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        let old = self.next.remove(&manifest::file_path(path)?)?;
        self.freed.push(old.object);
        Ok(())
    }

    /// Remove a directory and everything under it. Returns how many files.
    pub fn remove_dir(&mut self, dir: &str) -> Result<usize> {
        let old = self.next.remove_dir(&manifest::dir_path(dir)?)?;
        self.freed.extend(old.iter().map(|e| e.object));
        Ok(old.len())
    }

    /// Rename a file or directory. Manifest-only: objects don't move.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<usize> {
        self.next
            .rename(&manifest::file_path(from)?, &manifest::file_path(to)?)
    }

    pub fn commit(mut self) -> Result<()> {
        let next = std::mem::take(&mut self.next);
        self.store.save(next)?;
        self.committed = true;
        for id in &self.freed {
            self.store.delete_object(id);
        }
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.committed {
            for id in &self.written {
                self.store.delete_object(id);
            }
        }
    }
}

/// Collect `(vault path, fs path, meta)` for every regular file under `dir`.
fn walk(
    dir: &Path,
    prefix: &str,
    plan: &mut Vec<(String, PathBuf, Meta)>,
    skipped: &mut Vec<PathBuf>,
) -> Result<()> {
    for path in sorted_dir(dir)? {
        let md = stdfs::symlink_metadata(&path)?;
        let name = path.file_name().and_then(|n| n.to_str());
        let vault_path = name.map(|n| {
            if prefix.is_empty() {
                n.to_owned()
            } else {
                format!("{prefix}/{n}")
            }
        });
        // Only names that are already valid, unchanged vault path components.
        let vault_path = vault_path.filter(|p| manifest::file_path(p).is_ok_and(|n| n == *p));
        match vault_path {
            Some(p) if md.is_dir() => walk(&path, &p, plan, skipped)?,
            Some(p) if md.is_file() => plan.push((p, path, Meta::of(&md))),
            _ => skipped.push(path),
        }
    }
    Ok(())
}

fn sorted_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = stdfs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

/// Our temp files are `.<name>.tmp`; anything else we didn't make.
fn classify_stray(path: PathBuf, report: &mut Report) {
    let name = file_name(&path);
    if path.is_file() && name.starts_with('.') && name.ends_with(".tmp") {
        report.temps.push(path);
    } else {
        report.unknown.push(path);
    }
}

/// `objects/<2 lowercase hex>/`, as `object_path` makes them.
fn is_fanout(path: &Path) -> bool {
    let name = file_name(path);
    path.is_dir() && name.len() == 2 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
