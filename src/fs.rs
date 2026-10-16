//! filesystem helpers

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{Error, Result};

/// Reads the whole file, failing with `too_long` if it's over `max` bytes.
/// Reads through `take` rather than checking the size first, so a file that
/// grows in between can't slip past the limit.
pub fn read_capped(path: &Path, max: u64, too_long: Error) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(too_long);
    }
    Ok(bytes)
}

/// `.name.tmp` next to the target, so the final rename never crosses filesystems.
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
}

/// fsync the directory so the rename/link itself survives a power cut.
pub fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Create-only: fails with `AlreadyExists` rather than clobber anything.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    stream_new(path, |w| Ok(w.write_all(bytes)?))
}

/// A crash leaves either the old file or the new one, never half of each.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    stream_replace(path, |w| Ok(w.write_all(bytes)?))
}

/// Like `write_new`, but `write` streams the contents.
pub fn stream_new<T>(path: &Path, write: impl FnOnce(&mut dyn Write) -> Result<T>) -> Result<T> {
    // hard_link fails if the target exists, so there's no check-then-write
    // race and no way to clobber an existing file.
    stream(path, write, |tmp, path| match fs::hard_link(tmp, path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(Error::AlreadyExists),
        r => Ok(r?),
    })
}

/// Like `replace_file`, but `write` streams the contents.
pub fn stream_replace<T>(
    path: &Path,
    write: impl FnOnce(&mut dyn Write) -> Result<T>,
) -> Result<T> {
    stream(path, write, |tmp, path| Ok(fs::rename(tmp, path)?))
}

/// Write a fresh temp, fsync it, `publish` it to `path`, fsync the directory.
/// The temp is gone afterwards whether this succeeds or not.
///
/// The temp is always new: a leftover one (from a crash, or planted) is
/// removed first and the new one is opened `create_new`, so we never follow
/// a symlink or inherit a stale file's permissions.
fn stream<T>(
    path: &Path,
    write: impl FnOnce(&mut dyn Write) -> Result<T>,
    publish: impl FnOnce(&Path, &Path) -> Result<()>,
) -> Result<T> {
    let tmp = tmp_path(path);
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&tmp)?;

    let result = (|| {
        let mut w = BufWriter::new(file);
        let value = write(&mut w)?;
        let file = w.into_inner().map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        publish(&tmp, path)?;
        sync_parent(path)?;
        Ok(value)
    })();

    // After a rename the temp is already gone; after a hard link or a
    // failure it isn't.
    match (result, fs::remove_file(&tmp)) {
        (Ok(_), Err(e)) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        (result, _) => result,
    }
}

/// Create a directory only we can read; `AlreadyExists` if it's there.
pub fn create_private_dir(path: &Path) -> Result<()> {
    match private_dir_builder().create(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(Error::AlreadyExists),
        r => Ok(r?),
    }
}

/// Like `create_private_dir`, but fine if it already exists.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    Ok(private_dir_builder().recursive(true).create(path)?)
}

fn private_dir_builder() -> fs::DirBuilder {
    #[allow(unused_mut)]
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b
}

/// Set mtime, then permissions (in that order, so a read-only mode can't
/// stop us setting the time). Either may be absent.
pub fn apply_meta(path: &Path, mtime: Option<SystemTime>, mode: Option<u32>) -> Result<()> {
    if let Some(t) = mtime {
        OpenOptions::new().write(true).open(path)?.set_modified(t)?;
    }
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

/// An exclusive lock on a vault directory, held until dropped. Advisory: it
/// only keeps other `vlt` processes out.
#[derive(Debug)]
pub struct DirLock(#[allow(dead_code)] File);

/// Take the lock at `path` (creating the file if needed) without waiting:
/// `Error::Locked` if another process holds it.
pub fn lock(path: &Path) -> Result<DirLock> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(DirLock(file)),
        Err(fs::TryLockError::WouldBlock) => Err(Error::Locked),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}
