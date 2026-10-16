//! filesystem helpers

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::{Error, Result, header};

// TODO: TOCTOU between the metadata check and the read; the file can grow in
// between. Read through `File::take(MAX_HEADER_LEN + 1)` and check the length.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    if fs::metadata(path)?.len() > header::MAX_HEADER_LEN {
        return Err(Error::Corrupt);
    }
    Ok(fs::read(path)?)
}

/// `.name.tmp` next to the target, so the final rename never crosses filesystems.
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
}

pub fn write_tmp(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let tmp = tmp_path(path);
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(tmp)
}

/// fsync the directory so the rename/link itself survives a power cut.
pub fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::File;

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

/// Create-only: hard_link fails if the target exists, so there's no
/// check-then-write race and no way to clobber an existing vault.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = write_tmp(path, bytes)?;
    let linked = fs::hard_link(&tmp, path);
    fs::remove_file(&tmp)?;
    match linked {
        Ok(()) => sync_parent(path),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::AlreadyExists),
        Err(e) => Err(e.into()),
    }
}

/// Write temp, fsync, rename over the original. A crash leaves either the old
/// header or the new one, never half of each.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = write_tmp(path, bytes)?;
    fs::rename(&tmp, path)?;
    sync_parent(path)
}
