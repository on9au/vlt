pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a vault file")]
    BadMagic,

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),

    #[error("vault header is corrupt")]
    Corrupt,

    #[error("KDF parameters are out of range")]
    BadKdfParams,

    /// Deliberately doesn't say whether the file was tampered with or the
    /// password was wrong: from the crypto's point of view they're identical.
    #[error("wrong password or recovery key (or the vault was modified)")]
    BadCredential,

    /// The credential was right, but the header MAC failed: something
    /// edited the file (a different slot, the KDF params, the vault id...).
    #[error("vault header failed its integrity check: the file was modified or corrupted")]
    Tampered,

    #[error("malformed recovery key")]
    BadRecoveryKey,

    #[error("a file already exists at that path")]
    AlreadyExists,
}
