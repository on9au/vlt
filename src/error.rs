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

    /// Wrong id, truncated, reordered, spliced or modified: from the crypto's
    /// point of view these are all the same.
    #[error("encrypted object is corrupt or was modified")]
    BadObject,

    #[error("a file already exists at that path")]
    AlreadyExists,

    /// Several slots fit and picking one silently would be a guess. Holds
    /// the choices, formatted for the user.
    #[error("more than one password slot fits; choose one of: {0}")]
    SlotRequired(String),

    #[error("no such slot")]
    NoSuchSlot,

    #[error("that slot is the wrong kind for this operation")]
    WrongSlotKind,

    /// An edit would produce a header we'd refuse to read back.
    #[error("{0}")]
    Limit(&'static str),
}
