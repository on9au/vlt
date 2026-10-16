//! Vault

use std::path::{Path, PathBuf};

use crate::{
    Error, Result,
    crypto::{self, KEY_LEN, RecoveryKey, SecretKey, random_bytes, random_key},
    fs,
    header::{self, Header, KdfParams, KeySlot, SlotKind},
};

/// An unlocked vault. Holds MK in memory (zeroized)
pub struct Vault {
    path: PathBuf,
    header: Header,
    mk: SecretKey,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &hex::encode(self.header.vault_id))
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new vault. Refuses to overwrite anything. The recovery key is
    /// returned exactly once: if the caller drops it, it's gone.
    pub fn init(
        path: impl AsRef<Path>,
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<(Self, RecoveryKey)> {
        kdf.check()?;
        let path = path.as_ref().to_path_buf();
        let recovery = RecoveryKey::generate();
        let mut vault = Self {
            path,
            header: Header {
                vault_id: random_bytes(),
                kdf,
                slots: Vec::new(),
            },
            mk: random_key(),
        };
        let pw_slot = vault.password_slot(password)?;
        let rk_slot = vault.recovery_slot(&recovery);
        vault.header.slots = vec![pw_slot, rk_slot];
        fs::write_new(&vault.path, &vault.serialize(&vault.header))?;
        Ok((vault, recovery))
    }

    #[cfg(test)]
    pub(crate) fn new_test(path: impl AsRef<Path>, header: Header, mk: SecretKey) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            header,
            mk,
        }
    }

    pub fn unlock(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        Self::open_with(path.as_ref(), SlotKind::Password, |slot, kdf| {
            crypto::password_kek(password, &slot.salt, kdf)
        })
    }

    /// Requires the old password *every time*, never a cached one. An
    /// unlocked session on its own is not enough to change credentials.
    pub fn change_password(path: impl AsRef<Path>, old: &[u8], new: &[u8]) -> Result<Self> {
        let mut vault = Self::unlock(path, old)?;
        let slot = vault.password_slot(new)?;
        vault.replace_slot(slot)?;
        Ok(vault)
    }

    /// Forgot the password: open with the recovery key and set a new password.
    /// The recovery key stays valid (rotate it separately if it leaked).
    pub fn recover(
        path: impl AsRef<Path>,
        recovery: &RecoveryKey,
        new_password: &[u8],
    ) -> Result<Self> {
        let mut vault = Self::open_with(path.as_ref(), SlotKind::Recovery, |slot, _| {
            Ok(crypto::recovery_kek(recovery, &slot.salt))
        })?;
        let slot = vault.password_slot(new_password)?;
        vault.replace_slot(slot)?;
        Ok(vault)
    }

    /// Lost the paper, or think someone saw it: issue a new recovery key.
    /// The old one stops working immediately.
    pub fn rotate_recovery(path: impl AsRef<Path>, password: &[u8]) -> Result<(Self, RecoveryKey)> {
        let mut vault = Self::unlock(path, password)?;
        let recovery = RecoveryKey::generate();
        let slot = vault.recovery_slot(&recovery);
        vault.replace_slot(slot)?;
        Ok((vault, recovery))
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the file, unwrap MK through a slot of `kind`, then verify the
    /// header MAC before trusting anything else in the header.
    fn open_with(
        path: &Path,
        kind: SlotKind,
        derive_kek: impl Fn(&KeySlot, &KdfParams) -> Result<SecretKey>,
    ) -> Result<Self> {
        let bytes = fs::read_file(path)?;
        let raw = header::decode(&bytes)?;
        let mk = unwrap_mk(&raw.header, kind, derive_kek)?;
        crypto::verify_header_mac(&mk, raw.signed, raw.mac)?;
        Ok(Self {
            path: path.to_path_buf(),
            header: raw.header,
            mk,
        })
    }

    #[cfg(test)]
    pub(crate) fn serialize_test(&self, header: &Header) -> Vec<u8> {
        self.serialize(header)
    }

    fn serialize(&self, header: &Header) -> Vec<u8> {
        let mut out = header::encode_unsigned(header);
        let mac = crypto::header_mac(&self.mk, &out);
        out.extend_from_slice(&mac);
        out
    }

    fn password_slot(&self, password: &[u8]) -> Result<KeySlot> {
        let salt = random_bytes();
        let kek = crypto::password_kek(password, &salt, &self.header.kdf)?;
        Ok(self.wrap(SlotKind::Password, salt, &kek))
    }

    fn recovery_slot(&self, recovery: &RecoveryKey) -> KeySlot {
        let salt = random_bytes();
        let kek = crypto::recovery_kek(recovery, &salt);
        self.wrap(SlotKind::Recovery, salt, &kek)
    }

    fn wrap(&self, kind: SlotKind, salt: [u8; 16], kek: &SecretKey) -> KeySlot {
        let nonce = random_bytes();
        let aad = KeySlot::aad(&self.header.vault_id, kind);
        let encrypted_mk = crypto::seal(kek, &nonce, &aad, self.mk.as_ref());
        KeySlot {
            kind,
            salt,
            nonce,
            encrypted_mk,
        }
    }

    /// Swap in a new slot of the same kind and persist atomically.
    // TODO: no file lock around read-modify-write. Two concurrent
    // passwd/rotate-recovery runs both succeed and the last write wins.
    fn replace_slot(&mut self, slot: KeySlot) -> Result<()> {
        let mut header = self.header.clone();
        header.slots.retain(|s| s.kind != slot.kind);
        header.slots.push(slot);
        fs::replace_file(&self.path, &self.serialize(&header))?;
        // Only update in-memory state once the disk write succeeded.
        self.header = header;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn mk(&self) -> &[u8; KEY_LEN] {
        self.mk.as_ref().try_into().unwrap()
    }
}

fn unwrap_mk(
    header: &Header,
    kind: SlotKind,
    derive_kek: impl Fn(&KeySlot, &KdfParams) -> Result<SecretKey>,
) -> Result<SecretKey> {
    let aad = KeySlot::aad(&header.vault_id, kind);
    for slot in header.slots.iter().filter(|s| s.kind == kind) {
        let kek = derive_kek(slot, &header.kdf)?;
        if let Some(pt) = crypto::open(&kek, &slot.nonce, &aad, &slot.encrypted_mk)
            && pt.len() == KEY_LEN
        {
            let mut mk = zeroize::Zeroizing::new([0u8; KEY_LEN]);
            mk.copy_from_slice(&pt);
            return Ok(mk);
        }
    }
    Err(Error::BadCredential)
}
