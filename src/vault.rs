//! Vault

use std::path::{Path, PathBuf};

use crate::{
    Error, Result,
    crypto::{self, RecoveryKey, SecretKey, random_bytes, random_key},
    fs,
    header::{self, Header, KdfParams, KeySlot, SlotKind},
};

/// Something the user presents to open a slot. Each slot kind accepts
/// exactly one kind of credential.
enum Credential<'a> {
    Password(&'a [u8]),
    Recovery(&'a RecoveryKey),
}

/// Picks a slot: by its index in the header, or by its label.
#[derive(Debug, Clone, Copy)]
pub enum SlotRef<'a> {
    Index(usize),
    Label(&'a str),
}

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
                slots: Vec::new(),
            },
            mk: random_key(),
        };
        let pw_slot = vault.password_slot(password, kdf)?;
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
        Self::open_with(path.as_ref(), &Credential::Password(password)).map(|(v, _)| v)
    }

    /// Requires the old password *every time*, never a cached one. An
    /// unlocked session on its own is not enough to change credentials.
    ///
    /// Only the slot the old password opened is replaced; any other password
    /// slots are left alone. The new slot keeps that slot's label and KDF params.
    pub fn change_password(path: impl AsRef<Path>, old: &[u8], new: &[u8]) -> Result<Self> {
        let (mut vault, i) = Self::open_with(path.as_ref(), &Credential::Password(old))?;
        vault.reset_password_slot(i, new)?;
        Ok(vault)
    }

    /// Forgot a password: open with the recovery key and give one password
    /// slot a new password, keeping its label and KDF params. Other password
    /// slots are left alone. The recovery key stays valid (rotate it
    /// separately if it leaked).
    ///
    /// `slot` may be omitted when there's exactly one password slot. If there
    /// are none, a new one is added with `kdf`, which is otherwise unused.
    pub fn recover(
        path: impl AsRef<Path>,
        recovery: &RecoveryKey,
        new_password: &[u8],
        slot: Option<SlotRef>,
        kdf: KdfParams,
    ) -> Result<Self> {
        let (mut vault, _) = Self::open_with(path.as_ref(), &Credential::Recovery(recovery))?;
        let candidates: Vec<usize> = (0..vault.header.slots.len())
            .filter(|&i| matches!(vault.header.slots[i].kind, SlotKind::Password { .. }))
            .collect();
        let i = match (slot, candidates.as_slice()) {
            (None, []) => {
                kdf.check()?;
                let slot = vault.password_slot(new_password, kdf)?;
                let mut header = vault.header.clone();
                header.slots.push(slot);
                vault.persist(header)?;
                return Ok(vault);
            }
            (None, [i]) => *i,
            (None, _) => return Err(vault.slot_required(&candidates)),
            (Some(SlotRef::Index(i)), _) if candidates.contains(&i) => i,
            (Some(SlotRef::Index(_)), _) => return Err(Error::NoSuchSlot),
            (Some(SlotRef::Label(label)), _) => {
                let matching: Vec<usize> = candidates
                    .iter()
                    .copied()
                    .filter(|&i| vault.header.slots[i].label.as_deref() == Some(label))
                    .collect();
                match matching.as_slice() {
                    [i] => *i,
                    [] => return Err(Error::NoSuchSlot),
                    _ => return Err(vault.slot_required(&matching)),
                }
            }
        };
        vault.reset_password_slot(i, new_password)?;
        Ok(vault)
    }

    /// Lost the paper, or think someone saw it: issue a new recovery key.
    /// The old one stops working immediately.
    pub fn rotate_recovery(path: impl AsRef<Path>, password: &[u8]) -> Result<(Self, RecoveryKey)> {
        let mut vault = Self::unlock(path, password)?;
        let recovery = RecoveryKey::generate();
        let slot = vault.recovery_slot(&recovery);
        vault.replace_all(slot)?;
        Ok((vault, recovery))
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the file, unwrap MK through a slot that accepts `cred`, then
    /// verify the header MAC before trusting anything else in the header.
    /// Also returns the index of the slot that opened.
    fn open_with(path: &Path, cred: &Credential) -> Result<(Self, usize)> {
        let bytes = fs::read_file(path)?;
        let raw = header::decode(&bytes)?;
        let (i, mk) = unwrap_mk(&raw.header, cred)?;
        crypto::verify_header_mac(&mk, raw.signed, raw.mac)?;
        let vault = Self {
            path: path.to_path_buf(),
            header: raw.header,
            mk,
        };
        Ok((vault, i))
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

    fn password_slot(&self, password: &[u8], kdf: KdfParams) -> Result<KeySlot> {
        let salt = random_bytes();
        let kek = crypto::password_kek(password, &salt, &kdf)?;
        Ok(self.wrap(SlotKind::Password { salt, kdf }, &kek))
    }

    fn recovery_slot(&self, recovery: &RecoveryKey) -> KeySlot {
        let salt = random_bytes();
        let kek = crypto::recovery_kek(recovery, &salt);
        self.wrap(SlotKind::Recovery { salt }, &kek)
    }

    fn wrap(&self, kind: SlotKind, kek: &SecretKey) -> KeySlot {
        let nonce = random_bytes();
        let aad = KeySlot::aad(&self.header.vault_id, &kind);
        let (wrapped_mk, tag) = crypto::wrap_key(kek, &nonce, &aad, &self.mk);
        KeySlot {
            label: None,
            nonce,
            wrapped_mk,
            tag,
            kind,
        }
    }

    /// Give password slot `i` a new password, in place, keeping its label and
    /// KDF params.
    fn reset_password_slot(&mut self, i: usize, password: &[u8]) -> Result<()> {
        let old = &self.header.slots[i];
        let SlotKind::Password { kdf, .. } = old.kind else {
            unreachable!("only called with password slots")
        };
        let mut slot = self.password_slot(password, kdf)?;
        slot.label = old.label.clone();
        let mut header = self.header.clone();
        header.slots[i] = slot;
        self.persist(header)
    }

    /// Lists `candidates` so the user can pick one. Only called after the MAC
    /// check, so the labels are authentic.
    fn slot_required(&self, candidates: &[usize]) -> Error {
        let choices = candidates
            .iter()
            .map(|&i| match &self.header.slots[i].label {
                Some(label) => format!("{i} ({label:?})"),
                None => format!("{i} (no label)"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        Error::SlotRequired(choices)
    }

    /// Replace every slot of the same kind with `slot` and persist atomically.
    fn replace_all(&mut self, slot: KeySlot) -> Result<()> {
        let mut header = self.header.clone();
        header
            .slots
            .retain(|s| std::mem::discriminant(&s.kind) != std::mem::discriminant(&slot.kind));
        header.slots.push(slot);
        self.persist(header)
    }

    // TODO: no file lock around read-modify-write. Two concurrent
    // passwd/rotate-recovery runs both succeed and the last write wins.
    fn persist(&mut self, header: Header) -> Result<()> {
        fs::replace_file(&self.path, &self.serialize(&header))?;
        // Only update in-memory state once the disk write succeeded.
        self.header = header;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn mk(&self) -> &[u8; crypto::KEY_LEN] {
        &self.mk
    }
}

/// The KEK for `kind`, or `None` if that kind of slot doesn't take `cred`.
fn slot_kek(kind: &SlotKind, cred: &Credential) -> Option<Result<SecretKey>> {
    match (kind, cred) {
        (SlotKind::Password { salt, kdf }, Credential::Password(pw)) => {
            Some(crypto::password_kek(pw, salt, kdf))
        }
        (SlotKind::Recovery { salt }, Credential::Recovery(rk)) => {
            Some(Ok(crypto::recovery_kek(rk, salt)))
        }
        _ => None,
    }
}

/// Try every slot that accepts `cred`. Returns the index of the one that
/// opened along with MK.
fn unwrap_mk(header: &Header, cred: &Credential) -> Result<(usize, SecretKey)> {
    for (i, slot) in header.slots.iter().enumerate() {
        let Some(kek) = slot_kek(&slot.kind, cred) else {
            continue;
        };
        let aad = KeySlot::aad(&header.vault_id, &slot.kind);
        if let Some(mk) = crypto::unwrap_key(&kek?, &slot.nonce, &aad, &slot.wrapped_mk, &slot.tag)
        {
            return Ok((i, mk));
        }
    }
    Err(Error::BadCredential)
}
