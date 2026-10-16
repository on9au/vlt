//! Vault
//!
//! `LockedVault` (parsed, unverified) --unlock--> `Vault` (MK, verified)
//! --edit--> `Edit` --commit--> disk. What the operations *mean* (change
//! password, recover, ...) lives in `ops`.

use std::path::{Path, PathBuf};

use crate::{
    Error, Result,
    crypto::{self, SecretKey, random_bytes, random_key},
    fs,
    header::{self, Header, KeySlot, SlotId},
    slot::{self, Credential, NewSlot, SlotInfo},
};

/// A vault file that has been parsed but not unlocked. Nothing in it is
/// authenticated yet: use it only to decide what to prompt for.
pub struct LockedVault {
    path: PathBuf,
    bytes: Vec<u8>,
    header: Header,
}

impl LockedVault {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read_capped(&path, header::MAX_HEADER_LEN, Error::Corrupt)?;
        let header = header::decode(&bytes)?.header;
        Ok(Self {
            path,
            bytes,
            header,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// UNAUTHENTICATED: anyone can edit these. Fine for picking a prompt,
    /// not for any decision that matters.
    pub fn slots(&self) -> impl Iterator<Item = SlotInfo<'_>> {
        self.header.slots.iter().map(SlotInfo::of)
    }

    /// Try every slot that accepts `cred`, then verify the header MAC before
    /// trusting anything else in the header.
    pub fn unlock(self, cred: &Credential) -> Result<Vault> {
        let (opened_by, mk) = self
            .header
            .slots
            .iter()
            .find_map(|s| match slot::open(&self.header.vault_id, s, cred) {
                Ok(Some(mk)) => Some(Ok((s.id, mk))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            })
            .ok_or(Error::BadCredential)??;
        let (signed, mac) = self.bytes.split_at(self.bytes.len() - header::MAC_LEN);
        crypto::verify_header_mac(&mk, signed, mac)?;
        Ok(Vault {
            path: self.path,
            header: self.header,
            mk,
            opened_by: Some(opened_by),
        })
    }
}

/// An unlocked vault. Holds MK in memory (zeroized)
pub struct Vault {
    path: PathBuf,
    header: Header,
    mk: SecretKey,
    opened_by: Option<SlotId>,
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
    /// Create a new vault with `slots`, refusing to overwrite anything.
    pub fn create(path: impl AsRef<Path>, slots: &[NewSlot]) -> Result<Self> {
        let mut vault = Self {
            path: path.as_ref().to_path_buf(),
            header: Header {
                vault_id: random_bytes(),
                next_slot_id: SlotId(0),
                slots: Vec::new(),
            },
            mk: random_key(),
            opened_by: None,
        };
        let mut edit = vault.edit();
        for new in slots {
            edit.add(new, None)?;
        }
        let Edit { header, .. } = edit;
        header.check()?;
        let bytes = vault.serialize(&header);
        fs::write_new(&vault.path, &bytes)?;
        vault.header = header;
        Ok(vault)
    }

    #[cfg(test)]
    pub(crate) fn new_test(path: impl AsRef<Path>, header: Header, mk: SecretKey) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            header,
            mk,
            opened_by: None,
        }
    }

    pub fn id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn slots(&self) -> impl Iterator<Item = SlotInfo<'_>> {
        self.header.slots.iter().map(SlotInfo::of)
    }

    pub fn slot(&self, id: SlotId) -> Option<SlotInfo<'_>> {
        self.header.slot(id).map(SlotInfo::of)
    }

    /// The slot whose credential unlocked this vault. `None` for a vault
    /// you just created.
    pub fn opened_by(&self) -> Option<SlotId> {
        self.opened_by
    }

    /// A subkey of MK for one purpose. MK itself never leaves `Vault`; every
    /// consumer gets its own key, so no two primitives ever share one.
    pub(crate) fn derive_key(&self, info: &[&[u8]]) -> SecretKey {
        crypto::subkey(&self.mk, info)
    }

    /// Stage slot changes. Nothing touches the disk (or `self`) until
    /// `Edit::commit`.
    pub fn edit(&mut self) -> Edit<'_> {
        Edit {
            header: self.header.clone(),
            vault: self,
        }
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

    #[cfg(test)]
    pub(crate) fn mk(&self) -> &[u8; crypto::KEY_LEN] {
        &self.mk
    }
}

/// Staged slot changes, written in one atomic step by `commit`.
#[must_use = "edits are discarded unless committed"]
pub struct Edit<'v> {
    vault: &'v mut Vault,
    header: Header,
}

impl Edit<'_> {
    pub fn add(&mut self, new: &NewSlot, label: Option<String>) -> Result<SlotId> {
        let id = self.header.next_slot_id;
        let next = id.0.checked_add(1).ok_or(Error::Limit("out of slot ids"))?;
        let slot = self.seal(id, label, new)?;
        self.header.slots.push(slot);
        self.header.next_slot_id = SlotId(next);
        Ok(id)
    }

    /// New secret, same id and label. May change the slot's kind.
    pub fn replace(&mut self, id: SlotId, new: &NewSlot) -> Result<()> {
        let i = self.index(id)?;
        let label = self.header.slots[i].label.clone();
        self.header.slots[i] = self.seal(id, label, new)?;
        Ok(())
    }

    pub fn remove(&mut self, id: SlotId) -> Result<()> {
        let i = self.index(id)?;
        self.header.slots.remove(i);
        Ok(())
    }

    pub fn set_label(&mut self, id: SlotId, label: Option<String>) -> Result<()> {
        let i = self.index(id)?;
        self.header.slots[i].label = label;
        Ok(())
    }

    /// Check the result is a header we'd accept on read, write it
    /// atomically, and only then update the in-memory vault.
    // TODO: no file lock around read-modify-write. Two concurrent edits both
    // succeed and the last write wins.
    pub fn commit(self) -> Result<()> {
        let Edit { vault, header } = self;
        header.check()?;
        fs::replace_file(&vault.path, &vault.serialize(&header))?;
        vault.header = header;
        Ok(())
    }

    fn index(&self, id: SlotId) -> Result<usize> {
        self.header
            .slots
            .iter()
            .position(|s| s.id == id)
            .ok_or(Error::NoSuchSlot)
    }

    fn seal(&self, id: SlotId, label: Option<String>, new: &NewSlot) -> Result<KeySlot> {
        slot::seal(&self.header.vault_id, &self.vault.mk, id, label, new)
    }
}
