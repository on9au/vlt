//! What the operations *mean*: policy on top of `Vault`'s mechanics.
//!
//! Each step is its own function so a frontend can prompt in between, e.g.
//! settle which slot `recover` resets before asking for the new password.

use std::path::Path;

use crate::{
    Error, Result,
    crypto::RecoveryKey,
    header::{KdfParams, SlotId},
    slot::{NewSlot, SlotInfo},
    vault::Vault,
};

/// Picks a slot: by its stable id, or by its label.
#[derive(Debug, Clone, Copy)]
pub enum SlotRef<'a> {
    Id(SlotId),
    Label(&'a str),
}

/// Create a vault with one password slot and one recovery slot. The
/// recovery key is returned exactly once: if the caller drops it, it's gone.
pub fn init(
    path: impl AsRef<Path>,
    password: &[u8],
    kdf: KdfParams,
) -> Result<(Vault, RecoveryKey)> {
    let recovery = RecoveryKey::generate();
    let vault = Vault::create(
        path,
        &[
            NewSlot::Password { password, kdf },
            NewSlot::Recovery(&recovery),
        ],
    )?;
    Ok((vault, recovery))
}

/// Give password slot `id` a new password, keeping its id, label and KDF params.
pub fn set_password(vault: &mut Vault, id: SlotId, password: &[u8]) -> Result<()> {
    let kdf = vault
        .slot(id)
        .ok_or(Error::NoSuchSlot)?
        .password_kdf()
        .ok_or(Error::WrongSlotKind)?;
    let mut edit = vault.edit();
    edit.replace(id, &NewSlot::Password { password, kdf })?;
    edit.commit()
}

pub fn add_password(
    vault: &mut Vault,
    password: &[u8],
    kdf: KdfParams,
    label: Option<String>,
) -> Result<SlotId> {
    let mut edit = vault.edit();
    let id = edit.add(&NewSlot::Password { password, kdf }, label)?;
    edit.commit()?;
    Ok(id)
}

/// Resolve which password slot to reset. `None` means the vault has no
/// password slot at all (so the caller should add one). Never guesses: if
/// more than one slot fits, the error lists them.
pub fn choose_password_slot(vault: &Vault, choice: Option<SlotRef>) -> Result<Option<SlotId>> {
    let candidates: Vec<SlotInfo> = vault.slots().filter(SlotInfo::is_password).collect();
    let matching: Vec<SlotInfo> = match choice {
        None if candidates.is_empty() => return Ok(None),
        None => candidates,
        Some(SlotRef::Id(id)) => candidates.into_iter().filter(|s| s.id == id).collect(),
        Some(SlotRef::Label(label)) => candidates
            .into_iter()
            .filter(|s| s.label == Some(label))
            .collect(),
    };
    match matching.as_slice() {
        [] => Err(Error::NoSuchSlot),
        [one] => Ok(Some(one.id)),
        several => Err(Error::SlotRequired(describe(several))),
    }
}

/// Issue a new recovery key. Every old one stops working. The first
/// recovery slot keeps its id; any others are removed.
pub fn rotate_recovery(vault: &mut Vault) -> Result<RecoveryKey> {
    let recovery = RecoveryKey::generate();
    let ids: Vec<SlotId> = vault
        .slots()
        .filter(SlotInfo::is_recovery)
        .map(|s| s.id)
        .collect();
    let new = NewSlot::Recovery(&recovery);
    let mut edit = vault.edit();
    match ids.split_first() {
        Some((first, rest)) => {
            edit.replace(*first, &new)?;
            for id in rest {
                edit.remove(*id)?;
            }
        }
        None => {
            edit.add(&new, None)?;
        }
    }
    edit.commit()?;
    Ok(recovery)
}

/// Only ever called on a verified `Vault`, so the labels are authentic.
fn describe(slots: &[SlotInfo]) -> String {
    slots
        .iter()
        .map(|s| match s.label {
            Some(label) => format!("{} ({label:?})", s.id),
            None => format!("{} (no label)", s.id),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
