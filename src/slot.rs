//! Everything that differs per slot kind lives here. Adding a kind means a
//! variant in `SlotKind`, `Credential` and `NewSlot`, plus their match arms
//! below; nothing in `vault` changes.

use crate::{
    Result,
    crypto::{self, RecoveryKey, SecretKey, random_bytes},
    header::{KdfParams, KeySlot, SlotId, SlotKind},
};

/// What the user presents to open an existing slot.
pub enum Credential<'a> {
    Password(&'a [u8]),
    Recovery(&'a RecoveryKey),
}

/// What to put in a new slot.
pub enum NewSlot<'a> {
    Password { password: &'a [u8], kdf: KdfParams },
    Recovery(&'a RecoveryKey),
}

/// Read-only view of a slot.
#[derive(Debug, Clone, Copy)]
pub struct SlotInfo<'a> {
    pub id: SlotId,
    pub label: Option<&'a str>,
    pub kind: &'a SlotKind,
}

impl<'a> SlotInfo<'a> {
    pub(crate) fn of(slot: &'a KeySlot) -> Self {
        Self {
            id: slot.id,
            label: slot.label.as_deref(),
            kind: &slot.kind,
        }
    }

    pub fn is_password(&self) -> bool {
        matches!(self.kind, SlotKind::Password { .. })
    }

    pub fn is_recovery(&self) -> bool {
        matches!(self.kind, SlotKind::Recovery { .. })
    }

    pub fn password_kdf(&self) -> Option<KdfParams> {
        match self.kind {
            SlotKind::Password { kdf, .. } => Some(*kdf),
            _ => None,
        }
    }
}

/// The KEK for `kind`, or `None` if that kind of slot doesn't take `cred`.
fn kek_for(kind: &SlotKind, cred: &Credential) -> Option<Result<SecretKey>> {
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

/// Fresh salt, the resulting kind, and its KEK.
fn make(new: &NewSlot) -> Result<(SlotKind, SecretKey)> {
    match new {
        NewSlot::Password { password, kdf } => {
            let salt = random_bytes();
            let kek = crypto::password_kek(password, &salt, kdf)?;
            Ok((SlotKind::Password { salt, kdf: *kdf }, kek))
        }
        NewSlot::Recovery(rk) => {
            let salt = random_bytes();
            Ok((SlotKind::Recovery { salt }, crypto::recovery_kek(rk, &salt)))
        }
    }
}

/// Builds a slot that opens to `mk`.
pub(crate) fn seal(
    vault_id: &[u8; 16],
    mk: &SecretKey,
    id: SlotId,
    label: Option<String>,
    new: &NewSlot,
) -> Result<KeySlot> {
    let (kind, kek) = make(new)?;
    let nonce = random_bytes();
    let aad = KeySlot::aad(vault_id, &kind);
    let (wrapped_mk, tag) = crypto::wrap_key(&kek, &nonce, &aad, mk);
    Ok(KeySlot {
        id,
        label,
        nonce,
        wrapped_mk,
        tag,
        kind,
    })
}

/// MK, if `cred` opens `slot`.
pub(crate) fn open(
    vault_id: &[u8; 16],
    slot: &KeySlot,
    cred: &Credential,
) -> Result<Option<SecretKey>> {
    let Some(kek) = kek_for(&slot.kind, cred) else {
        return Ok(None);
    };
    let aad = KeySlot::aad(vault_id, &slot.kind);
    Ok(crypto::unwrap_key(
        &kek?,
        &slot.nonce,
        &aad,
        &slot.wrapped_mk,
        &slot.tag,
    ))
}
