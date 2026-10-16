//! On-disk header format
//!
//! Layout:
//!
//! ```text
//! MAGIC ([u8; 8]) || FORMAT_VERSION (u16 LE) || postcard(Header) || MAC (32)
//! ```
//!
//! MAC = HMAC-SHA256 over everything before it, keyed by HKDF(MK). It can
//! only be checked after a keyslot has produced a MK.

use crate::{Error, Result};

pub const MAGIC: [u8; 8] = *b"VLTfile\0";
pub const FORMAT_VERSION: u16 = 1;

pub const MAX_HEADER_LEN: u64 = 64 * 1024; // 64 KiB

pub const MAC_LEN: usize = 32;

/// Upper bound on slots of any kind, as a sanity limit.
pub const MAX_SLOTS: usize = 16;
/// Upper bound on Argon2id-backed slots. Every one of them is tried on unlock,
/// *before* the MAC can be checked, so this bounds the work someone who can
/// edit the file can force on us.
pub const MAX_PASSWORD_SLOTS: usize = 4;
/// Upper bound on a slot label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub vault_id: [u8; 16],
    /// Id the next new slot gets. Only ever goes up, so ids are never reused.
    pub next_slot_id: SlotId,
    pub slots: Vec<KeySlot>,
}

impl Header {
    /// Structural checks that don't need MK: slot counts, unique ids, label
    /// lengths and KDF bounds. Runs on every decode (before any KDF does) and
    /// on every commit, so we never write what we'd refuse to read.
    pub(crate) fn check(&self) -> Result<()> {
        let password_slots = self
            .slots
            .iter()
            .filter(|s| matches!(s.kind, SlotKind::Password { .. }))
            .count();
        if self.slots.is_empty() {
            return Err(Error::Limit("a vault needs at least one slot"));
        }
        if self.slots.len() > MAX_SLOTS {
            return Err(Error::Limit("too many slots"));
        }
        if password_slots > MAX_PASSWORD_SLOTS {
            return Err(Error::Limit("too many password slots"));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.id >= self.next_slot_id || self.slots[..i].iter().any(|s| s.id == slot.id) {
                return Err(Error::Limit("slot ids must be unique and issued"));
            }
            if slot.label.as_ref().is_some_and(|l| l.len() > MAX_LABEL_LEN) {
                return Err(Error::Limit("slot label too long"));
            }
            if let SlotKind::Password { kdf, .. } = &slot.kind {
                kdf.check()?;
            }
        }
        Ok(())
    }

    pub fn slot(&self, id: SlotId) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.id == id)
    }
}

/// Stable slot id: survives edits to other slots and is never reused.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SlotId(pub u16);

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Argon2id params, stored per password slot so they can be raised later without breaking compat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism_cost: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        mem_cost_kib: 256 * 1024,
        time_cost: 3,
        parallelism_cost: 1,
    };

    /// Upper bound to prevent DoS attacks. The headers can be RW'd by anyone incl an attacker.
    const MAX_MEM_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
    /// Upper bound to prevent DoS attacks. The headers can be RW'd by anyone incl an attacker.
    const MAX_TIME_COST: u32 = 64;
    /// Upper bound to prevent DoS attacks. The headers can be RW'd by anyone incl an attacker.
    const MAX_PARALLELISM_COST: u32 = 16;

    /// Insecure variant FOR TESTS ONLY.
    #[cfg(test)]
    pub const INSECURE_TEST: Self = Self {
        mem_cost_kib: 8,
        time_cost: 1,
        parallelism_cost: 1,
    };

    /// Validates the Argon2id params. Returns `Err(Error::BadKdfParams)` if any of the params are
    /// out of bounds.
    pub fn check(&self) -> Result<()> {
        let ok = (1..=Self::MAX_MEM_COST_KIB).contains(&self.mem_cost_kib)
            && (1..=Self::MAX_TIME_COST).contains(&self.time_cost)
            && (1..=Self::MAX_PARALLELISM_COST).contains(&self.parallelism_cost);
        if ok { Ok(()) } else { Err(Error::BadKdfParams) }
    }
}

/// Keyslot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeySlot {
    pub id: SlotId,
    /// Optional human label. Plaintext, and unauthenticated until the MAC check.
    pub label: Option<String>,
    /// Nonce for XChaCha20Poly1305
    pub nonce: [u8; 24],
    /// XChaCha20Poly1305(KEK, MK) ciphertext
    pub wrapped_mk: [u8; 32],
    /// Poly1305 tag over `wrapped_mk`
    pub tag: [u8; 16],
    /// Kind of keyslot, plus whatever it needs to derive its KEK
    pub kind: SlotKind,
}

impl KeySlot {
    /// Associated data for wrapping MK. Binds the slot to *this* vault and
    /// *this* slot kind, so a slot copied from another vault (even one with
    /// the same password) or relabelled as a different kind won't open.
    pub fn aad(vault_id: &[u8; 16], kind: &SlotKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(MAGIC.len() + size_of_val(&FORMAT_VERSION) + 16 + 1);
        aad.extend_from_slice(&MAGIC);
        aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        aad.extend_from_slice(vault_id);
        aad.push(kind.tag());
        aad
    }
}

/// Slot kind.
///
/// postcard encodes variants by index, so this order is part of the on-disk
/// format: only ever append new variants, never reorder or remove one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlotKind {
    Password {
        /// Argon2id salt
        salt: [u8; 16],
        /// Per slot, so one slot's cost can be raised without touching the others
        kdf: KdfParams,
    },
    Recovery {
        /// HKDF salt
        salt: [u8; 16],
    },
}

impl SlotKind {
    /// Same as the postcard variant index.
    fn tag(&self) -> u8 {
        match self {
            SlotKind::Password { .. } => 0,
            SlotKind::Recovery { .. } => 1,
        }
    }
}

/// A parsed header whose MAC has NOT been checked yet. Only good for finding
/// keyslots; call sites must verify `mac` over `signed` once they have MK.
pub struct Unverified<'a> {
    pub header: Header,
    pub signed: &'a [u8],
    pub mac: &'a [u8],
}

/// Decodes a header from bytes. Returns an `Unverified` struct containing the decoded header, the
/// signed portion of the header, and the MAC. The MAC is not verified in this function; it must be
/// verified separately after obtaining the master key (MK).
pub fn decode(bytes: &[u8]) -> Result<Unverified<'_>> {
    if bytes.len() < MAGIC.len() + size_of_val(&FORMAT_VERSION) || bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    if bytes.len() < MAGIC.len() + size_of_val(&FORMAT_VERSION) + MAC_LEN {
        return Err(Error::Corrupt);
    }
    let (signed, mac) = bytes.split_at(bytes.len() - MAC_LEN);
    // take_from_bytes + empty-remainder check: plain from_bytes silently
    // ignores trailing garbage, which we don't want in a security format.
    let (header, rest): (Header, _) =
        postcard::take_from_bytes(&signed[10..]).map_err(|_| Error::Corrupt)?;
    if !rest.is_empty() {
        return Err(Error::Corrupt);
    }
    // From disk, a broken limit just means a bad file.
    header.check().map_err(|e| match e {
        Error::Limit(_) => Error::Corrupt,
        e => e,
    })?;
    Ok(Unverified {
        header,
        signed,
        mac,
    })
}

/// The part of the file the header MAC covers: `MAGIC || version || body`.
/// The caller appends the MAC (it needs the master key, which this module
/// never sees).
pub fn encode_unsigned(header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(
        &postcard::to_allocvec(header).expect("header serialization is infallible"),
    );
    out
}
