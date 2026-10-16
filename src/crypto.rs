//! Thin wrappers over audited primitive crypto libs.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, AeadInOut, Payload};
use hkdf::Hkdf;
use hmac::KeyInit;
use rand::{TryRng, rngs::SysRng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::header::KdfParams;
use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;
type HmacSha256 = hmac::Hmac<Sha256>;

/// 256-bit recovery key, shown to the user once as
/// `xxxxxxxx-xxxxxxxx-...` (8 groups of 8 hex chars).
///
/// Deliberately no `Display` impl so it can't end up in a log by accident.
pub struct RecoveryKey(SecretKey);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(random_key())
    }

    /// Forgiving about case, dashes and whitespace, strict about everything else.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_lowercase())
                .collect(),
        );
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hex::decode_to_slice(cleaned.as_bytes(), key.as_mut())
            .map_err(|_| Error::BadRecoveryKey)?;
        Ok(Self(key))
    }

    pub fn reveal(&self) -> Zeroizing<String> {
        let hex = Zeroizing::new(hex::encode(self.0.as_ref()));
        let groups: Vec<&str> = hex
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        Zeroizing::new(groups.join("-"))
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

/// returns a random key
pub fn random_key() -> SecretKey {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    SysRng
        .try_fill_bytes(k.as_mut())
        .expect("failed to get random bytes from OS");
    k
}

/// returns random bytes of length N
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SysRng
        .try_fill_bytes(&mut b)
        .expect("failed to get random bytes from OS");
    b
}

/// Password -> key-encryption key. Slow on purpose.
pub fn password_kek(password: &[u8], salt: &[u8; 16], kdf: &KdfParams) -> Result<SecretKey> {
    kdf.check()?;

    let params = Params::new(
        kdf.mem_cost_kib,
        kdf.time_cost,
        kdf.parallelism_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::BadKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::BadKdfParams)?;
    Ok(out)
}

/// Recovery key -> key-encryption key. The recovery key is 256 random bits,
/// so there's nothing to brute-force and no need for a slow KDF.
pub fn recovery_kek(recovery: &RecoveryKey, salt: &[u8; 16]) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), recovery.0.as_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"vlt vault v1 recovery kek", out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Returns the header MAC, keyed by a key derived from the master key.
pub fn header_mac(mk: &SecretKey, signed: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut m =
        HmacSha256::new_from_slice(header_mac_key(mk).as_ref()).expect("any key length works");
    m.update(signed);
    m.finalize().into_bytes().into()
}

/// Separate subkey for the header MAC, so MK itself is only ever used as
/// input to HKDF and to wrap item keys.
fn header_mac_key(mk: &SecretKey) -> SecretKey {
    subkey(mk, &[b"vlt v1 header mac"])
}

/// Constant-time comparison.
pub fn verify_header_mac(mk: &SecretKey, signed: &[u8], mac: &[u8]) -> Result<()> {
    use hmac::Mac;
    let mut m =
        HmacSha256::new_from_slice(header_mac_key(mk).as_ref()).expect("any key length works");
    m.update(signed);
    m.verify_slice(mac).map_err(|_| Error::Tampered)
}

/// HKDF-Expand with MK as the PRK. `info` parts are concatenated; the first
/// one is always a fixed `vlt v1 ...` label, so purposes can't collide.
pub fn subkey(mk: &SecretKey, info: &[&[u8]]) -> SecretKey {
    let hk = Hkdf::<Sha256>::from_prk(mk.as_ref()).expect("32-byte PRK is valid");
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand_multi_info(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Encrypts `buf` in place and returns the tag.
pub fn seal_in_place(
    key: &SecretKey,
    nonce: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    XChaCha20Poly1305::new((&**key).into())
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail")
        .into()
}

/// Decrypts `buf` in place. `false` on authentication failure, in which case
/// `buf` holds garbage and must not be used.
#[must_use]
pub fn open_in_place(
    key: &SecretKey,
    nonce: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    XChaCha20Poly1305::new((&**key).into())
        .decrypt_inout_detached(nonce.into(), aad, buf.into(), tag.into())
        .is_ok()
}

/// Encrypts a key under `kek`, tag kept separate so both halves are fixed-size.
pub fn wrap_key(
    kek: &SecretKey,
    nonce: &[u8; 24],
    aad: &[u8],
    key: &SecretKey,
) -> ([u8; KEY_LEN], [u8; TAG_LEN]) {
    let mut buf = **key;
    let tag = seal_in_place(kek, nonce, aad, &mut buf);
    (buf, tag)
}

/// `None` on authentication failure: wrong KEK, or the slot was modified.
pub fn unwrap_key(
    kek: &SecretKey,
    nonce: &[u8; 24],
    aad: &[u8],
    wrapped: &[u8; KEY_LEN],
    tag: &[u8; TAG_LEN],
) -> Option<SecretKey> {
    let mut key = Zeroizing::new(*wrapped);
    open_in_place(kek, nonce, aad, key.as_mut(), tag).then_some(key)
}

pub fn seal(key: &SecretKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new((&**key).into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail")
}

/// `None` on any authentication failure. Callers decide what that means
/// (wrong password for a keyslot, tampering for an item).
pub fn open(
    key: &SecretKey,
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new((&**key).into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}
