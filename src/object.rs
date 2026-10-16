//! Encrypted objects: one per stored file.
//!
//! Layout:
//!
//! ```text
//! MAGIC ([u8; 8]) || FORMAT_VERSION (u16 LE) || object id ([u8; 16])   = header
//! chunk 0 || chunk 1 || ... || chunk n                                  = body
//! chunk = XChaCha20-Poly1305(key, nonce_i, aad = header, plaintext_i) || tag (16)
//! ```
//!
//! - `key = HKDF(MK, "vlt v1 object" || id)`: one key per object.
//! - Every chunk holds exactly `CHUNK_LEN` plaintext bytes except the last,
//!   which holds `0..=CHUNK_LEN` (only an empty file has an empty chunk).
//! - `nonce_i = i (u64 LE) || final (u8) || 0^15`. Deterministic nonces are
//!   safe because the key is unique per object and an id is only ever used
//!   for one encryption: `encrypt` picks it, callers can't.
//! - The final flag (the STREAM construction) means dropping trailing
//!   chunks, reordering chunks, or splicing in a chunk from another object
//!   all fail authentication.
//! - The id in the header is bound twice: through the key, and as AAD.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{self, SecretKey, TAG_LEN, random_bytes},
    vault::Vault,
};

pub const MAGIC: [u8; 8] = *b"VLTobj\0\0";
pub const FORMAT_VERSION: u16 = 1;
pub const CHUNK_LEN: usize = 64 * 1024;

const HEADER_LEN: usize = MAGIC.len() + size_of::<u16>() + 16;

/// Random object id, also the object's file name (as hex).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId(pub [u8; 16]);

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Ciphertext size for `plaintext_len` bytes of plaintext.
pub fn encrypted_len(plaintext_len: u64) -> u64 {
    let chunks = plaintext_len.div_ceil(CHUNK_LEN as u64).max(1);
    HEADER_LEN as u64 + plaintext_len + chunks * TAG_LEN as u64
}

/// Encrypt everything `src` yields into `dst` under a fresh object id.
/// Returns the id and the plaintext length.
pub fn encrypt(vault: &Vault, mut src: impl Read, mut dst: impl Write) -> Result<(ObjectId, u64)> {
    let id = ObjectId(random_bytes());
    let header = header(&id);
    let key = object_key(vault, &id);
    dst.write_all(&header)?;

    // Double-buffered: a chunk is only final once we've seen nothing follows it.
    let mut cur = Zeroizing::new(vec![0u8; CHUNK_LEN]);
    let mut next = Zeroizing::new(vec![0u8; CHUNK_LEN]);
    let mut cur_len = read_full(&mut src, &mut cur)?;
    let mut total = 0u64;
    for i in 0u64.. {
        let next_len = if cur_len == CHUNK_LEN {
            read_full(&mut src, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let tag = crypto::seal_in_place(&key, &nonce(i, last), &header, &mut cur[..cur_len]);
        dst.write_all(&cur[..cur_len])?;
        dst.write_all(&tag)?;
        total += cur_len as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    dst.flush()?;
    Ok((id, total))
}

/// Decrypt object `id` from `src` into `dst`. Returns the plaintext length.
///
/// Streams: each chunk is authenticated before any of it is written, but a
/// later chunk can still fail (truncation, tampering). On `Err`, whatever
/// reached `dst` is an incomplete prefix and must be discarded.
pub fn decrypt(
    vault: &Vault,
    id: &ObjectId,
    mut src: impl Read,
    mut dst: impl Write,
) -> Result<u64> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut src, &mut header)? != HEADER_LEN || header[..MAGIC.len()] != MAGIC {
        return Err(Error::BadObject);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    // An object stored under the wrong name is a swap, not a different file.
    if header[10..] != id.0 {
        return Err(Error::BadObject);
    }
    let key = object_key(vault, id);

    const SEALED_LEN: usize = CHUNK_LEN + TAG_LEN;
    let mut cur = Zeroizing::new(vec![0u8; SEALED_LEN]);
    let mut next = Zeroizing::new(vec![0u8; SEALED_LEN]);
    let mut cur_len = read_full(&mut src, &mut cur)?;
    let mut total = 0u64;
    for i in 0u64.. {
        let next_len = if cur_len == SEALED_LEN {
            read_full(&mut src, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let Some(pt_len) = cur_len.checked_sub(TAG_LEN) else {
            return Err(Error::BadObject);
        };
        let (pt, tag) = cur[..cur_len].split_at_mut(pt_len);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().expect("split at TAG_LEN");
        if !crypto::open_in_place(&key, &nonce(i, last), &header, pt, tag) {
            return Err(Error::BadObject);
        }
        dst.write_all(pt)?;
        total += pt_len as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    dst.flush()?;
    Ok(total)
}

fn object_key(vault: &Vault, id: &ObjectId) -> SecretKey {
    vault.derive_key(&[b"vlt v1 object", &id.0])
}

fn header(id: &ObjectId) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h[10..].copy_from_slice(&id.0);
    h
}

fn nonce(index: u64, last: bool) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&index.to_le_bytes());
    n[8] = last as u8;
    n
}

/// Like `read_exact`, but a short read at EOF is fine: returns how much it got.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
