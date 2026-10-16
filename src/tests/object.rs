use std::io::{self, Read};

use super::{KDF, setup};
use crate::{
    Error,
    crypto::TAG_LEN,
    object::{self, CHUNK_LEN, ObjectId},
    ops,
    vault::Vault,
};

const HEADER_LEN: usize = 26;
const SEALED: usize = CHUNK_LEN + TAG_LEN;

fn vault() -> Vault {
    let (d, p) = setup();
    let (v, _rk) = ops::init(&p, b"pw", KDF).unwrap();
    drop(d);
    v
}

/// Deterministic, non-repeating-looking bytes, so a chunk swap can't
/// accidentally produce identical plaintext.
fn data(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn enc(v: &Vault, pt: &[u8]) -> (ObjectId, Vec<u8>) {
    let mut ct = Vec::new();
    let (id, n) = object::encrypt(v, pt, &mut ct).unwrap();
    assert_eq!(n, pt.len() as u64);
    (id, ct)
}

fn dec(v: &Vault, id: &ObjectId, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let mut pt = Vec::new();
    object::decrypt(v, id, ct, &mut pt)?;
    Ok(pt)
}

/// Hands out at most 7 bytes per read, to shake out short-read handling.
struct Trickle<'a>(&'a [u8]);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(7).min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn round_trips_at_every_chunk_edge() {
    let v = vault();
    for len in [
        0,
        1,
        CHUNK_LEN - 1,
        CHUNK_LEN,
        CHUNK_LEN + 1,
        3 * CHUNK_LEN,
        3 * CHUNK_LEN + 17,
    ] {
        let pt = data(len);
        let (id, ct) = enc(&v, &pt);
        assert_eq!(
            ct.len() as u64,
            object::encrypted_len(len as u64),
            "len {len}"
        );
        assert_eq!(dec(&v, &id, &ct).unwrap(), pt, "len {len}");

        // Same again through reads that never fill a buffer in one go.
        let mut ct2 = Vec::new();
        let (id2, _) = object::encrypt(&v, Trickle(&pt), &mut ct2).unwrap();
        let mut out = Vec::new();
        object::decrypt(&v, &id2, Trickle(&ct2), &mut out).unwrap();
        assert_eq!(out, pt, "trickled, len {len}");
    }
}

#[test]
fn empty_file_is_header_plus_one_tag() {
    let v = vault();
    let (id, ct) = enc(&v, b"");
    assert_eq!(ct.len(), HEADER_LEN + TAG_LEN);
    assert_eq!(dec(&v, &id, &ct).unwrap(), b"");
}

#[test]
fn same_plaintext_encrypts_differently() {
    let v = vault();
    let (id1, ct1) = enc(&v, b"same");
    let (id2, ct2) = enc(&v, b"same");
    assert_ne!(id1, id2);
    assert_ne!(ct1[HEADER_LEN..], ct2[HEADER_LEN..]);
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let v = vault();
    let (id, good) = enc(&v, &data(100));
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            assert!(
                dec(&v, &id, &bad).is_err(),
                "flip at byte {i} bit {bit} accepted"
            );
        }
    }
}

#[test]
fn truncation_is_rejected_including_at_chunk_boundaries() {
    let v = vault();
    let (id, ct) = enc(&v, &data(2 * CHUNK_LEN + 5));
    let one_chunk = HEADER_LEN + SEALED;
    let two_chunks = HEADER_LEN + 2 * SEALED;
    for len in [
        0,
        HEADER_LEN - 1,
        HEADER_LEN,
        HEADER_LEN + TAG_LEN - 1,
        HEADER_LEN + 1000,
        one_chunk - 1,
        one_chunk, // a clean boundary: chunk 0 wasn't sealed as final
        one_chunk + 1,
        two_chunks,
        ct.len() - 1,
    ] {
        assert!(
            matches!(dec(&v, &id, &ct[..len]), Err(Error::BadObject)),
            "truncated to {len} accepted"
        );
    }

    // Exactly-full last chunk, cut back to the previous boundary.
    let (id, ct) = enc(&v, &data(2 * CHUNK_LEN));
    assert!(dec(&v, &id, &ct[..HEADER_LEN + SEALED]).is_err());
}

#[test]
fn appended_bytes_or_chunks_are_rejected() {
    let v = vault();
    let (id, ct) = enc(&v, &data(CHUNK_LEN));
    let mut long = ct.clone();
    long.push(0);
    assert!(dec(&v, &id, &long).is_err());

    // A whole extra chunk, copied from the object itself.
    let mut long = ct.clone();
    long.extend_from_slice(&ct[HEADER_LEN..]);
    assert!(dec(&v, &id, &long).is_err());
}

#[test]
fn reordered_chunks_are_rejected() {
    let v = vault();
    let (id, ct) = enc(&v, &data(3 * CHUNK_LEN));
    let chunk = |i: usize| &ct[HEADER_LEN + i * SEALED..HEADER_LEN + (i + 1) * SEALED];
    let mut swapped = ct[..HEADER_LEN].to_vec();
    for i in [1, 0, 2] {
        swapped.extend_from_slice(chunk(i));
    }
    assert!(matches!(dec(&v, &id, &swapped), Err(Error::BadObject)));
}

#[test]
fn chunk_spliced_from_another_object_is_rejected() {
    let v = vault();
    let (id_a, a) = enc(&v, &data(2 * CHUNK_LEN));
    let (_id_b, b) = enc(&v, &data(2 * CHUNK_LEN));
    let mut spliced = a[..HEADER_LEN + SEALED].to_vec();
    spliced.extend_from_slice(&b[HEADER_LEN + SEALED..]);
    assert!(matches!(dec(&v, &id_a, &spliced), Err(Error::BadObject)));
}

#[test]
fn object_under_the_wrong_id_is_rejected() {
    let v = vault();
    let (id_a, a) = enc(&v, b"a");
    let (id_b, _b) = enc(&v, b"b");
    // File swapped: B's name, A's contents.
    assert!(matches!(dec(&v, &id_b, &a), Err(Error::BadObject)));

    // Header rewritten to claim B's id: the key no longer matches.
    let mut relabelled = a.clone();
    relabelled[10..HEADER_LEN].copy_from_slice(&id_b.0);
    assert!(matches!(dec(&v, &id_b, &relabelled), Err(Error::BadObject)));
    dec(&v, &id_a, &a).unwrap();
}

#[test]
fn object_from_another_vault_is_rejected() {
    let a = vault();
    let b = vault();
    let (id, ct) = enc(&a, b"secret");
    assert!(matches!(dec(&b, &id, &ct), Err(Error::BadObject)));
}

#[test]
fn not_an_object_and_future_versions() {
    let v = vault();
    let (id, mut ct) = enc(&v, b"x");
    let mut not = ct.clone();
    not[0] ^= 1;
    assert!(matches!(dec(&v, &id, &not), Err(Error::BadObject)));

    ct[8..10].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        dec(&v, &id, &ct),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn only_authenticated_chunks_are_released() {
    let v = vault();
    let pt = data(3 * CHUNK_LEN);
    let (id, mut ct) = enc(&v, &pt);
    ct[HEADER_LEN + SEALED + 5] ^= 1; // corrupt chunk 1
    let mut out = Vec::new();
    assert!(object::decrypt(&v, &id, &ct[..], &mut out).is_err());
    assert_eq!(out, pt[..CHUNK_LEN], "only chunk 0 may have been written");
}
