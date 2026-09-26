use std::{
    fs as stdfs,
    path::{Path, PathBuf},
};

use crate::{
    Error,
    crypto::{RecoveryKey, random_key},
    fs,
    header::{self, Header, KdfParams, SlotKind},
    vault::Vault,
};

use tempfile::TempDir;

const KDF: KdfParams = KdfParams::INSECURE_TEST;

fn setup() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    (dir, path)
}

fn mk(v: &Vault) -> [u8; 32] {
    *v.mk()
}

fn load(p: &Path) -> Header {
    header::decode(&stdfs::read(p).unwrap()).unwrap().header
}

/// Re-encode with a garbage MAC. Used by tests that check a defence which
/// runs *before* the MAC check (AAD, KDF bounds).
fn store_unsigned(p: &Path, h: &Header) {
    let mut out = header::encode_unsigned(h);
    out.extend_from_slice(&[0u8; header::MAC_LEN]);
    stdfs::write(p, out).unwrap();
}

#[test]
fn init_then_unlock_gives_same_master_key() {
    let (_d, p) = setup();
    let (v, _rk) = Vault::init(&p, b"hunter2hunter2", KDF).unwrap();
    let v2 = Vault::unlock(&p, b"hunter2hunter2").unwrap();
    assert_eq!(mk(&v), mk(&v2));
    assert_eq!(v.vault_id(), v2.vault_id());
}

#[test]
fn wrong_password_fails_cleanly() {
    let (_d, p) = setup();
    Vault::init(&p, b"correct horse", KDF).unwrap();
    assert!(matches!(
        Vault::unlock(&p, b"wrong horse"),
        Err(Error::BadCredential)
    ));
    assert!(matches!(Vault::unlock(&p, b""), Err(Error::BadCredential)));
}

#[test]
fn init_refuses_to_overwrite() {
    let (_d, p) = setup();
    Vault::init(&p, b"a", KDF).unwrap();
    let before = stdfs::read(&p).unwrap();
    assert!(matches!(
        Vault::init(&p, b"b", KDF),
        Err(Error::AlreadyExists)
    ));
    assert_eq!(
        before,
        stdfs::read(&p).unwrap(),
        "existing vault must be untouched"
    );
    assert!(!fs::tmp_path(&p).exists(), "temp file must be cleaned up");
}

#[test]
fn change_password_keeps_mk_and_recovery() {
    let (_d, p) = setup();
    let (v, rk) = Vault::init(&p, b"old", KDF).unwrap();
    let original = mk(&v);

    assert!(matches!(
        Vault::change_password(&p, b"not old", b"new"),
        Err(Error::BadCredential)
    ));
    let v2 = Vault::change_password(&p, b"old", b"new").unwrap();
    assert_eq!(mk(&v2), original, "MK must never change");

    assert!(matches!(
        Vault::unlock(&p, b"old"),
        Err(Error::BadCredential)
    ));
    assert_eq!(mk(&Vault::unlock(&p, b"new").unwrap()), original);

    // Recovery key still works after a password change.
    let v3 = Vault::recover(&p, &rk, b"newer").unwrap();
    assert_eq!(mk(&v3), original);
}

#[test]
fn recover_resets_password() {
    let (_d, p) = setup();
    let (v, rk) = Vault::init(&p, b"forgotten", KDF).unwrap();
    let rk = RecoveryKey::parse(&rk.reveal()).unwrap(); // round-trip through the printed form
    Vault::recover(&p, &rk, b"fresh").unwrap();
    assert!(matches!(
        Vault::unlock(&p, b"forgotten"),
        Err(Error::BadCredential)
    ));
    assert_eq!(mk(&Vault::unlock(&p, b"fresh").unwrap()), mk(&v));
}

#[test]
fn wrong_recovery_key_fails() {
    let (_d, p) = setup();
    Vault::init(&p, b"pw", KDF).unwrap();
    let bogus = RecoveryKey::generate();
    assert!(matches!(
        Vault::recover(&p, &bogus, b"x"),
        Err(Error::BadCredential)
    ));
    // And the password slot must be untouched by the failed attempt.
    Vault::unlock(&p, b"pw").unwrap();
}

#[test]
fn rotate_recovery_kills_old_key() {
    let (_d, p) = setup();
    let (_v, old_rk) = Vault::init(&p, b"pw", KDF).unwrap();
    let (_v, new_rk) = Vault::rotate_recovery(&p, b"pw").unwrap();
    assert!(matches!(
        Vault::recover(&p, &old_rk, b"x"),
        Err(Error::BadCredential)
    ));
    Vault::recover(&p, &new_rk, b"x").unwrap();
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let (_d, p) = setup();
    Vault::init(&p, b"pw", KDF).unwrap();
    let good = stdfs::read(&p).unwrap();
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            stdfs::write(&p, &bad).unwrap();
            assert!(
                Vault::unlock(&p, b"pw").is_err(),
                "flip at byte {i} bit {bit} was accepted"
            );
        }
    }
    stdfs::write(&p, &good).unwrap();
    Vault::unlock(&p, b"pw").unwrap();
}

#[test]
fn tampering_with_the_other_slot_is_caught() {
    // The bug the bit-flip test originally found: corrupting the recovery
    // slot didn't affect password unlock, so you'd never know until the
    // day you actually needed recovery.
    let (_d, p) = setup();
    Vault::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    let s = h
        .slots
        .iter_mut()
        .find(|s| s.kind == SlotKind::Recovery)
        .unwrap();
    s.encrypted_mk[0] ^= 1;
    // Re-sign with a *wrong* MK to prove the MAC is keyed, not just a checksum.
    let fake = Vault::new_test(p.clone(), h.clone(), random_key());
    stdfs::write(&p, fake.serialize_test(&h)).unwrap();
    assert!(matches!(Vault::unlock(&p, b"pw"), Err(Error::Tampered)));

    // Same the other way round: mess with the password slot, recover path notices.
    let (_d2, p2) = setup();
    let (_v, rk2) = Vault::init(&p2, b"pw", KDF).unwrap();
    let mut bytes = stdfs::read(&p2).unwrap();
    let mut h2 = header::decode(&bytes).unwrap().header;
    h2.slots
        .iter_mut()
        .find(|s| s.kind == SlotKind::Password)
        .unwrap()
        .salt[0] ^= 1;
    let mac = bytes.split_off(bytes.len() - header::MAC_LEN); // keep the old, now-stale MAC
    let mut out = header::encode_unsigned(&h2);
    out.extend_from_slice(&mac);
    stdfs::write(&p2, out).unwrap();
    assert!(matches!(
        Vault::recover(&p2, &rk2, b"x"),
        Err(Error::Tampered)
    ));
}

#[test]
fn keyslot_from_another_vault_is_rejected() {
    // Same password on both vaults. Without vault_id in the AAD, pasting
    // B's slot into A would "work" and hand you B's master key.
    let (_d, pa) = setup();
    let pb = pa.with_file_name("b.vault");
    Vault::init(&pa, b"same", KDF).unwrap();
    Vault::init(&pb, b"same", KDF).unwrap();

    let mut a = load(&pa);
    let b = load(&pb);
    a.slots.retain(|s| s.kind != SlotKind::Password);
    a.slots.push(
        b.slots
            .iter()
            .find(|s| s.kind == SlotKind::Password)
            .unwrap()
            .clone(),
    );
    store_unsigned(&pa, &a);

    assert!(matches!(
        Vault::unlock(&pa, b"same"),
        Err(Error::BadCredential)
    ));
}

#[test]
fn relabelled_slot_is_rejected() {
    let (_d, p) = setup();
    let (_v, rk) = Vault::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    for s in &mut h.slots {
        s.kind = match s.kind {
            SlotKind::Password => SlotKind::Recovery,
            SlotKind::Recovery => SlotKind::Password,
        };
    }
    store_unsigned(&p, &h);
    assert!(Vault::unlock(&p, b"pw").is_err());
    assert!(Vault::recover(&p, &rk, b"x").is_err());
}

#[test]
fn absurd_kdf_params_rejected_before_running_argon() {
    let (_d, p) = setup();
    Vault::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    h.kdf.mem_cost_kib = u32::MAX; // ~4 TB. If this ran, the test would OOM.
    store_unsigned(&p, &h);
    assert!(matches!(Vault::unlock(&p, b"pw"), Err(Error::BadKdfParams)));
}

#[test]
fn trailing_garbage_and_truncation_rejected() {
    let (_d, p) = setup();
    Vault::init(&p, b"pw", KDF).unwrap();
    let good = stdfs::read(&p).unwrap();

    let mut long = good.clone();
    long.push(0);
    stdfs::write(&p, &long).unwrap();
    assert!(matches!(Vault::unlock(&p, b"pw"), Err(Error::Corrupt)));

    for len in 0..good.len() {
        stdfs::write(&p, &good[..len]).unwrap();
        assert!(
            Vault::unlock(&p, b"pw").is_err(),
            "truncated to {len} bytes was accepted"
        );
    }
}

#[test]
fn not_a_vault_and_future_versions() {
    let (_d, p) = setup();
    stdfs::write(&p, b"definitely not a vault").unwrap();
    assert!(matches!(Vault::unlock(&p, b"pw"), Err(Error::BadMagic)));

    let mut future = header::MAGIC.to_vec();
    future.extend_from_slice(&2u16.to_le_bytes());
    stdfs::write(&p, &future).unwrap();
    assert!(matches!(
        Vault::unlock(&p, b"pw"),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn recovery_key_parsing() {
    let rk = RecoveryKey::generate();
    let shown = rk.reveal();
    assert_eq!(shown.len(), 64 + 7);
    assert_eq!(shown.matches('-').count(), 7);

    let a = RecoveryKey::parse(&shown).unwrap();
    let b = RecoveryKey::parse(&shown.to_uppercase()).unwrap();
    let c = RecoveryKey::parse(&shown.replace('-', "  ")).unwrap();
    assert_eq!(*a.reveal(), *shown);
    assert_eq!(*b.reveal(), *shown);
    assert_eq!(*c.reveal(), *shown);

    assert!(
        RecoveryKey::parse(&shown[..shown.len() - 1]).is_err(),
        "too short"
    );
    assert!(
        RecoveryKey::parse(&format!("{}-00", *shown)).is_err(),
        "too long"
    );
    assert!(RecoveryKey::parse(&shown.replacen(|c: char| c.is_ascii_hexdigit(), "g", 1)).is_err());
    assert_eq!(format!("{rk:?}"), "RecoveryKey(<redacted>)");
}

#[test]
fn vault_file_is_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = setup();
        Vault::init(&p, b"pw", KDF).unwrap();
        assert_eq!(
            stdfs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        Vault::change_password(&p, b"pw", b"pw2").unwrap();
        assert_eq!(
            stdfs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
