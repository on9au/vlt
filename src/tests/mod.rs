use std::{
    fs as stdfs,
    path::{Path, PathBuf},
};

use crate::{
    Error, Result,
    crypto::{RecoveryKey, random_key},
    fs,
    header::{self, Header, KdfParams, KeySlot, SlotId, SlotKind},
    ops::{self, SlotRef},
    slot::{Credential, NewSlot},
    vault::{LockedVault, Vault},
};

use tempfile::TempDir;

mod object;

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
/// runs *before* the MAC check (AAD, KDF bounds, slot limits).
fn store_unsigned(p: &Path, h: &Header) {
    let mut out = header::encode_unsigned(h);
    out.extend_from_slice(&[0u8; header::MAC_LEN]);
    stdfs::write(p, out).unwrap();
}

fn password_slot(h: &mut Header) -> &mut KeySlot {
    h.slots
        .iter_mut()
        .find(|s| matches!(s.kind, SlotKind::Password { .. }))
        .unwrap()
}

/// `n` copies of `slot` with fresh ids, so only the limit under test trips.
fn push_copies(h: &mut Header, slot: &KeySlot, n: usize) {
    for _ in 0..n {
        let mut s = slot.clone();
        s.id = h.next_slot_id;
        h.next_slot_id = SlotId(h.next_slot_id.0 + 1);
        h.slots.push(s);
    }
}

// The CLI's flows, as one-shot calls.

fn unlock(p: &Path, password: &[u8]) -> Result<Vault> {
    LockedVault::read(p)?.unlock(&Credential::Password(password))
}

fn change_password(p: &Path, old: &[u8], new: &[u8]) -> Result<Vault> {
    let mut v = unlock(p, old)?;
    let id = v.opened_by().unwrap();
    ops::set_password(&mut v, id, new)?;
    Ok(v)
}

fn recover(
    p: &Path,
    rk: &RecoveryKey,
    new: &[u8],
    choice: Option<SlotRef>,
    kdf: KdfParams,
) -> Result<Vault> {
    let mut v = LockedVault::read(p)?.unlock(&Credential::Recovery(rk))?;
    match ops::choose_password_slot(&v, choice)? {
        Some(id) => ops::set_password(&mut v, id, new)?,
        None => {
            ops::add_password(&mut v, new, kdf, None)?;
        }
    }
    Ok(v)
}

fn rotate_recovery(p: &Path, password: &[u8]) -> Result<(Vault, RecoveryKey)> {
    let mut v = unlock(p, password)?;
    let rk = ops::rotate_recovery(&mut v)?;
    Ok((v, rk))
}

#[test]
fn second_password_slot_unlocks_and_change_password_only_touches_its_own() {
    let (_d, p) = setup();
    let (mut v, rk) = ops::init(&p, b"first", KDF).unwrap();
    ops::add_password(&mut v, b"second", KDF, Some("laptop".into())).unwrap();
    assert_eq!(mk(&unlock(&p, b"first").unwrap()), mk(&v));
    assert_eq!(mk(&unlock(&p, b"second").unwrap()), mk(&v));

    change_password(&p, b"second", b"second2").unwrap();
    unlock(&p, b"first").unwrap();
    unlock(&p, b"second2").unwrap();
    assert!(unlock(&p, b"second").is_err());
    let labels: Vec<_> = load(&p).slots.into_iter().filter_map(|s| s.label).collect();
    assert_eq!(labels, ["laptop"], "label must survive a password change");

    // Recovery replaces exactly the chosen slot.
    recover(&p, &rk, b"fresh", Some(SlotRef::Label("laptop")), KDF).unwrap();
    unlock(&p, b"first").unwrap();
    unlock(&p, b"fresh").unwrap();
    assert!(unlock(&p, b"second2").is_err());
}

#[test]
fn recover_with_several_password_slots_needs_a_choice() {
    let (_d, p) = setup();
    let (mut v, rk) = ops::init(&p, b"first", KDF).unwrap();
    let slower = KdfParams {
        time_cost: 2,
        ..KDF
    };
    let laptop = ops::add_password(&mut v, b"second", slower, Some("laptop".into())).unwrap();
    assert_eq!(laptop, SlotId(2));
    let before = stdfs::read(&p).unwrap();

    // No guessing: refuse, list the choices, write nothing.
    match recover(&p, &rk, b"x", None, KDF) {
        Err(Error::SlotRequired(choices)) => {
            assert_eq!(choices, r#"0 (no label), 2 ("laptop")"#)
        }
        other => panic!("expected SlotRequired, got {other:?}"),
    }
    // 1 is the recovery slot, not a password slot.
    for bad in [
        SlotRef::Id(SlotId(1)),
        SlotRef::Id(SlotId(9)),
        SlotRef::Label("nope"),
    ] {
        assert!(matches!(
            recover(&p, &rk, b"x", Some(bad), KDF),
            Err(Error::NoSuchSlot)
        ));
    }
    assert_eq!(before, stdfs::read(&p).unwrap());

    // By id: only that slot changes, and it keeps its id, label and KDF params.
    recover(&p, &rk, b"fresh", Some(SlotRef::Id(laptop)), KDF).unwrap();
    unlock(&p, b"first").unwrap();
    unlock(&p, b"fresh").unwrap();
    assert!(unlock(&p, b"second").is_err());
    let h = load(&p);
    let slot = h.slot(laptop).unwrap();
    assert_eq!(slot.label.as_deref(), Some("laptop"));
    assert!(matches!(slot.kind, SlotKind::Password { kdf, .. } if kdf == slower));
}

#[test]
fn recover_with_no_password_slot_adds_one() {
    let (_d, p) = setup();
    let (mut v, rk) = ops::init(&p, b"pw", KDF).unwrap();
    let mut edit = v.edit();
    edit.remove(SlotId(0)).unwrap();
    edit.commit().unwrap();

    let chosen = KdfParams {
        time_cost: 2,
        ..KDF
    };
    recover(&p, &rk, b"fresh", None, chosen).unwrap();
    assert_eq!(mk(&unlock(&p, b"fresh").unwrap()), mk(&v));
    let mut h = load(&p);
    let slot = password_slot(&mut h);
    assert_eq!(slot.id, SlotId(2), "ids are never reused");
    assert!(matches!(slot.kind, SlotKind::Password { kdf, .. } if kdf == chosen));
}

#[test]
fn slot_ids_are_stable_across_edits() {
    let (_d, p) = setup();
    let (mut v, _rk) = ops::init(&p, b"pw", KDF).unwrap();
    ops::add_password(&mut v, b"two", KDF, None).unwrap();
    let ids = |p: &Path| load(p).slots.iter().map(|s| s.id.0).collect::<Vec<_>>();
    assert_eq!(ids(&p), [0, 1, 2]);

    // Rotating recovery and changing a password keep every id in place.
    rotate_recovery(&p, b"pw").unwrap();
    change_password(&p, b"pw", b"pw2").unwrap();
    assert_eq!(ids(&p), [0, 1, 2]);

    let mut v = unlock(&p, b"two").unwrap();
    assert_eq!(v.opened_by(), Some(SlotId(2)));
    let mut edit = v.edit();
    edit.remove(SlotId(2)).unwrap();
    edit.commit().unwrap();
    assert_eq!(
        ops::add_password(&mut v, b"three", KDF, None).unwrap(),
        SlotId(3)
    );
}

#[test]
fn edits_are_all_or_nothing() {
    let (_d, p) = setup();
    let (mut v, rk) = ops::init(&p, b"pw", KDF).unwrap();
    let before = stdfs::read(&p).unwrap();

    // Dropped without commit: nothing happens.
    let mut edit = v.edit();
    edit.remove(SlotId(0)).unwrap();
    drop(edit);
    assert_eq!(v.slots().count(), 2);

    // A commit that breaks a limit writes nothing and leaves `v` as it was.
    let mut edit = v.edit();
    for _ in 0..header::MAX_PASSWORD_SLOTS {
        edit.add(
            &NewSlot::Password {
                password: b"x",
                kdf: KDF,
            },
            None,
        )
        .unwrap();
    }
    assert!(matches!(edit.commit(), Err(Error::Limit(_))));

    let mut edit = v.edit();
    edit.remove(SlotId(0)).unwrap();
    edit.remove(SlotId(1)).unwrap();
    assert!(matches!(edit.commit(), Err(Error::Limit(_))));

    let mut edit = v.edit();
    let long = "x".repeat(header::MAX_LABEL_LEN + 1);
    edit.set_label(SlotId(0), Some(long)).unwrap();
    assert!(matches!(edit.commit(), Err(Error::Limit(_))));

    assert_eq!(before, stdfs::read(&p).unwrap());
    assert_eq!(v.slots().count(), 2);
    recover(&p, &rk, b"still", None, KDF).unwrap();
}

#[test]
fn locked_vault_lists_slots_before_unlock() {
    let (_d, p) = setup();
    let (mut v, _rk) = ops::init(&p, b"pw", KDF).unwrap();
    ops::add_password(&mut v, b"two", KDF, Some("phone".into())).unwrap();
    let locked = LockedVault::read(&p).unwrap();
    let kinds: Vec<_> = locked
        .slots()
        .map(|s| (s.id.0, s.is_password(), s.label))
        .collect();
    assert_eq!(
        kinds,
        [(0, true, None), (1, false, None), (2, true, Some("phone"))]
    );
}

#[test]
fn duplicate_or_unissued_slot_ids_rejected() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let good = load(&p);

    let mut h = good.clone();
    h.slots[1].id = h.slots[0].id;
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));

    let mut h = good;
    h.slots[1].id = h.next_slot_id;
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));
}

#[test]
fn too_many_password_slots_rejected_before_running_argon() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    let mut slot = password_slot(&mut h).clone();
    // Absurd params too: if any slot reached Argon2 the test would OOM.
    if let SlotKind::Password { kdf, .. } = &mut slot.kind {
        kdf.mem_cost_kib = 4 * 1024 * 1024;
        kdf.time_cost = 64;
    }
    push_copies(&mut h, &slot, header::MAX_PASSWORD_SLOTS);
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));
}

#[test]
fn too_many_slots_and_long_labels_rejected() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let good = load(&p);

    let mut h = good.clone();
    let recovery = h
        .slots
        .iter()
        .find(|s| matches!(s.kind, SlotKind::Recovery { .. }))
        .unwrap()
        .clone();
    push_copies(&mut h, &recovery, header::MAX_SLOTS);
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));

    let mut h = good;
    password_slot(&mut h).label = Some("x".repeat(header::MAX_LABEL_LEN + 1));
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));
}

#[cfg(unix)]
#[test]
fn stale_temp_file_is_not_followed_or_inherited() {
    use std::os::unix::fs::PermissionsExt;
    let (d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let tmp = fs::tmp_path(&p);

    // A planted symlink must not redirect the write.
    let victim = d.path().join("victim");
    stdfs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, &tmp).unwrap();
    change_password(&p, b"pw", b"pw2").unwrap();
    assert_eq!(stdfs::read(&victim).unwrap(), b"untouched");
    unlock(&p, b"pw2").unwrap();

    // A leftover world-readable temp must not hand its mode to the vault.
    stdfs::write(&tmp, b"stale").unwrap();
    stdfs::set_permissions(&tmp, stdfs::Permissions::from_mode(0o644)).unwrap();
    change_password(&p, b"pw2", b"pw3").unwrap();
    assert_eq!(
        stdfs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!tmp.exists());
}

#[test]
fn init_then_unlock_gives_same_master_key() {
    let (_d, p) = setup();
    let (v, _rk) = ops::init(&p, b"hunter2hunter2", KDF).unwrap();
    let v2 = unlock(&p, b"hunter2hunter2").unwrap();
    assert_eq!(mk(&v), mk(&v2));
    assert_eq!(v.id(), v2.id());
}

#[test]
fn wrong_password_fails_cleanly() {
    let (_d, p) = setup();
    ops::init(&p, b"correct horse", KDF).unwrap();
    assert!(matches!(
        unlock(&p, b"wrong horse"),
        Err(Error::BadCredential)
    ));
    assert!(matches!(unlock(&p, b""), Err(Error::BadCredential)));
}

#[test]
fn init_refuses_to_overwrite() {
    let (_d, p) = setup();
    ops::init(&p, b"a", KDF).unwrap();
    let before = stdfs::read(&p).unwrap();
    assert!(matches!(
        ops::init(&p, b"b", KDF),
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
    let (v, rk) = ops::init(&p, b"old", KDF).unwrap();
    let original = mk(&v);

    assert!(matches!(
        change_password(&p, b"not old", b"new"),
        Err(Error::BadCredential)
    ));
    let v2 = change_password(&p, b"old", b"new").unwrap();
    assert_eq!(mk(&v2), original, "MK must never change");

    assert!(matches!(unlock(&p, b"old"), Err(Error::BadCredential)));
    assert_eq!(mk(&unlock(&p, b"new").unwrap()), original);

    // Recovery key still works after a password change.
    let v3 = recover(&p, &rk, b"newer", None, KDF).unwrap();
    assert_eq!(mk(&v3), original);
}

#[test]
fn recover_resets_password() {
    let (_d, p) = setup();
    let (v, rk) = ops::init(&p, b"forgotten", KDF).unwrap();
    let rk = RecoveryKey::parse(&rk.reveal()).unwrap(); // round-trip through the printed form
    recover(&p, &rk, b"fresh", None, KDF).unwrap();
    assert!(matches!(
        unlock(&p, b"forgotten"),
        Err(Error::BadCredential)
    ));
    assert_eq!(mk(&unlock(&p, b"fresh").unwrap()), mk(&v));
}

#[test]
fn wrong_recovery_key_fails() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let bogus = RecoveryKey::generate();
    assert!(matches!(
        recover(&p, &bogus, b"x", None, KDF),
        Err(Error::BadCredential)
    ));
    // And the password slot must be untouched by the failed attempt.
    unlock(&p, b"pw").unwrap();
}

#[test]
fn rotate_recovery_kills_old_key() {
    let (_d, p) = setup();
    let (_v, old_rk) = ops::init(&p, b"pw", KDF).unwrap();
    let (_v, new_rk) = rotate_recovery(&p, b"pw").unwrap();
    assert!(matches!(
        recover(&p, &old_rk, b"x", None, KDF),
        Err(Error::BadCredential)
    ));
    recover(&p, &new_rk, b"x", None, KDF).unwrap();
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let good = stdfs::read(&p).unwrap();
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            stdfs::write(&p, &bad).unwrap();
            assert!(
                unlock(&p, b"pw").is_err(),
                "flip at byte {i} bit {bit} was accepted"
            );
        }
    }
    stdfs::write(&p, &good).unwrap();
    unlock(&p, b"pw").unwrap();
}

#[test]
fn tampering_with_the_other_slot_is_caught() {
    // The bug the bit-flip test originally found: corrupting the recovery
    // slot didn't affect password unlock, so you'd never know until the
    // day you actually needed recovery.
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    let s = h
        .slots
        .iter_mut()
        .find(|s| matches!(s.kind, SlotKind::Recovery { .. }))
        .unwrap();
    s.wrapped_mk[0] ^= 1;
    // Re-sign with a *wrong* MK to prove the MAC is keyed, not just a checksum.
    let fake = Vault::new_test(p.clone(), h.clone(), random_key());
    stdfs::write(&p, fake.serialize_test(&h)).unwrap();
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Tampered)));

    // Same the other way round: mess with the password slot, recover path notices.
    let (_d2, p2) = setup();
    let (_v, rk2) = ops::init(&p2, b"pw", KDF).unwrap();
    let mut bytes = stdfs::read(&p2).unwrap();
    let mut h2 = header::decode(&bytes).unwrap().header;
    let SlotKind::Password { salt, .. } = &mut password_slot(&mut h2).kind else {
        unreachable!()
    };
    salt[0] ^= 1;
    let mac = bytes.split_off(bytes.len() - header::MAC_LEN); // keep the old, now-stale MAC
    let mut out = header::encode_unsigned(&h2);
    out.extend_from_slice(&mac);
    stdfs::write(&p2, out).unwrap();
    assert!(matches!(
        recover(&p2, &rk2, b"x", None, KDF),
        Err(Error::Tampered)
    ));
}

#[test]
fn keyslot_from_another_vault_is_rejected() {
    // Same password on both vaults. Without vault_id in the AAD, pasting
    // B's slot into A would "work" and hand you B's master key.
    let (_d, pa) = setup();
    let pb = pa.with_file_name("b.vault");
    ops::init(&pa, b"same", KDF).unwrap();
    ops::init(&pb, b"same", KDF).unwrap();

    let mut a = load(&pa);
    let b = load(&pb);
    a.slots
        .retain(|s| !matches!(s.kind, SlotKind::Password { .. }));
    a.slots.push(
        b.slots
            .iter()
            .find(|s| matches!(s.kind, SlotKind::Password { .. }))
            .unwrap()
            .clone(),
    );
    store_unsigned(&pa, &a);

    assert!(matches!(unlock(&pa, b"same"), Err(Error::BadCredential)));
}

#[test]
fn relabelled_slot_is_rejected() {
    let (_d, p) = setup();
    let (_v, rk) = ops::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    for s in &mut h.slots {
        s.kind = match s.kind {
            SlotKind::Password { salt, .. } => SlotKind::Recovery { salt },
            SlotKind::Recovery { salt } => SlotKind::Password { salt, kdf: KDF },
        };
    }
    store_unsigned(&p, &h);
    assert!(unlock(&p, b"pw").is_err());
    assert!(recover(&p, &rk, b"x", None, KDF).is_err());
}

#[test]
fn absurd_kdf_params_rejected_before_running_argon() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let mut h = load(&p);
    let SlotKind::Password { kdf, .. } = &mut password_slot(&mut h).kind else {
        unreachable!()
    };
    kdf.mem_cost_kib = u32::MAX; // ~4 TB. If this ran, the test would OOM.
    store_unsigned(&p, &h);
    assert!(matches!(unlock(&p, b"pw"), Err(Error::BadKdfParams)));
}

#[test]
fn trailing_garbage_and_truncation_rejected() {
    let (_d, p) = setup();
    ops::init(&p, b"pw", KDF).unwrap();
    let good = stdfs::read(&p).unwrap();

    let mut long = good.clone();
    long.push(0);
    stdfs::write(&p, &long).unwrap();
    assert!(matches!(unlock(&p, b"pw"), Err(Error::Corrupt)));

    for len in 0..good.len() {
        stdfs::write(&p, &good[..len]).unwrap();
        assert!(
            unlock(&p, b"pw").is_err(),
            "truncated to {len} bytes was accepted"
        );
    }
}

#[test]
fn not_a_vault_and_future_versions() {
    let (_d, p) = setup();
    stdfs::write(&p, b"definitely not a vault").unwrap();
    assert!(matches!(unlock(&p, b"pw"), Err(Error::BadMagic)));

    let mut future = header::MAGIC.to_vec();
    future.extend_from_slice(&2u16.to_le_bytes());
    stdfs::write(&p, &future).unwrap();
    assert!(matches!(
        unlock(&p, b"pw"),
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
        ops::init(&p, b"pw", KDF).unwrap();
        assert_eq!(
            stdfs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        change_password(&p, b"pw", b"pw2").unwrap();
        assert_eq!(
            stdfs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
