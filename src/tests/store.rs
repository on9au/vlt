use std::{
    fs as stdfs,
    path::{Path, PathBuf},
};

use super::{KDF, change_password, unlock};
use crate::{
    Error,
    crypto::RecoveryKey,
    fs,
    manifest::Listing,
    object::CHUNK_LEN,
    store::{self, Meta, Store},
};

use tempfile::TempDir;

fn setup() -> (TempDir, PathBuf, Store, RecoveryKey) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("my.vault");
    let (s, rk) = store::init(&root, b"pw", KDF).unwrap();
    (dir, root, s, rk)
}

fn reopen(root: &Path) -> Store {
    Store::open(root, unlock(&store::header_path(root), b"pw").unwrap()).unwrap()
}

fn get(s: &Store, path: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    s.get(path, &mut out)?;
    Ok(out)
}

/// Every file under `root`, relative, sorted.
fn files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for e in stdfs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                out.push(p.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn objects(root: &Path) -> Vec<String> {
    files(root)
        .into_iter()
        .filter(|f| f.starts_with("objects/"))
        .collect()
}

#[test]
fn init_lays_out_the_directory_and_refuses_existing() {
    let (d, root, _s, _rk) = setup();
    assert_eq!(files(&root), ["header", "lock", "manifest"]);
    assert!(root.join("objects").is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| stdfs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("objects")), 0o700);
    }
    assert!(matches!(
        store::init(&root, b"pw", KDF),
        Err(Error::AlreadyExists)
    ));
    let empty = d.path().join("empty");
    stdfs::create_dir(&empty).unwrap();
    assert!(matches!(
        store::init(&empty, b"pw", KDF),
        Err(Error::AlreadyExists)
    ));
}

#[test]
fn add_get_list_remove_and_persist() {
    let (_d, root, mut s, _rk) = setup();
    let big: Vec<u8> = (0..3 * CHUNK_LEN + 5).map(|i| i as u8).collect();
    assert_eq!(
        s.add("tax/2025.pdf", &big[..], false).unwrap(),
        big.len() as u64
    );
    s.add("/notes.txt", &b"hi"[..], false).unwrap();
    s.add("tax/old/2019.pdf", &b""[..], false).unwrap();

    // Everything survives a fresh unlock.
    drop(s); // releases the lock
    let s = reopen(&root);
    assert_eq!(get(&s, "tax/2025.pdf").unwrap(), big);
    assert_eq!(get(&s, "notes.txt").unwrap(), b"hi");
    assert_eq!(get(&s, "tax/old/2019.pdf").unwrap(), b"");
    assert_eq!(
        s.list("/").unwrap(),
        [
            Listing::File {
                name: "notes.txt",
                size: 2
            },
            Listing::Dir { name: "tax" },
        ]
    );
    assert_eq!(objects(&root).len(), 3);

    let mut s = s;
    s.remove("tax/2025.pdf").unwrap();
    assert!(matches!(get(&s, "tax/2025.pdf"), Err(Error::NoSuchPath)));
    assert!(matches!(s.remove("tax/2025.pdf"), Err(Error::NoSuchPath)));
    assert_eq!(objects(&root).len(), 2, "object deleted with its entry");
    s.remove("notes.txt").unwrap();
    s.remove("tax/old/2019.pdf").unwrap();
    assert_eq!(
        stdfs::read_dir(root.join("objects")).unwrap().count(),
        0,
        "empty fan-out dirs pruned"
    );
    drop(s);
    assert!(matches!(
        get(&reopen(&root), "tax/2025.pdf"),
        Err(Error::NoSuchPath)
    ));
}

#[test]
fn nothing_on_disk_reveals_names_or_contents() {
    let (_d, root, mut s, _rk) = setup();
    s.add("secret-name.txt", &b"secret-contents"[..], false)
        .unwrap();
    for f in files(&root) {
        assert!(!f.contains("secret"), "name leaked in {f}");
        let bytes = stdfs::read(root.join(&f)).unwrap();
        assert!(
            !bytes.windows(6).any(|w| w == b"secret"),
            "plaintext leaked in {f}"
        );
    }
}

#[test]
fn replace_only_when_asked_and_old_object_goes() {
    let (_d, root, mut s, _rk) = setup();
    s.add("a", &b"one"[..], false).unwrap();
    let before = objects(&root);
    assert!(matches!(
        s.add("a", &b"two"[..], false),
        Err(Error::PathExists)
    ));
    assert_eq!(objects(&root), before, "refused add leaves no orphan");

    s.add("a", &b"two"[..], true).unwrap();
    assert_eq!(get(&s, "a").unwrap(), b"two");
    let after = objects(&root);
    assert_eq!(after.len(), 1);
    assert_ne!(after, before, "replaced object deleted");
}

#[test]
fn bad_paths_and_conflicts_write_nothing() {
    let (_d, root, mut s, _rk) = setup();
    s.add("dir/file", &b"x"[..], false).unwrap();
    let manifest_before = stdfs::read(root.join("manifest")).unwrap();
    for (path, want) in [
        ("../escape", "BadPath"),
        ("a//b", "BadPath"),
        ("dir/file/child", "BadPath"),
        ("dir", "PathExists"),
    ] {
        let err = s.add(path, &b"y"[..], true).unwrap_err();
        assert!(format!("{err:?}").starts_with(want), "{path}: {err:?}");
    }
    assert_eq!(objects(&root).len(), 1);
    assert_eq!(stdfs::read(root.join("manifest")).unwrap(), manifest_before);
}

#[test]
fn get_to_file_never_clobbers_and_never_leaves_partial_plaintext() {
    let (d, root, mut s, _rk) = setup();
    let data: Vec<u8> = (0..2 * CHUNK_LEN).map(|i| (i * 7) as u8).collect();
    s.add("f", &data[..], false).unwrap();

    let out = d.path().join("out");
    s.get_to_file("f", &out).unwrap();
    assert_eq!(stdfs::read(&out).unwrap(), data);
    assert!(matches!(
        s.get_to_file("f", &out),
        Err(Error::AlreadyExists)
    ));

    // Corrupt the last chunk: chunk 0 decrypts fine and gets written to the
    // temp, but neither the temp nor the destination may survive.
    let obj = root.join(&objects(&root)[0]);
    let mut bytes = stdfs::read(&obj).unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    stdfs::write(&obj, bytes).unwrap();
    let out2 = d.path().join("out2");
    assert!(matches!(s.get_to_file("f", &out2), Err(Error::BadObject)));
    assert!(!out2.exists());
    assert!(!fs::tmp_path(&out2).exists());
}

#[test]
fn swapped_objects_are_caught() {
    let (_d, root, mut s, _rk) = setup();
    s.add("a", &b"aaa"[..], false).unwrap();
    s.add("b", &b"bbb"[..], false).unwrap();
    let objs = objects(&root);
    let (pa, pb) = (root.join(&objs[0]), root.join(&objs[1]));
    let (a, b) = (stdfs::read(&pa).unwrap(), stdfs::read(&pb).unwrap());
    stdfs::write(&pa, &b).unwrap();
    stdfs::write(&pb, &a).unwrap();
    assert!(matches!(get(&s, "a"), Err(Error::BadObject)));
    assert!(matches!(get(&s, "b"), Err(Error::BadObject)));
}

#[test]
fn manifest_tampering_missing_or_foreign_is_an_error() {
    let (d, root, mut s, _rk) = setup();
    s.add("a", &b"x"[..], false).unwrap();
    let good = stdfs::read(root.join("manifest")).unwrap();
    drop(s); // releases the lock
    let open = |root: &Path| Store::open(root, unlock(&store::header_path(root), b"pw").unwrap());

    let mut bad = good.clone();
    bad[20] ^= 1;
    stdfs::write(root.join("manifest"), &bad).unwrap();
    assert!(matches!(open(&root), Err(Error::BadManifest)));

    // Missing is an error, never silently "empty".
    stdfs::remove_file(root.join("manifest")).unwrap();
    assert!(matches!(open(&root), Err(Error::Io(_))));

    // Another vault's manifest (same password) doesn't open here.
    let other = d.path().join("other.vault");
    store::init(&other, b"pw", KDF).unwrap();
    stdfs::copy(other.join("manifest"), root.join("manifest")).unwrap();
    assert!(matches!(open(&root), Err(Error::BadManifest)));

    stdfs::write(root.join("manifest"), &good).unwrap();
    open(&root).unwrap();
}

#[test]
fn password_change_keeps_the_files() {
    let (_d, root, mut s, _rk) = setup();
    s.add("a", &b"x"[..], false).unwrap();
    drop(s); // releases the lock
    change_password(&store::header_path(&root), b"pw", b"pw2").unwrap();
    let v = unlock(&store::header_path(&root), b"pw2").unwrap();
    assert_eq!(get(&Store::open(&root, v).unwrap(), "a").unwrap(), b"x");
}

/// A small tree on disk:
/// src/a.txt, src/sub/b.txt, src/sub/deep/c.bin, src/empty/, plus (unix) a
/// symlink and a file whose name can't be a vault path.
fn make_tree(base: &Path) -> PathBuf {
    let src = base.join("src");
    stdfs::create_dir_all(src.join("sub/deep")).unwrap();
    stdfs::create_dir_all(src.join("empty")).unwrap();
    stdfs::write(src.join("a.txt"), b"alpha").unwrap();
    stdfs::write(src.join("sub/b.txt"), b"beta").unwrap();
    stdfs::write(src.join("sub/deep/c.bin"), vec![7u8; CHUNK_LEN + 3]).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        stdfs::write(src.join("back\\slash"), b"x").unwrap();
    }
    src
}

#[test]
fn uncommitted_tx_leaves_no_trace() {
    let (_d, root, mut s, _rk) = setup();
    s.add("keep", &b"k"[..], false).unwrap();
    let manifest_before = stdfs::read(root.join("manifest")).unwrap();
    let objects_before = objects(&root);

    let mut tx = s.begin();
    tx.add("one", &b"1"[..], Meta::default(), false).unwrap();
    tx.add("two", &b"2"[..], Meta::default(), false).unwrap();
    tx.remove("keep").unwrap();
    drop(tx);

    assert_eq!(objects(&root), objects_before, "written objects deleted");
    assert_eq!(stdfs::read(root.join("manifest")).unwrap(), manifest_before);
    assert_eq!(get(&s, "keep").unwrap(), b"k", "removed object kept");
    assert!(matches!(get(&s, "one"), Err(Error::NoSuchPath)));
}

#[test]
fn add_tree_then_get_tree_round_trips() {
    let (d, root, mut s, _rk) = setup();
    let src = make_tree(d.path());
    let mut tx = s.begin();
    let report = tx.add_tree(&src, "docs", false).unwrap();
    tx.commit().unwrap();
    assert_eq!(report.files, 3);
    assert_eq!(report.bytes, 5 + 4 + CHUNK_LEN as u64 + 3);
    #[cfg(unix)]
    assert_eq!(
        report.skipped,
        [src.join("back\\slash"), src.join("link")],
        "symlinks and unusable names skipped, not followed or mangled"
    );
    assert_eq!(objects(&root).len(), 3);

    let out = d.path().join("out");
    assert_eq!(s.get_tree("docs", &out).unwrap().0, 3);
    assert_eq!(stdfs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(stdfs::read(out.join("sub/b.txt")).unwrap(), b"beta");
    assert_eq!(
        stdfs::read(out.join("sub/deep/c.bin")).unwrap(),
        stdfs::read(src.join("sub/deep/c.bin")).unwrap()
    );
    assert!(!out.join("link").exists());
    assert!(matches!(
        s.get_tree("docs", &out),
        Err(Error::AlreadyExists)
    ));

    // A subdirectory, and the whole vault.
    s.get_tree("docs/sub", &d.path().join("sub")).unwrap();
    assert_eq!(
        stdfs::read(d.path().join("sub/deep/c.bin")).unwrap().len(),
        CHUNK_LEN + 3
    );
    s.get_tree("/", &d.path().join("all")).unwrap();
    assert!(d.path().join("all/docs/a.txt").is_file());
    assert!(matches!(
        s.get_tree("nope", &d.path().join("x")),
        Err(Error::NoSuchPath)
    ));
}

#[test]
fn add_tree_checks_every_path_before_encrypting_anything() {
    let (d, root, mut s, _rk) = setup();
    let src = make_tree(d.path());
    // `docs/sub/b.txt` is taken, so the whole tree must be refused up front.
    s.add("docs/sub/b.txt", &b"old"[..], false).unwrap();
    let before = objects(&root);
    let mut tx = s.begin();
    assert!(matches!(
        tx.add_tree(&src, "docs", false),
        Err(Error::PathExists)
    ));
    drop(tx);
    assert_eq!(objects(&root), before);

    let mut tx = s.begin();
    tx.add_tree(&src, "docs", true).unwrap();
    tx.commit().unwrap();
    assert_eq!(get(&s, "docs/sub/b.txt").unwrap(), b"beta");
    assert_eq!(objects(&root).len(), 3, "replaced object deleted");
}

#[cfg(unix)]
#[test]
fn metadata_is_kept_but_never_setuid() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let (d, _root, mut s, _rk) = setup();
    let mtime = UNIX_EPOCH + Duration::new(1_600_000_000, 500);
    let mut tx = s.begin();
    let meta = |mode| Meta {
        mtime: Some(mtime),
        mode: Some(mode),
    };
    tx.add("script", &b"#!/bin/sh"[..], meta(0o4755), false)
        .unwrap();
    tx.add("ro", &b"r"[..], meta(0o444), false).unwrap();
    tx.commit().unwrap();

    let out = d.path().join("script");
    s.get_to_file("script", &out).unwrap();
    let md = stdfs::metadata(&out).unwrap();
    assert_eq!(md.permissions().mode() & 0o7777, 0o755, "setuid dropped");
    assert_eq!(md.modified().unwrap(), mtime);

    // Read-only: mtime still applied (set before the mode).
    let ro = d.path().join("ro");
    s.get_to_file("ro", &ro).unwrap();
    let md = stdfs::metadata(&ro).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o444);
    assert_eq!(md.modified().unwrap(), mtime);

    // No metadata: a plain private file, mtime is "now".
    s.add("plain", &b"p"[..], false).unwrap();
    let plain = d.path().join("plain");
    s.get_to_file("plain", &plain).unwrap();
    let md = stdfs::metadata(&plain).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    assert!(md.modified().unwrap() > SystemTime::now() - Duration::from_secs(60));
}

#[test]
fn mv_and_rm_r_only_touch_the_manifest_and_the_right_objects() {
    let (d, root, mut s, _rk) = setup();
    let src = make_tree(d.path());
    let mut tx = s.begin();
    tx.add_tree(&src, "docs", false).unwrap();
    tx.commit().unwrap();
    s.add("other", &b"o"[..], false).unwrap();
    let before = objects(&root);

    let mut tx = s.begin();
    assert_eq!(tx.rename("docs/sub", "archive/2024").unwrap(), 2);
    tx.commit().unwrap();
    assert_eq!(objects(&root), before, "mv moves no objects");
    assert_eq!(get(&s, "archive/2024/b.txt").unwrap(), b"beta");
    assert!(matches!(get(&s, "docs/sub/b.txt"), Err(Error::NoSuchPath)));

    let mut tx = s.begin();
    assert_eq!(tx.remove_dir("archive").unwrap(), 2);
    tx.commit().unwrap();
    assert_eq!(objects(&root).len(), 2, "docs/a.txt and other remain");
    assert_eq!(get(&s, "other").unwrap(), b"o");
}

#[test]
fn second_open_is_locked_out() {
    let (d, root, s, _rk) = setup();
    let v = unlock(&store::header_path(&root), b"pw").unwrap();
    assert!(matches!(Store::open(&root, v), Err(Error::Locked)));
    assert!(matches!(store::lock(&root), Err(Error::Locked)));
    drop(s);
    let lock = store::lock(&root).unwrap();
    drop(lock);
    reopen(&root);

    // Not a vault: refused, and no stray lock file created.
    let plain = d.path().join("plain");
    stdfs::create_dir(&plain).unwrap();
    assert!(store::lock(&plain).is_err());
    assert!(!plain.join("lock").exists());
}

#[test]
fn fsck_reports_and_gc_cleans_only_what_it_should() {
    let (_d, root, mut s, _rk) = setup();
    s.add("good", &b"g"[..], false).unwrap();
    s.add("gone", &b"x"[..], false).unwrap();
    s.add("bad", &b"b"[..], false).unwrap();
    assert!(s.check(true).unwrap().is_clean());

    // An orphan, the way a crash leaves one: object written, never committed.
    let mut tx = s.begin();
    tx.add("never", &b"n"[..], Meta::default(), false).unwrap();
    std::mem::forget(tx);
    let orphan = objects(&root)
        .into_iter()
        .map(|o| root.join(o))
        .find(|p| {
            s.manifest()
                .entries()
                .all(|(_, e)| !p.ends_with(e.object.to_string()))
        })
        .unwrap();

    let path_of = |s: &Store, name: &str| {
        let id = s.manifest().get(name).unwrap().object.to_string();
        root.join("objects").join(&id[..2]).join(id)
    };
    stdfs::remove_file(path_of(&s, "gone")).unwrap();
    let bad = path_of(&s, "bad");
    let mut bytes = stdfs::read(&bad).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    stdfs::write(&bad, bytes).unwrap();
    let fan = root.join("objects/ab");
    stdfs::create_dir_all(&fan).unwrap();
    stdfs::write(fan.join(".deadbeef.tmp"), b"t").unwrap();
    stdfs::write(root.join(".manifest.tmp"), b"t").unwrap();
    stdfs::write(root.join("objects/README"), b"not ours").unwrap();
    stdfs::create_dir(root.join("objects/zz")).unwrap(); // empty, not ours

    let r = s.check(false).unwrap();
    assert_eq!(r.missing, ["gone"]);
    assert_eq!(r.orphans, std::slice::from_ref(&orphan));
    assert_eq!(r.temps.len(), 2);
    assert_eq!(
        r.unknown,
        [root.join("objects/README"), root.join("objects/zz")]
    );
    assert!(r.corrupt.is_empty(), "only found with verify");
    let r = s.check(true).unwrap();
    assert_eq!(r.corrupt.len(), 1);
    assert_eq!(r.corrupt[0].0, "bad");

    let r = s.gc().unwrap();
    assert_eq!(r.orphans, std::slice::from_ref(&orphan));
    assert!(!orphan.exists());
    assert!(!fan.exists(), "emptied fan-out dir pruned");
    assert!(!root.join(".manifest.tmp").exists());
    assert!(
        root.join("objects/README").exists(),
        "never deletes what it didn't make"
    );
    assert!(root.join("objects/zz").is_dir(), "not even an empty dir");
    assert_eq!(get(&s, "good").unwrap(), b"g");

    let r = s.check(false).unwrap();
    assert!(r.orphans.is_empty() && r.temps.is_empty());
    assert_eq!(r.missing, ["gone"]);
}
