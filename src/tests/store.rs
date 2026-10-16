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
    store::{self, Store},
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
    assert_eq!(files(&root), ["header", "manifest"]);
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
    change_password(&store::header_path(&root), b"pw", b"pw2").unwrap();
    let v = unlock(&store::header_path(&root), b"pw2").unwrap();
    assert_eq!(get(&Store::open(&root, v).unwrap(), "a").unwrap(), b"x");
}
