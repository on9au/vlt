use super::{KDF, setup};
use crate::{
    Error,
    manifest::{self, Entry, Listing, Manifest},
    object::ObjectId,
    ops,
};

fn entry(n: u8, size: u64) -> Entry {
    Entry {
        object: ObjectId([n; 16]),
        size,
        mtime: None,
        mode: None,
    }
}

fn manifest(paths: &[&str]) -> Manifest {
    let mut m = Manifest::default();
    for (i, p) in paths.iter().enumerate() {
        m.insert(p.to_string(), entry(i as u8, i as u64), false)
            .unwrap();
    }
    m
}

#[test]
fn paths_are_normalized_or_rejected() {
    assert_eq!(manifest::file_path("a/b.txt").unwrap(), "a/b.txt");
    assert_eq!(manifest::file_path("/a/b.txt/").unwrap(), "a/b.txt");
    assert_eq!(manifest::dir_path("/").unwrap(), "");
    assert_eq!(manifest::dir_path("").unwrap(), "");
    for bad in [
        "", "/", "a//b", "../x", "a/../b", "./a", "a/.", "a\\b", "a\0b",
    ] {
        assert!(
            matches!(manifest::file_path(bad), Err(Error::BadPath(_))),
            "{bad:?} accepted"
        );
    }
    let long = "x".repeat(manifest::MAX_PATH_LEN + 1);
    assert!(manifest::file_path(&long).is_err());
}

#[test]
fn listing_shows_immediate_children() {
    let m = manifest(&["a.txt", "b/one", "b/two", "b/c/deep", "b.txt", "z"]);
    assert_eq!(
        m.list("").unwrap(),
        [
            Listing::File {
                name: "a.txt",
                size: 0
            },
            // `.` sorts before `/`
            Listing::File {
                name: "b.txt",
                size: 4
            },
            Listing::Dir { name: "b" },
            Listing::File { name: "z", size: 5 },
        ]
    );
    assert_eq!(
        m.list("b").unwrap(),
        [
            Listing::Dir { name: "c" },
            Listing::File {
                name: "one",
                size: 1
            },
            Listing::File {
                name: "two",
                size: 2
            },
        ]
    );
    // A file lists as itself; a missing dir is an error, the root never is.
    assert_eq!(
        m.list("b/one").unwrap(),
        [Listing::File {
            name: "b/one",
            size: 1
        }]
    );
    assert!(matches!(m.list("nope"), Err(Error::NoSuchPath)));
    assert!(Manifest::default().list("").unwrap().is_empty());
}

#[test]
fn a_path_cant_be_both_file_and_directory() {
    let mut m = manifest(&["a/b"]);
    // `a` is a directory.
    assert!(matches!(
        m.insert("a".into(), entry(9, 0), true),
        Err(Error::PathExists)
    ));
    // `a/b` is a file, so it can't have children.
    assert!(matches!(
        m.insert("a/b/c".into(), entry(9, 0), true),
        Err(Error::BadPath(_))
    ));
    // Same path: only with `replace`, and the old entry comes back.
    assert!(matches!(
        m.insert("a/b".into(), entry(9, 0), false),
        Err(Error::PathExists)
    ));
    let old = m.insert("a/b".into(), entry(9, 0), true).unwrap();
    assert_eq!(old, Some(entry(0, 0)));
    // `ab` and `a.b` share a prefix with `a` but aren't under it.
    m.insert("ab".into(), entry(1, 0), false).unwrap();
    m.insert("a.b".into(), entry(2, 0), false).unwrap();
}

#[test]
fn seal_open_round_trip_and_tampering() {
    let (_d, p) = setup();
    let (v, _rk) = ops::init(&p, b"pw", KDF).unwrap();
    let m = manifest(&["secret-name.pdf", "dir/other"]);
    let sealed = m.seal(&v);
    assert_eq!(Manifest::open(&v, &sealed).unwrap(), m);
    assert!(
        !sealed.windows(11).any(|w| w == b"secret-name"),
        "names must not appear in the clear"
    );
    assert_ne!(sealed, m.seal(&v), "fresh nonce per write");

    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x10;
        assert!(Manifest::open(&v, &bad).is_err(), "flip at {i} accepted");
    }
    for len in 0..sealed.len() {
        assert!(Manifest::open(&v, &sealed[..len]).is_err());
    }

    // Another vault's manifest doesn't open, even though the format is fine.
    let (_d2, p2) = setup();
    let (other, _) = ops::init(&p2, b"pw", KDF).unwrap();
    assert!(matches!(
        Manifest::open(&other, &sealed),
        Err(Error::BadManifest)
    ));
}

#[test]
fn rename_moves_files_and_whole_directories() {
    let mut m = manifest(&["a/x", "a/sub/y", "ab", "f"]);
    assert_eq!(m.rename("a", "b/c").unwrap(), 2);
    assert_eq!(
        m.entries().map(|(p, _)| p).collect::<Vec<_>>(),
        ["ab", "b/c/sub/y", "b/c/x", "f"]
    );
    assert_eq!(m.get("b/c/x"), Some(&entry(0, 0)), "entry travels intact");

    assert_eq!(m.rename("f", "g").unwrap(), 1);
    assert!(m.get("f").is_none() && m.get("g").is_some());
}

#[test]
fn rename_never_merges_overwrites_or_half_applies() {
    let m = manifest(&["a/x", "a/y", "b/y", "file"]);
    for (from, to, want) in [
        ("a", "b", "PathExists"),    // b exists (as a directory)
        ("a", "file", "PathExists"), // file exists
        ("a", "file/z", "BadPath"),  // parent is a file
        ("a", "a/inner", "BadPath"), // into itself
        ("a", "a", "BadPath"),
        ("nope", "z", "NoSuchPath"),
        ("a", "", "BadPath"),
    ] {
        let mut m2 = m.clone();
        let err = m2.rename(from, to).unwrap_err();
        assert!(
            format!("{err:?}").starts_with(want),
            "{from}->{to}: {err:?}"
        );
        assert_eq!(m2, m, "{from}->{to} must leave the manifest untouched");
    }
}

#[test]
fn remove_dir_takes_everything_under_it_but_never_the_root() {
    let mut m = manifest(&["a/x", "a/sub/y", "ab"]);
    assert!(matches!(m.remove_dir(""), Err(Error::BadPath(_))));
    assert!(matches!(m.remove_dir("nope"), Err(Error::NoSuchPath)));
    assert_eq!(m.remove_dir("a").unwrap().len(), 2);
    assert_eq!(m.entries().map(|(p, _)| p).collect::<Vec<_>>(), ["ab"]);
}

#[test]
fn files_under_gives_relative_paths() {
    let m = manifest(&["a/x", "a/sub/y", "ab"]);
    let rel = |d| m.files_under(d).map(|(p, _)| p).collect::<Vec<_>>();
    assert_eq!(rel("a"), ["sub/y", "x"]);
    assert_eq!(rel(""), ["a/sub/y", "a/x", "ab"]);
    assert!(rel("nope").is_empty());
}

#[test]
fn mtime_round_trips_including_before_the_epoch() {
    use crate::manifest::Mtime;
    use std::time::{Duration, UNIX_EPOCH};
    for t in [
        UNIX_EPOCH,
        UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
        UNIX_EPOCH - Duration::new(5, 0),
        UNIX_EPOCH - Duration::new(5, 250_000_000),
    ] {
        let m = Mtime::from_system(t);
        assert!(m.nanos < 1_000_000_000);
        assert_eq!(m.to_system(), Some(t));
    }
    assert_eq!(
        Mtime::from_system(UNIX_EPOCH - Duration::new(5, 250_000_000)),
        Mtime {
            secs: -6,
            nanos: 750_000_000
        }
    );
}
