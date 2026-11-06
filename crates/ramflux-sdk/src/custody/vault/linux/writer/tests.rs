// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::{cleanup::Secret, codec::Plaintext};
use super::*;
use std::{
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::Path,
    process::Command,
    sync::Barrier,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn setup(root: &Path, realm: u8) -> TestResult<Arc<Store>> {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    Ok(Arc::new(Store::open(root, "alice", realm, [1; 16], [2; 16])?))
}
fn reference(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn record(store: &Store, kind: u8, name: &str, generation: u64, value: u8) -> TestResult<Vec<u8>> {
    let len = match kind {
        1 => 32,
        2 => 64,
        _ => 31,
    };
    let mut source = Secret::<64>::new("p03-fixture-source");
    source.bytes_mut()[..len].fill(value);
    let input = Plaintext::new(&source.bytes()[..len])?;
    Ok(codec::seal(store.binding(kind, name, generation), &Secret::new("p03-test-key"), &input)?)
}
fn insert(name: &str, kind: u8, record: &[u8]) -> Operation {
    Operation::Insert { reference: name.into(), kind, record: record.into() }
}
fn read(name: &str, kind: u8, generation: u64) -> Operation {
    Operation::Read { reference: name.into(), kind, generation }
}
fn remove(name: &str, kind: u8, generation: u64) -> Operation {
    Operation::Delete { reference: name.into(), kind, generation }
}

#[test]
fn linux_vault_file_store_is_insert_only_and_crash_durable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 1)?;
    let name = reference(3);
    let a = record(&store, 1, &name, 1, 7)?;
    let b = record(&store, 1, &name, 1, 8)?;
    let barrier = Arc::new(Barrier::new(3));
    let threads: Vec<_> = [a.clone(), b.clone()]
        .into_iter()
        .map(|bytes| {
            let (s, n, start) = (store.clone(), name.clone(), barrier.clone());
            std::thread::spawn(move || {
                start.wait();
                s.apply(insert(&n, 1, &bytes), |_| {})
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|t| t.join().map_err(|_| "writer panicked"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "one winner");
    assert!(results.iter().any(|r| *r == Err(Error::Busy) || *r == Err(Error::Exists)));
    let lock = open_file(&store.account_dir, ".writer.lock", OFlags::RDWR)?;
    fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
    assert_eq!(store.apply(read(&name, 1, 1), |_| {}), Err(Error::Busy));
    let same_account = Store::open(dir.path(), "alice", 2, [1; 16], [2; 16])?;
    assert_eq!(
        same_account.apply(read(&format!("branch:{}", reference(3)), 2, 1), |_| {}),
        Err(Error::Busy)
    );
    drop(lock);
    let winner = store.apply(read(&name, 1, 1), |_| {})?;
    assert!(winner == a || winner == b);
    // Independent filesystem bytes, not a product success counter.
    assert_eq!(std::fs::read(dir.path().join("alice/1").join(&name))?, winner);
    assert_eq!(
        store.apply(insert(&name, 1, &b), |_| {}),
        Err(Error::Exists),
        "immutable competing writer"
    );
    assert_eq!(store.apply(read(&name, 1, 1), |_| {})?, winner);
    assert_eq!(
        store.apply(insert("../escape", 1, &a), |_| {}),
        Err(Error::Record(codec::Error::Reference))
    );
    assert_eq!(
        store.apply(insert(&name, 2, &a), |_| {}),
        Err(Error::Record(codec::Error::Combination))
    );
    for (vault_id, key_id) in [([9; 16], [2; 16]), ([1; 16], [9; 16])] {
        let foreign = Store::open(dir.path(), "alice", 1, vault_id, key_id)?;
        assert_eq!(foreign.read(&name, 1, 1), Err(Error::Record(codec::Error::Authentication)));
    }
    let mut oversized = a.clone();
    oversized.resize(codec::MAX_RECORD + 1, 0);
    assert_eq!(
        store.apply(insert(&name, 1, &oversized), |_| {}),
        Err(Error::Record(codec::Error::RecordSize))
    );
    for n in 4..19 {
        let name = reference(n);
        let bytes = record(&store, 1, &name, 1, n)?;
        store.apply(insert(&name, 1, &bytes), |_| {})?;
    }
    let extra = reference(19);
    let bytes = record(&store, 1, &extra, 1, 19)?;
    assert_eq!(store.apply(insert(&extra, 1, &bytes), |_| {}), Err(Error::Full));
    let other = Store::open(dir.path(), "bob", 1, [1; 16], [2; 16])?;
    let bytes = record(&other, 1, &extra, 1, 19)?;
    other.apply(insert(&extra, 1, &bytes), |_| {})?;
    store.apply(remove(&name, 1, 1), |_| {})?;
    assert_eq!(store.apply(read(&name, 1, 1), |_| {}), Err(Error::Missing));
    invalid_store_configs(dir.path());
    unsafe_objects()?;
    replacement()?;
    crash_cuts()?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(store.clone().execute(read(&reference(4), 1, 1)))?;
    let held: Vec<_> = (0..4).map(|_| Slot::acquire()).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(runtime.block_on(store.execute(read(&reference(4), 1, 1))), Err(Error::Busy));
    drop(held);
    Ok(())
}
fn invalid_store_configs(root: &Path) {
    assert_eq!(
        Store::open(Path::new("relative"), "alice", 1, [1; 16], [2; 16]).err(),
        Some(Error::Path)
    );
    assert_eq!(
        Store::open(root, "../alice", 1, [1; 16], [2; 16]).err(),
        Some(Error::Record(codec::Error::Account))
    );
    assert_eq!(
        Store::open(root, "alice", 0, [1; 16], [2; 16]).err(),
        Some(Error::Record(codec::Error::Realm))
    );
    assert_eq!(
        Store::open(root, &"x".repeat(129), 1, [1; 16], [2; 16]).err(),
        Some(Error::Record(codec::Error::Account))
    );
    assert_eq!(Store::open(Path::new("/"), "alice", 1, [1; 16], [2; 16]).err(), Some(Error::Path));
    assert_eq!(
        Store::open(root, "alice", 4, [1; 16], [2; 16]).err(),
        Some(Error::Record(codec::Error::Realm))
    );
}
fn unsafe_objects() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 1)?;
    let n = reference(9);
    let path = dir.path().join("alice/1").join(&n);
    symlink("/dev/null", &path)?;
    assert_eq!(store.read(&n, 1, 1), Err(Error::Path));
    std::fs::remove_file(&path)?;
    rustix::fs::mknodat(
        &store.realm_dir,
        n.as_str(),
        fs::FileType::Fifo,
        fs::Mode::RUSR | fs::Mode::WUSR,
        0,
    )?;
    assert_eq!(store.read(&n, 1, 1), Err(Error::Metadata));
    std::fs::remove_file(&path)?;
    let bytes = record(&store, 1, &n, 1, 1)?;
    store.apply(insert(&n, 1, &bytes), |_| {})?;
    std::fs::hard_link(&path, dir.path().join("alias"))?;
    assert_eq!(store.read(&n, 1, 1), Err(Error::Metadata));
    std::fs::remove_file(dir.path().join("alias"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
    assert_eq!(store.read(&n, 1, 1), Err(Error::Metadata));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let fd = open_file(&store.realm_dir, &n, OFlags::RDONLY)?;
    assert_eq!(
        super::super::files::verify_owner(
            &fd,
            false,
            rustix::process::geteuid().as_raw().wrapping_add(1)
        ),
        Err(Error::Metadata)
    );
    for size in [0, 96, codec::MAX_RECORD + 1] {
        std::fs::write(&path, vec![0; size])?;
        assert_eq!(store.read(&n, 1, 1), Err(Error::Record(codec::Error::RecordSize)));
    }
    let link = dir.path().join("parent");
    symlink(dir.path().join("alice"), &link)?;
    assert_eq!(Store::open(&link.join("1"), "alice", 1, [1; 16], [2; 16]).err(), Some(Error::Path));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))?;
    assert_eq!(Store::open(dir.path(), "alice", 1, [1; 16], [2; 16]).err(), Some(Error::Metadata));
    Ok(())
}
fn replacement() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let n = "unlock:alice";
    let a = record(&store, 4, n, 1, 1)?;
    let b = record(&store, 4, n, 2, 2)?;
    store.apply(insert(n, 4, &a), |_| {})?;
    assert_eq!(
        store.apply(
            Operation::Replace { reference: n.into(), expected: 0, record: b.clone() },
            |_| {}
        ),
        Err(Error::Record(codec::Error::Generation))
    );
    store.apply(
        Operation::Replace { reference: n.into(), expected: 1, record: b.clone() },
        |_| {},
    )?;
    assert_eq!(store.read(n, 4, 2)?, b);
    assert_eq!(
        store.apply(Operation::Replace { reference: n.into(), expected: 1, record: a }, |_| {}),
        Err(Error::Generation)
    );
    assert_eq!(
        store.apply(
            Operation::Replace { reference: n.into(), expected: u64::MAX, record: b },
            |_| {}
        ),
        Err(Error::Generation)
    );
    assert_eq!(
        store.apply(
            Operation::Replace { reference: reference(1), expected: 1, record: vec![] },
            |_| {}
        ),
        Err(Error::Replacement)
    );
    Ok(())
}
fn crash_cuts() -> TestResult {
    for operation in ["insert", "replace", "delete"] {
        let stages: &[&str] = if operation == "delete" {
            &["before_delete", "after_delete", "delete_synced"]
        } else {
            &["written", "file_synced", "before_publish", "published", "parent_synced"]
        };
        for stage in stages {
            let dir = tempfile::tempdir()?;
            let store = setup(dir.path(), 3)?;
            let n = "unlock:alice";
            let a = record(&store, 4, n, 1, 1)?;
            let b = record(&store, 4, n, 2, 2)?;
            if operation != "insert" {
                store.apply(insert(n, 4, &a), |_| {})?;
            }
            std::fs::write(
                dir.path().join("candidate"),
                if operation == "replace" { &b } else { &a },
            )?;
            // Socket barrier proves the child reached the cut; parent kills/reaps it.
            let listener = std::os::unix::net::UnixListener::bind(dir.path().join("barrier"))?;
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "custody::vault::linux::writer::tests::crash_child",
                    "--nocapture",
                ])
                .env("RF_VAULT_CRASH_ROOT", dir.path())
                .env("RF_VAULT_CRASH_OPERATION", operation)
                .env("RF_VAULT_CRASH_STAGE", stage)
                .stdout(std::process::Stdio::null())
                .spawn()?;
            let (mut stream, _) = listener.accept()?;
            let mut marker = [0];
            std::io::Read::read_exact(&mut stream, &mut marker)?;
            assert_eq!(marker, [1]);
            child.kill()?;
            child.wait()?;
            let reopened = Store::open(dir.path(), "alice", 3, [1; 16], [2; 16])?;
            let path = dir.path().join("alice/3").join(n);
            let expected = match operation {
                "insert" => {
                    if matches!(*stage, "published" | "parent_synced") {
                        Some(&a)
                    } else {
                        None
                    }
                }
                "replace" => {
                    Some(if matches!(*stage, "published" | "parent_synced") { &b } else { &a })
                }
                _ => {
                    if *stage == "before_delete" {
                        Some(&a)
                    } else {
                        None
                    }
                }
            };
            match expected {
                Some(bytes) => assert_eq!(&std::fs::read(path)?, bytes),
                None => assert!(!path.exists()),
            }
            // Death releases the same permanent lock, without a new lock inode.
            let lock = open_file(&reopened.account_dir, ".writer.lock", OFlags::RDWR)?;
            fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        }
    }
    Ok(())
}
#[test]
fn crash_child() -> TestResult {
    let Some(root) = std::env::var_os("RF_VAULT_CRASH_ROOT") else { return Ok(()) };
    let operation = std::env::var("RF_VAULT_CRASH_OPERATION")?;
    let stage = std::env::var("RF_VAULT_CRASH_STAGE")?;
    let store = setup(Path::new(&root), 3)?;
    let n = "unlock:alice";
    let candidate = std::fs::read(Path::new(&root).join("candidate"))?;
    let op = match operation.as_str() {
        "insert" => insert(n, 4, &candidate),
        "replace" => Operation::Replace { reference: n.into(), expected: 1, record: candidate },
        _ => remove(n, 4, 1),
    };
    store.apply(op, |point| {
        if point == stage {
            let Ok(mut socket) = UnixStream::connect(Path::new(&root).join("barrier")) else {
                std::process::exit(93)
            };
            assert!(socket.write_all(&[1]).is_ok(), "notify cut");
            let mut byte = [0];
            let _ = std::io::Read::read(&mut socket, &mut byte);
            std::process::exit(94);
        }
    })?;
    Err("cut was not reached".into())
}
