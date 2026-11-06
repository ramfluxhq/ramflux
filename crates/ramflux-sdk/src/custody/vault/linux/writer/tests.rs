// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::{cleanup::Secret, codec::Plaintext};
use super::*;
use std::{
    cell::RefCell,
    io::ErrorKind,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::{Child, Command},
    sync::{atomic::AtomicBool, mpsc},
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Every blocking wait in this module (accept, marker read, start gate, result receive) uses this.
const GUARD: Duration = Duration::from_secs(10);

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + GUARD;
    while !ready() {
        if Instant::now() >= deadline {
            return Err(format!("timed out after 10s waiting for {what}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
/// Kills and reaps a crash child on every exit path, including early errors.
struct Reaper(Child);
impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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
    sized_record(store, kind, name, generation, len, value)
}
fn sized_record(
    store: &Store,
    kind: u8,
    name: &str,
    generation: u64,
    len: usize,
    value: u8,
) -> TestResult<Vec<u8>> {
    let mut source = Secret::<{ codec::MAX_PLAINTEXT }>::new("p03-fixture-source");
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
/// Runs one operation and returns its result with the ordered durability steps it emitted.
fn observed(store: &Store, operation: Operation) -> (Result<Vec<u8>, Error>, Vec<Event>) {
    let log = RefCell::new(Vec::new());
    let result = store.apply(operation, |event| log.borrow_mut().push(event));
    (result, log.into_inner())
}

#[test]
fn linux_vault_file_store_is_insert_only_and_crash_durable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 1)?;
    let name = reference(3);
    let a = record(&store, 1, &name, 1, 7)?;
    let b = record(&store, 1, &name, 1, 8)?;
    let started = Arc::new(AtomicUsize::new(0));
    let go = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    for bytes in [a.clone(), b.clone()] {
        let (s, n, started, go, tx) =
            (store.clone(), name.clone(), started.clone(), go.clone(), tx.clone());
        std::thread::spawn(move || {
            started.fetch_add(1, Ordering::SeqCst);
            // Bounded start gate: a failed test cannot leave this worker parked forever.
            if wait_until("start gate", || go.load(Ordering::SeqCst)).is_ok() {
                let _ = tx.send(s.apply(insert(&n, 1, &bytes), |_| {}));
            }
        });
    }
    drop(tx);
    wait_until("both writers started", || started.load(Ordering::SeqCst) == 2)?;
    go.store(true, Ordering::SeqCst);
    let results = (0..2)
        .map(|_| {
            rx.recv_timeout(GUARD)
                .map_err(|e| format!("writer result not received within 10s: {e}"))
        })
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
    record_size_boundaries()?;
    crash_cuts()?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(store.clone().execute(read(&reference(4), 1, 1)))?;
    let held: Vec<_> = (0..4).map(|_| Slot::acquire()).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(runtime.block_on(store.execute(read(&reference(4), 1, 1))), Err(Error::Busy));
    drop(held);
    Ok(())
}
/// Durability oracle: the real fsync, rename and unlink steps must occur in D5 order.
#[test]
fn linux_vault_publication_call_order_is_durable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let n = "unlock:alice";
    let a = record(&store, 4, n, 1, 1)?;
    let b = record(&store, 4, n, 2, 2)?;
    let publish = [
        Event::Cut("written"),
        Event::FileSync,
        Event::Cut("file_synced"),
        Event::Cut("before_publish"),
        Event::Rename,
        Event::Cut("published"),
        Event::DirSync,
        Event::Cut("parent_synced"),
    ];
    let (result, events) = observed(&store, insert(n, 4, &a));
    result?;
    assert_eq!(events, publish, "insert: file fsync, then rename, then parent fsync");
    let (result, events) =
        observed(&store, Operation::Replace { reference: n.into(), expected: 1, record: b });
    result?;
    assert_eq!(events, publish, "replace: file fsync, then rename, then parent fsync");
    let (result, events) = observed(&store, remove(n, 4, 2));
    result?;
    assert_eq!(
        events,
        [
            Event::Cut("before_delete"),
            Event::Unlink,
            Event::Cut("after_delete"),
            Event::DirSync,
            Event::Cut("delete_synced"),
        ],
        "delete: unlink, then parent fsync"
    );
    // A failed sync is an error to the caller and never a durable success.
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let failed = store
        .observe(insert(n, 4, &a), |e| if e == Event::FileSync { Err(Error::Io) } else { Ok(()) });
    assert_eq!(failed, Err(Error::Io));
    assert!(!dir.path().join("alice/3").join(n).exists(), "unsynced file must not publish");
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let failed = store
        .observe(insert(n, 4, &a), |e| if e == Event::DirSync { Err(Error::Io) } else { Ok(()) });
    assert_eq!(failed, Err(Error::Io), "parent fsync failure must not report success");
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
/// Exact accept edges of the reader guard: 97 and 8288 bytes succeed, 96 and 8289 refuse.
fn record_size_boundaries() -> TestResult {
    let n = "unlock:alice";
    for (plaintext, total) in [(1, 97), (codec::MAX_PLAINTEXT, codec::MAX_RECORD)] {
        let dir = tempfile::tempdir()?;
        let store = setup(dir.path(), 3)?;
        let bytes = sized_record(&store, 4, n, 1, plaintext, 5)?;
        assert_eq!(bytes.len(), total);
        store.apply(insert(n, 4, &bytes), |_| {})?;
        let path = dir.path().join("alice/3").join(n);
        assert_eq!(std::fs::metadata(&path)?.len(), total as u64);
        let reopened = Store::open(dir.path(), "alice", 3, [1; 16], [2; 16])?;
        assert_eq!(reopened.read(n, 4, 1)?, bytes, "{total}-byte record reopens byte-identical");
        assert_eq!(store.apply(read(n, 4, 1), |_| {})?, bytes);
    }
    for size in [96, codec::MAX_RECORD + 1] {
        let dir = tempfile::tempdir()?;
        let store = setup(dir.path(), 3)?;
        let path = dir.path().join("alice/3").join(n);
        std::fs::write(&path, vec![0; size])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(store.read(n, 4, 1), Err(Error::Record(codec::Error::RecordSize)), "{size}");
    }
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
            crash_at(dir.path(), operation, stage)?;
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
/// Runs one crash child to its named cut. Every wait is bounded; the child is always reaped.
fn crash_at(root: &Path, operation: &str, stage: &str) -> TestResult {
    let listener = UnixListener::bind(root.join("barrier"))?;
    listener.set_nonblocking(true)?;
    let mut child = Reaper(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "custody::vault::linux::writer::tests::crash_child", "--nocapture"])
            .env("RF_VAULT_CRASH_ROOT", root)
            .env("RF_VAULT_CRASH_OPERATION", operation)
            .env("RF_VAULT_CRASH_STAGE", stage)
            .stdout(std::process::Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + GUARD;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("{operation}/{stage}: accept failed: {e}").into()),
        }
        if let Some(status) = child.0.try_wait()? {
            return Err(format!(
                "{operation}/{stage}: crash child exited ({status}) before reaching the cut"
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err(format!("{operation}/{stage}: no cut connection within 10s").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(GUARD))?;
    let mut marker = [0];
    std::io::Read::read_exact(&mut stream, &mut marker)
        .map_err(|e| format!("{operation}/{stage}: cut marker not received: {e}"))?;
    if marker != [1] {
        return Err(format!("{operation}/{stage}: bad cut marker").into());
    }
    child.0.kill()?;
    child.0.wait()?;
    Ok(())
}
#[test]
fn crash_harness_reports_early_child_failure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let a = record(&store, 4, "unlock:alice", 1, 1)?;
    std::fs::write(dir.path().join("candidate"), a)?;
    // An unknown stage lets the child finish without a cut, so it exits before connecting.
    let err = crash_at(dir.path(), "insert", "no_such_stage").err().ok_or("expected failure")?;
    assert!(err.to_string().contains("exited"), "{err}");
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
    store.apply(op, |event| {
        if matches!(event, Event::Cut(point) if point == stage) {
            let Ok(mut socket) = UnixStream::connect(Path::new(&root).join("barrier")) else {
                std::process::exit(93)
            };
            let _ = socket.set_read_timeout(Some(GUARD));
            assert!(socket.write_all(&[1]).is_ok(), "notify cut");
            let mut byte = [0];
            let _ = std::io::Read::read(&mut socket, &mut byte);
            std::process::exit(94);
        }
    })?;
    Err("cut was not reached".into())
}
