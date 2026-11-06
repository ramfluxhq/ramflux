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
/// One durability operation as invoked by the writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    FileSync,
    Rename,
    Unlink,
    DirSync,
}
/// Records each operation when it is invoked, then either performs the real syscall or, for the
/// injected operation, returns an error instead of performing it.
struct RecordingOps {
    log: RefCell<Vec<Op>>,
    fail: Option<Op>,
}
impl RecordingOps {
    fn new(fail: Option<Op>) -> Self {
        Self { log: RefCell::new(Vec::new()), fail }
    }
    fn step(&self, op: Op, real: impl FnOnce() -> Result<(), Error>) -> Result<(), Error> {
        self.log.borrow_mut().push(op);
        if self.fail == Some(op) { Err(Error::Io) } else { real() }
    }
}
impl DurabilityOps for RecordingOps {
    fn fsync_file(&self, file: &File) -> Result<(), Error> {
        self.step(Op::FileSync, || RealDurabilityOps.fsync_file(file))
    }
    fn fsync_dir(&self, dir: &OwnedFd) -> Result<(), Error> {
        self.step(Op::DirSync, || RealDurabilityOps.fsync_dir(dir))
    }
    fn rename(&self, dir: &OwnedFd, from: &str, to: &str, flags: RenameFlags) -> Result<(), Error> {
        self.step(Op::Rename, || RealDurabilityOps.rename(dir, from, to, flags))
    }
    fn unlink(&self, dir: &OwnedFd, name: &str) -> Result<(), Error> {
        self.step(Op::Unlink, || RealDurabilityOps.unlink(dir, name))
    }
}
/// Runs one operation and returns its result with the ordered durability operations invoked.
fn observed(
    store: &Store,
    operation: Operation,
    fail: Option<Op>,
) -> (Result<Vec<u8>, Error>, Vec<Op>) {
    let ops = RecordingOps::new(fail);
    let result = store.publish(operation, &ops, &|_| Ok(()));
    (result, ops.log.into_inner())
}

#[test]
fn linux_vault_file_store_is_insert_only_and_crash_durable() -> TestResult {
    run_in_child("file_store_body")
}
/// Out-of-process body of the file-store test; a no-op unless launched by `run_in_child`.
#[test]
fn file_store_body() -> TestResult {
    if std::env::var_os(BODY_ENV).is_none() {
        return Ok(());
    }
    file_store_is_insert_only_and_crash_durable()
}
fn file_store_is_insert_only_and_crash_durable() -> TestResult {
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
    run_in_child("order_oracle_body")
}
/// Out-of-process body of the order oracle; a no-op unless launched by `run_in_child`.
#[test]
fn order_oracle_body() -> TestResult {
    if std::env::var_os(BODY_ENV).is_none() {
        return Ok(());
    }
    order_oracle()
}
fn order_oracle() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let n = "unlock:alice";
    let a = record(&store, 4, n, 1, 1)?;
    let b = record(&store, 4, n, 2, 2)?;
    let publish = [Op::FileSync, Op::Rename, Op::DirSync];
    let (result, ops) = observed(&store, insert(n, 4, &a), None);
    result?;
    assert_eq!(ops, publish, "insert: file fsync, then rename, then parent fsync");
    let (result, ops) =
        observed(&store, Operation::Replace { reference: n.into(), expected: 1, record: b }, None);
    result?;
    assert_eq!(ops, publish, "replace: file fsync, then rename, then parent fsync");
    let (result, ops) = observed(&store, remove(n, 4, 2), None);
    result?;
    assert_eq!(ops, [Op::Unlink, Op::DirSync], "delete: unlink, then parent fsync");
    // An injected syscall failure replaces the syscall: it is an error to the caller and never a
    // durable success, and the failed step is the last one recorded before cleanup.
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let (failed, ops) = observed(&store, insert(n, 4, &a), Some(Op::FileSync));
    assert_eq!(failed, Err(Error::Io));
    assert_eq!(ops, [Op::FileSync, Op::Unlink, Op::DirSync], "failed file fsync cleans up");
    assert!(!dir.path().join("alice/3").join(n).exists(), "unsynced file must not publish");
    let dir = tempfile::tempdir()?;
    let store = setup(dir.path(), 3)?;
    let (failed, _) = observed(&store, insert(n, 4, &a), Some(Op::DirSync));
    assert_eq!(failed, Err(Error::Io), "parent fsync failure must not report success");
    Ok(())
}
/// Child of the strace proof: one insert and one delete through the production operations.
#[test]
fn strace_child() -> TestResult {
    let Some(root) = std::env::var_os("RF_VAULT_STRACE_ROOT") else { return Ok(()) };
    let store = setup(Path::new(&root), 3)?;
    let n = "unlock:alice";
    let a = record(&store, 4, n, 1, 1)?;
    store.apply(insert(n, 4, &a), |_| {})?;
    store.apply(remove(n, 4, 1), |_| {})?;
    Ok(())
}
/// Set in the child that runs a lock-holding test body.
const BODY_ENV: &str = "RF_VAULT_TEST_BODY";
/// Runs a lock-holding test body in its own process (re-exec of this test binary).
///
/// `flock` locks belong to the open file description, which a forked child shares with its
/// parent until it execs. A fixture spawned by another test thread would therefore keep a copy of
/// a lock held at that instant, and the holder's next lock attempt would see `Busy`. CLOEXEC
/// cannot close the fork-to-exec window. Bodies that take the realm lock run here, so no other
/// test's fork can ever see their descriptors, and no timing window or gate is needed. The wait
/// is bounded, the child is killed and reaped on every path, and its output is propagated.
fn run_in_child(body: &str) -> TestResult {
    let dir = tempfile::tempdir()?;
    let log = dir.path().join("child.log");
    let out = File::create(&log)?;
    let status = run_bounded(
        Command::new(std::env::current_exe()?)
            .args(["--exact", &format!("custody::vault::linux::writer::tests::{body}")])
            .arg("--nocapture")
            .env(BODY_ENV, "1")
            .stdout(out.try_clone()?)
            .stderr(out),
        Duration::from_secs(60),
    )?;
    if !status.success() {
        let output = std::fs::read_to_string(&log).unwrap_or_default();
        return Err(format!("{body} failed ({status}):\n{output}").into());
    }
    Ok(())
}
/// Kills the whole process group of a traced run on every exit path and reaps the leader.
struct GroupReaper(Child);
impl Drop for GroupReaper {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
/// Runs `command` in its own process group with a fail-loud deadline; tracer and tracee are
/// killed and reaped when this returns, however it returns.
fn run_bounded(command: &mut Command, deadline: Duration) -> TestResult<std::process::ExitStatus> {
    use std::os::unix::process::CommandExt;
    let mut child = GroupReaper(command.process_group(0).spawn()?);
    let end = Instant::now() + deadline;
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(format!("traced run timed out after {deadline:?}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn bounded_run_reports_stall_and_early_exit() -> TestResult {
    let started = Instant::now();
    let err = run_bounded(Command::new("sleep").arg("60"), Duration::from_millis(300))
        .err()
        .ok_or("stalled run must fail")?;
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10), "stall must not wait for the child");
    let status = run_bounded(Command::new("sh").args(["-c", "exit 3"]), GUARD)?;
    assert_eq!(status.code(), Some(3), "early exit is reported, not hidden");
    Ok(())
}

/// One syscall line of a `strace -f -y` trace: name, quoted/bare arguments and result.
struct Call<'a> {
    name: &'a str,
    args: &'a str,
    ok: bool,
}
fn parse_calls(text: &str) -> Vec<Call<'_>> {
    text.lines()
        .filter_map(|line| {
            let call = line.split_once(' ').map_or(line, |(_, rest)| rest).trim_start();
            let (name, rest) = call.split_once('(')?;
            let (args, result) = rest.rsplit_once(") = ")?;
            let ok = result.split_whitespace().next()? == "0";
            matches!(
                name,
                "fsync" | "fdatasync" | "rename" | "renameat" | "renameat2" | "unlink" | "unlinkat"
            )
            .then_some(Call { name, args, ok })
        })
        .collect()
}
/// Why a trace was refused. Each negative case is pinned to exactly one variant.
#[derive(Debug, PartialEq, Eq)]
enum TraceError {
    NoTempFileSync,
    WrongCount(usize),
    TempNotInRealm(String),
    NotARename,
    RenameSourceDir(String),
    RenameDestDir(String),
    RenameNames,
    NoDirSyncAfterRename,
    NotRealmUnlink,
    NoDirSyncAfterUnlink,
    Failed(String),
}
/// The path inside `N<path>` of a `-y` descriptor argument.
fn fd_path(arg: &str) -> Option<&str> {
    arg.split_once('<')?.1.strip_suffix('>')
}
fn quoted(arg: &str) -> Option<&str> {
    arg.strip_prefix('"')?.strip_suffix('"')
}
/// Checks the insert-then-delete publication by descriptor identity, not by syscall name: the
/// temporary file's own fsync (full path inside `realm`), then the rename of that temp name with
/// both directory descriptors equal to `realm`, a realm-directory fsync, the unlink in `realm`
/// and a final realm-directory fsync. Every call must have succeeded. Directory fsyncs from
/// `Store::open` come before the temp file exists and cannot stand in for the file fsync.
fn check_publication_trace(text: &str, realm: &str) -> Result<(), TraceError> {
    let calls = parse_calls(text);
    let is_sync = |c: &Call<'_>| matches!(c.name, "fsync" | "fdatasync");
    let temp_prefix = format!("{realm}/.pending-");
    let first = calls
        .iter()
        .position(|c| is_sync(c) && fd_path(c.args).is_some_and(|p| p.contains("/.pending-")))
        .ok_or(TraceError::NoTempFileSync)?;
    let seq = &calls[first..];
    if seq.len() != 5 {
        return Err(TraceError::WrongCount(seq.len()));
    }
    let temp_path = fd_path(seq[0].args).unwrap_or_default();
    if !temp_path.starts_with(&temp_prefix) {
        return Err(TraceError::TempNotInRealm(temp_path.to_string()));
    }
    let temp_name = &temp_path[realm.len() + 1..];
    if !seq[1].name.starts_with("rename") {
        return Err(TraceError::NotARename);
    }
    let parts: Vec<&str> = seq[1].args.split(", ").collect();
    if parts.len() < 4 {
        return Err(TraceError::NotARename);
    }
    if fd_path(parts[0]) != Some(realm) {
        return Err(TraceError::RenameSourceDir(parts[0].to_string()));
    }
    if fd_path(parts[2]) != Some(realm) {
        return Err(TraceError::RenameDestDir(parts[2].to_string()));
    }
    if quoted(parts[1]) != Some(temp_name) || quoted(parts[3]) != Some("unlock:alice") {
        return Err(TraceError::RenameNames);
    }
    if !(is_sync(&seq[2]) && fd_path(seq[2].args) == Some(realm)) {
        return Err(TraceError::NoDirSyncAfterRename);
    }
    let unlink: Vec<&str> = seq[3].args.split(", ").collect();
    if !(seq[3].name.starts_with("unlink")
        && fd_path(unlink[0]) == Some(realm)
        && unlink.get(1).copied().and_then(quoted) == Some("unlock:alice"))
    {
        return Err(TraceError::NotRealmUnlink);
    }
    if !(is_sync(&seq[4]) && fd_path(seq[4].args) == Some(realm)) {
        return Err(TraceError::NoDirSyncAfterUnlink);
    }
    if let Some(bad) = seq.iter().find(|c| !c.ok) {
        return Err(TraceError::Failed(format!("{}({})", bad.name, bad.args)));
    }
    Ok(())
}
const REALM: &str = "/r/alice/3";
const GOOD_TRACE: &str = "7 fsync(4</r/alice>) = 0
7 fsync(6</r/alice/3/.pending-AbC>) = 0
7 renameat2(5</r/alice/3>, \".pending-AbC\", 5</r/alice/3>, \"unlock:alice\", RENAME_NOREPLACE) = 0
7 fsync(5</r/alice/3>) = 0
7 unlinkat(5</r/alice/3>, \"unlock:alice\", 0) = 0
7 fsync(5</r/alice/3>) = 0
";
#[test]
fn trace_checker_pins_file_sync_identity_and_results() {
    let check = |trace: &str| check_publication_trace(trace, REALM);
    assert_eq!(check(GOOD_TRACE), Ok(()));
    // Missing file fsync: Store::open's directory fsync is still there, yet the trace is refused.
    let no_file_sync = GOOD_TRACE.replace("7 fsync(6</r/alice/3/.pending-AbC>) = 0\n", "");
    assert_eq!(check(&no_file_sync), Err(TraceError::NoTempFileSync));
    // Directory fsync standing in for the file fsync.
    let swapped = GOOD_TRACE.replace("fsync(6</r/alice/3/.pending-AbC>)", "fsync(5</r/alice/3>)");
    assert_eq!(check(&swapped), Err(TraceError::NoTempFileSync));
    // Temp file fsync on a file of an unrelated directory with the same basename.
    let unrelated = GOOD_TRACE.replace("6</r/alice/3/.pending-AbC>", "6</unrelated/.pending-AbC>");
    assert_eq!(
        check(&unrelated),
        Err(TraceError::TempNotInRealm("/unrelated/.pending-AbC".into()))
    );
    let dest =
        GOOD_TRACE.replace("5</r/alice/3>, \"unlock:alice\"", "8</unrelated>, \"unlock:alice\"");
    assert_eq!(check(&dest), Err(TraceError::RenameDestDir("8</unrelated>".into())));
    let source = GOOD_TRACE.replace("renameat2(5</r/alice/3>", "renameat2(8</unrelated>");
    assert_eq!(check(&source), Err(TraceError::RenameSourceDir("8</unrelated>".into())));
    let failed =
        GOOD_TRACE.replacen("fsync(5</r/alice/3>) = 0", "fsync(5</r/alice/3>) = -1 EIO", 1);
    assert_eq!(check(&failed), Err(TraceError::Failed("fsync(5</r/alice/3>)".into())));
    let wrong_dir = GOOD_TRACE.replacen("fsync(5</r/alice/3>)", "fsync(4</r/alice>)", 1);
    assert_eq!(check(&wrong_dir), Err(TraceError::NoDirSyncAfterRename));
}
/// Proves `RealDurabilityOps` itself: the real syscalls, on the right descriptors, in order.
#[test]
#[ignore = "needs strace; run on QA"]
fn real_durability_ops_issue_syscalls_in_durable_order() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("root");
    std::fs::create_dir(&root)?;
    let trace = dir.path().join("trace.txt");
    let status = run_bounded(
        Command::new("strace")
            .args(["-f", "-y", "-o"])
            .arg(&trace)
            .args(["-e", "trace=fsync,fdatasync,rename,renameat,renameat2,unlink,unlinkat"])
            .arg(std::env::current_exe()?)
            .args(["--exact", "custody::vault::linux::writer::tests::strace_child", "--nocapture"])
            .env("RF_VAULT_STRACE_ROOT", &root)
            .stdout(std::process::Stdio::null()),
        Duration::from_secs(30),
    )
    .map_err(|e| format!("strace is required for this test and failed: {e}"))?;
    assert!(status.success(), "traced child failed: {status}");
    let text = std::fs::read_to_string(&trace)?;
    let realm = root.join("alice/3");
    let realm = realm.to_str().ok_or("non-utf8 realm path")?;
    check_publication_trace(&text, realm).map_err(|e| format!("{e:?}\n{text}"))?;
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
    store.apply(op, |point| {
        if point == stage {
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
