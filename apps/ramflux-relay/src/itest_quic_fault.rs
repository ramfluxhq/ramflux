// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const DROP_AFTER_COMMIT_ENV: &str = "RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT";
const CAPTURE_FILE_ENV: &str = "RAMFLUX_RELAY_ITEST_CAPTURE_FILE";
const HOLD_MARKER_ENV: &str = "RAMFLUX_RELAY_ITEST_HOLD_MARKER";
const BODY_FINGERPRINT_DOMAIN: &str = "ramflux.itest.quic_fault.body.v1";

// Fail exactly once per relay process, claimed atomically so concurrent streams cannot both
// inject. A non-matching request never consumes the claim.
static FAULT_CLAIMED: AtomicBool = AtomicBool::new(false);
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
// A per-process-START identity for the capture. The relay is PID 1 inside its container and
// keeps PID 1 across a restart, so `std::process::id()` cannot distinguish a pre-restart from a
// post-restart process — this nanosecond process-start stamp does (a between-attempt restart is
// seconds apart). Captured once per process; used to prove a between-attempt retry lands on a
// genuinely different relay process.
static PROCESS_INSTANCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

fn process_instance() -> u64 {
    *PROCESS_INSTANCE.get_or_init(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| {
            elapsed
                .as_secs()
                .wrapping_mul(1_000_000_000)
                .wrapping_add(u64::from(elapsed.subsec_nanos()))
        })
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    Put,
    Ack,
    Tombstone,
    PutRestartHold,
}

fn mode() -> Mode {
    match std::env::var(DROP_AFTER_COMMIT_ENV).ok().as_deref() {
        Some("put") => Mode::Put,
        Some("ack") => Mode::Ack,
        Some("tombstone") => Mode::Tombstone,
        Some("put-restart-hold") => Mode::PutRestartHold,
        _ => Mode::Off,
    }
}

fn path_matches(route: &str, mode: Mode) -> bool {
    match mode {
        Mode::Put | Mode::PutRestartHold => route.ends_with("/put_chunk"),
        Mode::Ack => route.ends_with("/ack"),
        Mode::Tombstone => route.ends_with("/tombstone"),
        Mode::Off => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Write,
    Drop,
    Hold,
}

fn action_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Write => "write",
        Decision::Drop => "drop",
        Decision::Hold => "hold",
    }
}

/// Pure post-commit decision: fires only on a matching route with a 2xx commit and an
/// unclaimed once-slot; a 4xx/5xx status, a non-matching route, `Mode::Off`, or an
/// already-claimed slot all yield `Write`.
fn plan(mode: Mode, route: &str, response_status: u16, already_claimed: bool) -> Decision {
    let commit_succeeded = (200..300).contains(&response_status);
    let matches = commit_succeeded && path_matches(route, mode);
    if matches && !already_claimed {
        match mode {
            Mode::PutRestartHold => Decision::Hold,
            _ => Decision::Drop,
        }
    } else {
        Decision::Write
    }
}

/// The hold marker file also serves as the **cross-process one-shot claim** for
/// `put-restart-hold`: the first process holds and writes it; after a between-attempt restart
/// the new process (same mode, its in-process claim reset) finds the marker already present and
/// returns `Write` for the retry, so it never holds twice.
fn hold_marker_exists() -> bool {
    std::env::var_os(HOLD_MARKER_ENV).is_some_and(|path| std::path::Path::new(&path).exists())
}

/// Two-layer one-shot claim for `put-restart-hold`. The persistent marker guards the
/// cross-process / post-restart claim; the in-process atomic guards concurrent connections
/// within a single process (the relay `tokio::spawn`s one task per QUIC connection, so two
/// matching connections could otherwise both read a not-yet-written marker and both Hold).
/// **Short-circuit order matters**: after a restart the marker is present, so the new process
/// returns claimed WITHOUT consuming its fresh atomic; on the first process the marker is
/// absent, so exactly one concurrent caller wins the atomic swap (returns `false` = unclaimed
/// → Hold) and every other caller sees `true` → Write.
fn hold_claim_already_taken(marker_exists: bool, claimed: &AtomicBool) -> bool {
    marker_exists || claimed.swap(true, Ordering::SeqCst)
}

/// Computes the post-commit decision, sourcing the one-shot claim per mode: `put-restart-hold`
/// combines the persistent hold marker (survives a relay restart) with the in-process atomic
/// (thread-safe fail-once across concurrent connections); the drop modes use the in-process
/// atomic alone. `plan` itself stays pure.
fn decide(mode: Mode, route: &str, response_status: u16) -> Decision {
    let will_match = (200..300).contains(&response_status) && path_matches(route, mode);
    let already_claimed = if will_match {
        match mode {
            Mode::PutRestartHold => hold_claim_already_taken(hold_marker_exists(), &FAULT_CLAIMED),
            _ => FAULT_CLAIMED.swap(true, Ordering::SeqCst),
        }
    } else {
        true
    };
    plan(mode, route, response_status, already_claimed)
}

/// Decides the post-commit action for a just-dispatched request and appends a non-sensitive
/// capture record. Called for every client QUIC request (under the feature) so the capture also
/// witnesses normal `write` actions for connection-reuse proofs. Returns `Err` (fail-closed) when
/// a requested capture record cannot be written — the caller then fails the connection so a lost
/// capture never masquerades as an empty log.
pub(super) fn decide_and_capture(
    request: &ramflux_transport::GatewayQuicRequest,
    response_status: u16,
    connection_id: u64,
) -> Result<Decision, ()> {
    let request_seq = REQUEST_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    let decision = decide(mode(), &request.path, response_status);
    capture(request, response_status, connection_id, request_seq, action_label(decision))?;
    Ok(decision)
}

/// Builds the non-sensitive capture record. NEVER records raw token/grant/PoP/nonce/seed/cert or
/// a filesystem path — only the route, method, a blake3 fingerprint of the canonical body bytes
/// (stable across attempts regardless of JSON key ordering), the connection id, request seq, the
/// process id (so a between-attempt retry on a restarted relay is distinguishable — connection
/// ids and request seqs reset per process), action and business status.
fn capture_line(
    request: &ramflux_transport::GatewayQuicRequest,
    response_status: u16,
    connection_id: u64,
    request_seq: u64,
    action: &str,
) -> serde_json::Value {
    let body_fingerprint = ramflux_protocol::canonical_json_bytes(&request.body).map_or_else(
        |_| "canonicalization-failed".to_owned(),
        |bytes| ramflux_protocol::hash_base64url(BODY_FINGERPRINT_DOMAIN, &bytes),
    );
    serde_json::json!({
        "request_seq": request_seq,
        "connection_id": connection_id,
        "process_instance": process_instance(),
        "method": request.method,
        "route": request.path,
        "body_fingerprint": body_fingerprint,
        "action": action,
        "status": response_status,
    })
}

/// Appends the capture record. `Ok(())` when no capture file is configured (capture not
/// requested) or the record is written; `Err(())` when a configured capture file cannot be
/// opened or written — the caller fails the connection fail-closed.
fn capture(
    request: &ramflux_transport::GatewayQuicRequest,
    response_status: u16,
    connection_id: u64,
    request_seq: u64,
    action: &str,
) -> Result<(), ()> {
    let Some(path) = std::env::var_os(CAPTURE_FILE_ENV) else {
        return Ok(());
    };
    let line = capture_line(request, response_status, connection_id, request_seq, action);
    capture_to(std::path::Path::new(&path), &line)
}

// Serializes the process-wide capture writer. Multiple client-QUIC connections run on independent
// tasks/threads; each `capture_to` call must land as ONE indivisible appended line. Formatting to
// a stream (`writeln!`) could split into several `write` calls that interleave under concurrency
// and corrupt/lose lines (observed: a whole daemon's connection dropping from the log under K-way
// fan-out). This lock + a pre-serialized single-`write_all` guarantees atomic, race-free append.
static CAPTURE_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn capture_to(path: &std::path::Path, line: &serde_json::Value) -> Result<(), ()> {
    // Serialize the ENTIRE line (JSON + newline) into one owned buffer BEFORE taking the lock or
    // touching the file, so the guarded critical section is a single atomic append.
    let mut buffer = serde_json::to_vec(line).map_err(|_error| ())?;
    buffer.push(b'\n');
    let _guard = CAPTURE_WRITE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|error| {
        tracing::warn!(%error, capture_path = %path.display(), "relay client QUIC capture open failed");
    })?;
    // One write_all of the fully-formed line; still fail-closed on any I/O error.
    file.write_all(&buffer).map_err(|error| {
        tracing::warn!(%error, capture_path = %path.display(), "relay client QUIC capture write failed");
    })
}

/// Writes the between-attempt restart barrier marker (also the cross-process hold claim, see
/// [`hold_marker_exists`]). `Err(())` when the marker env is unset or the file cannot be written,
/// so the caller fails the connection rather than parking without a recorded barrier.
pub(super) fn write_hold_marker() -> Result<(), ()> {
    let path = std::env::var_os(HOLD_MARKER_ENV).ok_or(())?;
    write_marker_to(std::path::Path::new(&path))
}

fn write_marker_to(path: &std::path::Path) -> Result<(), ()> {
    let mut file = std::fs::File::create(path).map_err(|_error| ())?;
    file.write_all(b"held-after-commit\n").map_err(|_error| ())
}

#[cfg(test)]
mod tests {
    use super::{
        Decision, Mode, capture_line, capture_to, hold_claim_already_taken, path_matches, plan,
        write_marker_to,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    fn request(route: &str) -> ramflux_transport::GatewayQuicRequest {
        ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: route.to_owned(),
            body: serde_json::json!({
                "token": { "nonce": "sdk-pop-1700000000-0" },
                "chunk": "opaque",
            }),
        }
    }

    #[test]
    fn plan_injects_once_per_matching_route_only_on_2xx() {
        // Matching route + 2xx + unclaimed -> drop; claimed -> write (fail-once).
        assert_eq!(plan(Mode::Put, "/relay/v1/object/put_chunk", 200, false), Decision::Drop);
        assert_eq!(plan(Mode::Put, "/relay/v1/object/put_chunk", 200, true), Decision::Write);
        assert_eq!(plan(Mode::Ack, "/relay/v1/object/ack", 200, false), Decision::Drop);
        assert_eq!(plan(Mode::Tombstone, "/relay/v1/object/tombstone", 200, false), Decision::Drop);
        assert_eq!(
            plan(Mode::PutRestartHold, "/relay/v1/object/put_chunk", 200, false),
            Decision::Hold
        );
        // Cross-process one-shot: after a between-attempt restart the hold marker exists, so the
        // same put-restart-hold mode returns Write (the retry lands), never a second Hold.
        assert_eq!(
            plan(Mode::PutRestartHold, "/relay/v1/object/put_chunk", 200, true),
            Decision::Write
        );
    }

    #[test]
    fn hold_claim_is_thread_safe_one_shot_under_concurrency() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 16;

        // Deterministic contention: every thread parks on the barrier and then races the claim.
        fn count_hold_winners(marker_exists: bool) -> (usize, bool) {
            let claimed = Arc::new(AtomicBool::new(false));
            let winners = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let claimed = Arc::clone(&claimed);
                    let winners = Arc::clone(&winners);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        // `already_taken == false` means this caller wins the one-shot and Holds.
                        if !hold_claim_already_taken(marker_exists, &claimed) {
                            winners.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                })
                .collect();
            for handle in handles {
                assert!(handle.join().is_ok(), "claim thread must not panic");
            }
            (winners.load(Ordering::SeqCst), claimed.load(Ordering::SeqCst))
        }

        // First process (marker absent): exactly one concurrent Hold winner, the atomic is set.
        let (winners, consumed) = count_hold_winners(false);
        assert_eq!(winners, 1, "marker absent -> exactly one concurrent Hold winner");
        assert!(consumed, "the winning caller must leave the in-process atomic claimed");

        // Post-restart (marker present): zero Hold winners and the fresh atomic is never
        // consumed (short-circuit), so every retry across every concurrent connection Writes.
        let (winners, consumed) = count_hold_winners(true);
        assert_eq!(winners, 0, "marker present -> zero Hold winners (all retries Write)");
        assert!(!consumed, "marker present short-circuits -> new-process atomic untouched");
    }

    #[test]
    fn plan_never_injects_on_non_matching_route_or_off_mode() {
        assert_eq!(plan(Mode::Put, "/relay/v1/object/ack", 200, false), Decision::Write);
        assert_eq!(plan(Mode::Ack, "/relay/v1/object/put_chunk", 200, false), Decision::Write);
        assert_eq!(plan(Mode::Off, "/relay/v1/object/put_chunk", 200, false), Decision::Write);
    }

    #[test]
    fn plan_never_injects_on_4xx_or_5xx_dispatch() {
        for status in [400_u16, 401, 403, 404, 409, 500, 503] {
            assert_eq!(
                plan(Mode::Put, "/relay/v1/object/put_chunk", status, false),
                Decision::Write,
                "status {status} must never induce a post-commit fault"
            );
        }
    }

    #[test]
    fn path_matches_is_route_specific() {
        assert!(path_matches("/relay/v1/object/put_chunk", Mode::Put));
        assert!(path_matches("/relay/v1/object/put_chunk", Mode::PutRestartHold));
        assert!(path_matches("/relay/v1/object/ack", Mode::Ack));
        assert!(path_matches("/relay/v1/object/tombstone", Mode::Tombstone));
        assert!(!path_matches("/relay/v1/object/get_chunk", Mode::Put));
        assert!(!path_matches("/relay/v1/object/put_chunk", Mode::Ack));
    }

    #[test]
    fn capture_line_carries_no_sensitive_raw_fields() -> Result<(), String> {
        let line = capture_line(&request("/relay/v1/object/put_chunk"), 200, 7, 3, "drop");
        let Some(object) = line.as_object() else {
            return Err("capture line must be a JSON object".to_owned());
        };
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "action",
                "body_fingerprint",
                "connection_id",
                "method",
                "process_instance",
                "request_seq",
                "route",
                "status",
            ],
            "capture must expose only the fixed non-sensitive fields"
        );
        // The whole record must not leak any raw secret material even though the request body
        // carried a token/nonce: only a fingerprint of the canonical body is recorded.
        let rendered = line.to_string();
        for forbidden in ["sdk-pop", "token", "nonce", "grant", "seed", "cert"] {
            assert!(
                !rendered.contains(forbidden),
                "capture record leaked sensitive substring {forbidden:?}: {rendered}"
            );
        }
        Ok(())
    }

    #[test]
    fn capture_write_is_fail_closed_on_unwritable_path() -> Result<(), String> {
        let line = capture_line(&request("/relay/v1/object/put_chunk"), 200, 7, 3, "write");
        // A writable path succeeds; an unwritable (missing parent dir) path is Err, so the
        // connection loop fails the connection instead of proceeding on a lost capture.
        let ok_path = std::env::temp_dir()
            .join(format!("ramflux-s62-capture-ok-{}.jsonl", std::process::id()));
        capture_to(&ok_path, &line).map_err(|()| "writable capture path must succeed")?;
        let _ = std::fs::remove_file(&ok_path);
        let bad_path =
            std::path::Path::new("/nonexistent-ramflux-itest-dir/capture.jsonl").to_path_buf();
        assert!(
            capture_to(&bad_path, &line).is_err(),
            "an unwritable capture path must fail closed"
        );
        Ok(())
    }

    #[test]
    fn capture_writes_are_atomic_under_concurrency() -> Result<(), String> {
        // CTRL-074: 16 concurrent writers x 100 lines each must produce exactly 1600 lines, every
        // one independently parseable, with unique request_seq (no interleaved/lost line). Proves
        // the pre-serialize + single-writer-lock + one write_all append is atomic under K-way
        // fan-out (the failure mode that dropped a whole daemon's connection from the log).
        use std::collections::BTreeSet;
        use std::sync::{Arc, Barrier};
        const THREADS: usize = 16;
        const LINES_PER_THREAD: usize = 100;

        let path = std::env::temp_dir()
            .join(format!("ramflux-capture-concurrency-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|thread_index| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                std::thread::spawn(move || -> Result<(), ()> {
                    barrier.wait();
                    for i in 0..LINES_PER_THREAD {
                        let seq = (thread_index * LINES_PER_THREAD + i) as u64;
                        let line = capture_line(
                            &request("/relay/v1/object/put_chunk"),
                            200,
                            thread_index as u64,
                            seq,
                            "write",
                        );
                        capture_to(&path, &line)?;
                    }
                    Ok(())
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .map_err(|_error| "capture writer thread panicked".to_owned())?
                .map_err(|()| "capture_to failed under concurrency".to_owned())?;
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let _ = std::fs::remove_file(&path);
        let mut seqs: BTreeSet<u64> = BTreeSet::new();
        let mut line_count = 0usize;
        for raw in contents.lines() {
            line_count += 1;
            let value: serde_json::Value = serde_json::from_str(raw)
                .map_err(|error| format!("unparseable capture line {raw:?}: {error}"))?;
            let seq = value
                .get("request_seq")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("capture line missing request_seq: {raw}"))?;
            if !seqs.insert(seq) {
                return Err(format!("duplicate request_seq {seq} — interleaved/corrupted write"));
            }
        }
        assert_eq!(
            line_count,
            THREADS * LINES_PER_THREAD,
            "all 1600 concurrent lines must be present and independently parseable"
        );
        assert_eq!(
            seqs.len(),
            THREADS * LINES_PER_THREAD,
            "every request_seq must survive uniquely (no lost or merged line)"
        );
        Ok(())
    }

    #[test]
    fn hold_marker_write_is_fail_closed_on_unwritable_path() -> Result<(), String> {
        let ok_path =
            std::env::temp_dir().join(format!("ramflux-s62-hold-ok-{}.marker", std::process::id()));
        write_marker_to(&ok_path).map_err(|()| "writable marker path must succeed")?;
        assert!(ok_path.exists(), "hold marker must be created");
        let _ = std::fs::remove_file(&ok_path);
        let bad_path =
            std::path::Path::new("/nonexistent-ramflux-itest-dir/hold.marker").to_path_buf();
        assert!(
            write_marker_to(&bad_path).is_err(),
            "an unwritable hold-marker path must fail closed"
        );
        Ok(())
    }
}
