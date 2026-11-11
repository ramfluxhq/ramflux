// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S6c P09 handler rows: the real session ingress persists nothing (I-NP), keeps its rate state
//! on the session, and refuses source and signature failures with exact results.

use super::tests::{EnqueueRecorder, RouteRecorder, TestResult, guard_10s, mutated};
use super::{SubmitIngress, handle_submit_with};
use crate::session::submit_fixtures::{signed_submit, test_runtime};
use crate::session_push::tests::support::sink;
use ramflux_protocol::SignedRequest;
use serde_json::{Value, json};

pub(super) fn unix_now() -> i64 {
    i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX)
}

/// A correctly signed ephemeral submit from the fixture session; `change` edits the envelope
/// before it is signed, `tamper` edits the finished frame.
pub(crate) fn submit(
    runtime: &crate::GatewaySessionRuntime,
    id: &str,
    ttl: u32,
    change: impl FnOnce(&mut ramflux_protocol::Envelope),
) -> TestResult<ramflux_node_core::GatewaySubmitFrame> {
    let now = unix_now();
    let mut envelope = mutated(|e| {
        e.envelope_id = id.to_owned();
        e.source_principal_id = "agent".to_owned();
        e.source_device_id = "agent-device".to_owned();
        e.target_delivery_id = "alice-target".to_owned();
        e.created_at = now;
        e.ttl = ttl;
        e.ext.ext.insert(
            "source_root_commitment".to_owned(),
            json!(runtime.source_identity.root_commitment()),
        );
    });
    change(&mut envelope);
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        [4; 32],
    );
    let signed_request = signed_request_for(runtime, &envelope, now)?;
    Ok(ramflux_node_core::GatewaySubmitFrame { signed_request, envelope })
}

fn signed_request_for(
    runtime: &crate::GatewaySessionRuntime,
    envelope: &ramflux_protocol::Envelope,
    now: i64,
) -> TestResult<SignedRequest> {
    let mut request = signed_submit(runtime, now)?.signed_request;
    request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(envelope)?,
    );
    resign(&mut request)?;
    Ok(request)
}

fn resign(request: &mut SignedRequest) -> TestResult {
    request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(request)?,
        [4; 32],
    );
    Ok(())
}

/// Persisted and in-memory gateway state, serialized: byte-identical means nothing was written.
pub(super) fn snapshot(context: &crate::GatewayQuicContext) -> TestResult<Vec<u8>> {
    let disk = context.store.load_state()?;
    let memory =
        context.state.lock().map_err(|_| anyhow::anyhow!("gateway state poisoned"))?.clone();
    Ok(serde_json::to_vec(&(disk, memory))?)
}

struct Outcome {
    frames: Vec<Value>,
    route: RouteRecorder,
    enqueue: EnqueueRecorder,
}

async fn drive(
    runtime: &crate::GatewaySessionRuntime,
    now_ms: u64,
    frames: &[ramflux_node_core::GatewaySubmitFrame],
) -> TestResult<Outcome> {
    let (send, written) = sink();
    let (mut route, mut enqueue) = (RouteRecorder::default(), EnqueueRecorder::default());
    for frame in frames {
        guard_10s(
            "handle_submit_with",
            handle_submit_with(
                &send,
                &SubmitIngress { runtime, negotiated: true, now_ms },
                frame,
                &mut route,
                &mut enqueue,
            ),
        )
        .await?;
    }
    let frames = written.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    Ok(Outcome { frames, route, enqueue })
}

pub(super) fn now_ms() -> u64 {
    u64::try_from(unix_now()).unwrap_or(0).saturating_mul(1_000)
}

pub(super) fn dropped(id: &str, reason: &str) -> Value {
    json!({"frame_type":"ephemeral_result","envelope_id":id,"outcome":"dropped","reason":reason})
}

pub(super) fn accepted(id: &str) -> Value {
    json!({"frame_type":"ephemeral_result","envelope_id":id,"outcome":"accepted"})
}

/// I-NP: a correctly signed submit, accepted or refused by admission, writes no gateway state.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_ingress_persists_nothing() -> TestResult {
    let context = crate::session::tests::test_gateway_context()?;
    let runtime = test_runtime()?;
    let before = snapshot(&context)?;

    let ok = submit(&runtime, "np-accepted", 5, |_| {})?;
    let outcome = drive(&runtime, now_ms(), &[ok]).await?;
    anyhow::ensure!(outcome.frames == vec![accepted("np-accepted")], "{:?}", outcome.frames);
    anyhow::ensure!(outcome.route.calls.len() == 1 && outcome.enqueue.calls == 1);
    anyhow::ensure!(snapshot(&context)? == before, "accepted submit changed gateway state");

    let zero_ttl = submit(&runtime, "np-ttl0", 0, |_| {})?;
    let outcome = drive(&runtime, now_ms(), &[zero_ttl]).await?;
    anyhow::ensure!(outcome.frames == vec![dropped("np-ttl0", "invalid")], "{:?}", outcome.frames);
    anyhow::ensure!(outcome.route.calls.is_empty(), "ttl=0 reached the router");
    anyhow::ensure!(snapshot(&context)? == before, "refused submit changed gateway state");

    // Control: the persisting validator does change this snapshot, so the rows above are sensitive.
    let control = submit(&runtime, "np-control", 5, |_| {})?;
    crate::session::validate_gateway_session_signed_request(
        &context,
        &runtime,
        &control.signed_request,
        "POST",
        "/gateway/session/submit",
        &control.envelope,
    )?;
    anyhow::ensure!(snapshot(&context)? != before, "control: persisting validator wrote nothing");
    Ok(())
}

/// M1: the bucket belongs to the session; 40 consecutive submits at one instant, then the 41st.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_session_rate_state() -> TestResult {
    let runtime = test_runtime()?;
    let instant = now_ms();
    let mut frames = Vec::new();
    for n in 0..41 {
        frames.push(submit(&runtime, &format!("rate-{n}"), 5, |_| {})?);
    }
    let (send, written) = sink();
    let (mut route, mut enqueue) = (RouteRecorder::default(), EnqueueRecorder::default());
    for frame in &frames {
        // A clone of the runtime stands for the session's other handles: same bucket.
        let handle = runtime.clone();
        guard_10s(
            "handle_submit_with",
            handle_submit_with(
                &send,
                &SubmitIngress { runtime: &handle, negotiated: true, now_ms: instant },
                frame,
                &mut route,
                &mut enqueue,
            ),
        )
        .await?;
    }
    let written = written.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    anyhow::ensure!(written.len() == 41, "one result per submit, got {}", written.len());
    for (n, frame) in written.iter().take(40).enumerate() {
        anyhow::ensure!(*frame == accepted(&format!("rate-{n}")), "submit {n}: {frame}");
    }
    anyhow::ensure!(written[40] == dropped("rate-40", "rate_limited"), "{}", written[40]);
    anyhow::ensure!(route.calls.len() == 40, "41st submit routed: {}", route.calls.len());
    anyhow::ensure!(enqueue.calls == 40);
    Ok(())
}

type Tamper = fn(&mut ramflux_node_core::GatewaySubmitFrame) -> TestResult;

fn expect_refused(label: &str, outcome: &Outcome, id: &str) -> TestResult {
    anyhow::ensure!(
        outcome.frames == vec![dropped(id, "invalid")],
        "{label}: {:?}",
        outcome.frames
    );
    anyhow::ensure!(outcome.route.calls.is_empty(), "{label}: router called");
    anyhow::ensure!(outcome.enqueue.calls == 0, "{label}: enqueue called");
    Ok(())
}

/// M3: each source or signature failure gets the exact refusal, with zero router calls.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_ingress_source_failures() -> TestResult {
    let runtime = test_runtime()?;
    let now = unix_now();

    let mismatch = submit(&runtime, "src-mismatch", 5, |e| {
        e.source_principal_id = "mallory".to_owned();
    })?;
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &mismatch.envelope)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("submit source differs from authenticated session")
    );
    expect_refused(
        "source mismatch",
        &drive(&runtime, now_ms(), &[mismatch]).await?,
        "src-mismatch",
    )?;

    let mut bad_envelope = submit(&runtime, "src-badsig", 5, |_| {})?;
    bad_envelope.envelope.signed.signature = "invalid".to_owned();
    bad_envelope.signed_request = signed_request_for(&runtime, &bad_envelope.envelope, now)?;
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &bad_envelope.envelope)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("base64url decode failed: Invalid last symbol 100, offset 6.")
    );
    expect_refused(
        "envelope signature",
        &drive(&runtime, now_ms(), &[bad_envelope]).await?,
        "src-badsig",
    )?;

    // Signed-request failures: (label, exact verify error, tamper).
    let rows: [(&str, &str, Tamper); 8] = [
        (
            "source device",
            "signed request source device does not match authenticated session",
            |f| {
                f.signed_request.source_device_id = "other-device".to_owned();
                resign(&mut f.signed_request)
            },
        ),
        ("path", "signed request path mismatch", |f| {
            f.signed_request.path = "/gateway/session/other".to_owned();
            resign(&mut f.signed_request)
        }),
        ("session binding", "signed request must bind to authenticated gateway session", |f| {
            f.signed_request.device_proof_hash = "proof".to_owned();
            resign(&mut f.signed_request)
        }),
        ("method", "signed request method mismatch", |f| {
            f.signed_request.method = ramflux_protocol::HttpMethod::GET;
            resign(&mut f.signed_request)
        }),
        ("expired", "signed request expired", |f| {
            f.signed_request.expires_at = 1;
            resign(&mut f.signed_request)
        }),
        ("body hash", "signed request body hash mismatch", |f| {
            f.signed_request.body_hash = "wrong".to_owned();
            resign(&mut f.signed_request)
        }),
        (
            "malformed request signature",
            "base64url decode failed: Invalid last symbol 100, offset 6.",
            |f| {
                f.signed_request.signed.signature = "invalid".to_owned();
                Ok(())
            },
        ),
        ("request signed by another key", "ed25519 verification failed", |f| {
            f.signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_protocol::signed_bytes(&f.signed_request)?,
                [9; 32],
            );
            Ok(())
        }),
    ];
    for (label, want, tamper) in rows {
        let mut frame = submit(&runtime, "req-failure", 5, |_| {})?;
        tamper(&mut frame)?;
        let error = crate::session::verify_gateway_session_signed_request(
            &runtime,
            &frame.signed_request,
            "POST",
            "/gateway/session/submit",
            &frame.envelope,
        )
        .err()
        .map(|e| e.to_string());
        anyhow::ensure!(error.as_deref() == Some(want), "{label}: {error:?}");
        expect_refused(label, &drive(&runtime, now_ms(), &[frame]).await?, "req-failure")?;
    }
    Ok(())
}

/// Envelope binding negatives: the signed request is valid and only the envelope's device or
/// `source_root_commitment` disagrees with the authenticated session; zero router calls.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_ingress_envelope_binding_failures() -> TestResult {
    let runtime = test_runtime()?;
    // Separate envelope binding negatives: the signed request is valid and only the envelope's
    // device or source_root_commitment disagrees with the authenticated session.
    let device = submit(&runtime, "src-device", 5, |e| {
        e.source_device_id = "other-device".to_owned();
    })?;
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &device.envelope)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("submit source differs from authenticated session")
    );
    expect_refused("envelope device", &drive(&runtime, now_ms(), &[device]).await?, "src-device")?;

    // A validly encoded signature made by another key: the verifier refuses it, not the decoder.
    let mut wrong_key = submit(&runtime, "src-wrongkey", 5, |_| {})?;
    wrong_key.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&wrong_key.envelope)?,
        [9; 32],
    );
    wrong_key.signed_request = signed_request_for(&runtime, &wrong_key.envelope, unix_now())?;
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &wrong_key.envelope)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("ed25519 verification failed")
    );
    expect_refused(
        "envelope wrong key",
        &drive(&runtime, now_ms(), &[wrong_key]).await?,
        "src-wrongkey",
    )?;

    let root = submit(&runtime, "src-root", 5, |e| {
        e.ext.ext.insert("source_root_commitment".to_owned(), json!("wrong"));
    })?;
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &root.envelope)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("submit source differs from authenticated session")
    );
    expect_refused(
        "source_root_commitment",
        &drive(&runtime, now_ms(), &[root]).await?,
        "src-root",
    )?;
    Ok(())
}
