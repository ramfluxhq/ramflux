// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use serde_json::json;
fn response(value: serde_json::Value) -> anyhow::Result<IssuedSeqsResponse> {
    Ok(serde_json::from_value(value)?)
}
const ID: &str = "0123456789abcdef0123456789abcdef";
#[test]
fn issued_seqs_contract() -> anyhow::Result<()> {
    use InvalidBatch as E;
    let empty = || response(json!({"issued":[]}));
    for targets in [vec![], vec!["x".into(); 1025]] {
        assert_eq!(validate(&targets, empty()?).err(), Some(E::TargetCount));
    }
    assert_eq!(validate(&["x".into(), "x".into()], empty()?).err(), Some(E::TargetDuplicate));
    assert_eq!(validate(&[String::new()], empty()?).err(), Some(E::TargetEmpty));
    assert_eq!(validate(&["x".into()], empty()?).err(), Some(E::ResultCount));
    let row = |target: &str, seq, id| json!({"target_delivery_id":target,"inbox_seq":seq,"incarnation_id":id});
    assert_eq!(
        validate(&["x".into()], response(json!({"issued":[row("z",0,None::<&str>)]}))?).err(),
        Some(E::ResultTarget)
    );
    assert_eq!(
        validate(
            &["x".into(), "y".into()],
            response(json!({"issued":[row("x",0,None::<&str>),row("x",0,None::<&str>)]}))?
        )
        .err(),
        Some(E::ResultDuplicate)
    );
    for (seq, id) in [(1, None), (0, Some("BAD")), (2, Some("ABCDEF0123456789abcdef0123456789ab"))]
    {
        assert_eq!(
            validate(&["x".into()], response(json!({"issued":[row("x",seq,id)]}))?).err(),
            Some(E::Incarnation)
        );
    }
    for n in [1, 1024] {
        let targets: Vec<_> = (0..n).map(|i| format!("t{i}")).collect();
        let rows: Vec<_> = targets.iter().map(|t| row(t, 0, None::<&str>)).collect();
        assert_eq!(validate(&targets, response(json!({"issued":rows}))?)?.len(), n);
    }
    Ok(())
}
#[test]
fn probe_hole_below_high_push() {
    let mut c = Coverage::default();
    assert!(c.offered(2, 2));
    assert_eq!(c.prefix, 0);
    assert_eq!(c.observe(Some(2)), None);
    assert_eq!(c.observe(Some(2)), Some((0, 2)));
    assert_eq!(c.observe(None), None);
    assert_eq!(c.observe(Some(2)), None);
    assert_eq!(c.observe(Some(2)), Some((0, 2)));
    assert!(c.offered(1, 1));
    assert_eq!(c.prefix, 2);
    assert_eq!(c.observe(Some(2)), None);
    let mut c = Coverage::default();
    for n in 1..=256 {
        assert!(c.offered(n * 2, n * 2));
    }
    assert!(!c.offered(514, 514));
    assert_eq!(c.ranges.len(), 256);
    assert_eq!(c.prefix, 0);
}

#[tokio::test]
async fn probe_hole_wire_and_replacement() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, sink};
    let fixture = Fixture::new("probe-hole")?;
    let hub = &fixture.context.hub;
    let (send, rows) = sink();
    let reg =
        hub.register_session("target".into(), "s".into(), send.clone(), Some(ID.into())).await?;
    // Completion of s2 alone leaves s1 uncovered. Write through the production guarded sink.
    crate::push_queue::write_frame(
        &send,
        &serde_json::to_vec(&json!({"frame_type":"deliver","entry":{"inbox_seq":2}}))?,
    )
    .await?;
    let observed: IssuedSeq = serde_json::from_value(
        json!({"target_delivery_id":"target","inbox_seq":2,"incarnation_id":ID}),
    )?;
    hub.probe_observation("target", reg.token, Some(&observed)).await;
    assert_eq!(rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?.len(), 1);
    hub.probe_observation("target", reg.token, Some(&observed)).await;
    hub.flushed("target").await?;
    assert_eq!(
        rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?[1]["after_inbox_seq"],
        0
    );
    assert_eq!(
        rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?[1]["frame_type"],
        "resync"
    );
    hub.probe_observation("target", reg.token, Some(&observed)).await;
    hub.flushed("target").await?;
    assert_eq!(
        rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?.len(),
        2,
        "completed hint covers its watermark"
    );
    assert_eq!(
        rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?[1]["incarnation_id"],
        ID
    );
    // Hold the shared sink until a complete Resume supersedes a pending probe hint.
    let mut held_sink = send.lock().await;
    let newer: IssuedSeq = serde_json::from_value(
        json!({"target_delivery_id":"target","inbox_seq":4,"incarnation_id":ID}),
    )?;
    hub.probe_observation("target", reg.token, Some(&newer)).await;
    hub.probe_observation("target", reg.token, Some(&newer)).await;
    held_sink
        .send_frame(&serde_json::to_vec(
            &json!({"frame_type":"resume_page","after_inbox_seq":2,"covered_through_seq":4}),
        )?)
        .await?;
    drop(held_sink);
    hub.flushed("target").await?;
    assert_eq!(
        rows.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?.len(),
        3,
        "completed Resume suppresses obsolete hint"
    );
    let (new_send, new_rows) = sink();
    let new =
        hub.register_session("target".into(), "new".into(), new_send, Some(ID.into())).await?;
    hub.probe_observation("target", reg.token, Some(&observed)).await;
    hub.probe_observation("target", new.token, Some(&observed)).await;
    assert!(
        new_rows.lock().map_err(|_| anyhow::anyhow!("new capture poisoned"))?.is_empty(),
        "old token cannot confirm replacement"
    );
    hub.probe_observation("target", new.token, Some(&observed)).await;
    hub.flushed("target").await?;
    assert_eq!(new_rows.lock().map_err(|_| anyhow::anyhow!("new capture poisoned"))?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn population_probe() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, sink};
    for n in [1025_usize, 5000, 40960] {
        let mut fixture = Fixture::new(&format!("population-{n}"))?;
        let (send, _) = sink();
        fixture.context.hub.population_fixture(n, ID, &send).await;
        for observation in 0..4 {
            let hub = fixture.context.hub.clone();
            let router = fixture.context.router.clone();
            let task = tokio::spawn(async move { round(&hub, &router).await });
            let mut seen = std::collections::BTreeSet::new();
            let batches = n.div_ceil(1024);
            for group in 0..batches.div_ceil(4) {
                let width = (batches - group * 4).min(4);
                let mut held = Vec::new();
                // Holding all four proves the task launches its concurrency window.
                for _ in 0..width {
                    held.push(fixture.next().await?);
                }
                assert!(
                    matches!(
                        fixture.requests.try_recv(),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    ),
                    "more than four concurrent requests"
                );
                for request in held {
                    assert_eq!(request.path, "/mvp0/issued-seqs");
                    let targets = request.body["targets"]
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("targets missing"))?;
                    assert!(!targets.is_empty() && targets.len() <= 1024);
                    let rows: Vec<_> = targets
                        .iter()
                        .map(|t| {
                            assert!(
                                seen.insert(t.as_str().unwrap_or_default().to_owned()),
                                "visited twice"
                            );
                            json!({"target_delivery_id":t,"incarnation_id":ID,"inbox_seq":2})
                        })
                        .collect();
                    let value = if observation == 1 {
                        json!({"issued":[]})
                    } else {
                        json!({"issued":rows})
                    };
                    request
                        .respond
                        .send((200, value))
                        .map_err(|_| anyhow::anyhow!("request cancelled"))?;
                }
            }
            assert_eq!(seen.len(), n, "every initial token visited");
            assert_eq!(task.await?, observation == 1);
            let snapshot = fixture.context.hub.snapshot().await;
            assert!(
                snapshot.values().all(|e| e.queue.probe_pending() == (observation == 3)),
                "failure resets consecutive confirmations; second complete observation hints every token"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn probe_timeout_resets_confirmation() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, sink};
    let mut fixture = Fixture::new("probe-timeout")?;
    let (send, _) = sink();
    fixture.context.hub.population_fixture(1, ID, &send).await;
    let hub = fixture.context.hub.clone();
    let snapshot = hub.snapshot().await;
    let row = snapshot.page(0).remove(0);
    let observed: IssuedSeq = serde_json::from_value(
        json!({"target_delivery_id":row.0,"inbox_seq":2,"incarnation_id":ID}),
    )?;
    hub.probe_observation(&row.0, row.1.token, Some(&observed)).await;
    let router = fixture.context.router.clone();
    let running = hub.clone();
    let task = tokio::spawn(async move { round(&running, &router).await });
    let held = fixture.next().await?;
    assert_eq!(held.path, "/mvp0/issued-seqs");
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(1501)).await;
    tokio::time::resume();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), task).await??,
        "held request must fail at its 1.5 second probe deadline"
    );
    drop(held);
    hub.probe_observation(&row.0, row.1.token, Some(&observed)).await;
    assert!(!row.1.queue.probe_pending(), "timeout reset the first confirmation");
    hub.probe_observation(&row.0, row.1.token, Some(&observed)).await;
    assert!(row.1.queue.probe_pending());
    Ok(())
}

#[tokio::test]
async fn probe_router_origin_hole() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, sink};
    use ramflux_node_core::{RouterCore, RouterSubmitOutcome, publication};
    let fixture = Fixture::new("probe-router-hole")?;
    let root = crate::clients::tests::temp_cert_root("probe-router-store")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = publication::open_durability_fixture(&root, 0)?;
    let router = RouterCore::new();
    let runtime = crate::session::submit_ack_tests::test_runtime()?;
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    store.initialize_inbox("alice-target")?;
    router.prepare_publication_target(&store, "alice-target")?;
    let mut rows = Vec::new();
    for seq in 1..=2 {
        let mut envelope = crate::session::submit_ack_tests::signed_submit(&runtime, now)?.envelope;
        envelope.envelope_id = format!("probe-origin-{seq}");
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            [4; 32],
        );
        let accepted = publication::capture(|| -> anyhow::Result<_> {
            let RouterSubmitOutcome::OfflineQueued(queued) =
                router.submit_envelope_at(&runtime.source_identity, envelope, now)
            else {
                anyhow::bail!("router did not accept probe fixture");
            };
            store.record_submission_increment(
                &format!("probe-origin-{seq}"),
                now + 3600,
                Some(&queued.entry),
            )?;
            Ok(queued.entry)
        })?;
        rows.push(accepted.published().await?);
    }
    let observed: IssuedSeq =
        serde_json::from_value(serde_json::to_value(router.session_push_status("alice-target"))?)?;
    assert_eq!(observed.inbox_seq, 2);
    let id = observed.incarnation_id.as_deref().ok_or_else(|| anyhow::anyhow!("router E"))?;
    let ramflux_node_core::InboxEntryResponse::Entry { record, .. } =
        router.fetch_entry("alice-target", 2, now)?
    else {
        anyhow::bail!("live second entry");
    };
    let deadline = record.retain_until;
    let (send, captured) = sink();
    let hub = &fixture.context.hub;
    let registration = hub
        .register_session("alice-target".into(), "recipient".into(), send, Some(id.into()))
        .await?;
    assert!(
        hub.send_delivery(
            "alice-target",
            &ramflux_node_core::GatewayServerFrame::Deliver { entry: rows[1].clone() },
            Some((id, deadline))
        )
        .await
    );
    hub.flushed("alice-target").await?;
    hub.probe_observation("alice-target", registration.token, Some(&observed)).await;
    assert_eq!(captured.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?.len(), 1);
    hub.probe_observation("alice-target", registration.token, Some(&observed)).await;
    hub.flushed("alice-target").await?;
    let wire = captured.lock().map_err(|_| anyhow::anyhow!("capture poisoned"))?;
    assert_eq!(wire[0]["entry"]["inbox_seq"], 2);
    assert_eq!(wire[0]["retain_until"], deadline);
    assert_eq!(wire[1]["after_inbox_seq"], 0, "router-origin sequence one remains uncovered");
    assert_eq!(wire[1]["incarnation_id"], id);
    drop(wire);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn issued_raw_reply_duplicates_and_identity() -> anyhow::Result<()> {
    let targets = vec!["target".into()];
    let raw = br#"{"status":200,"body":{"issued":[{"target_delivery_id":"target","incarnation_id":null,"inbox_seq":0}]}}"#;
    let wire: IssuedWireResponse = ramflux_protocol::parse_i_json(raw)?;
    assert_eq!(serde_json::to_vec(&wire)?, raw);
    assert_eq!(decode(&targets, raw, true)?["target"].inbox_seq, 0);
    for (raw, message) in [
        (br#"{"status":200,"status":200,"body":{"issued":[]}}"#.as_slice(), "I-JSON ingress rejected: duplicate I-JSON member at line 1 column 22"),
        (br#"{"issued":[],"issued":[]}"#.as_slice(), "I-JSON ingress rejected: duplicate I-JSON member at line 1 column 21"),
        (br#"{"issued":[{"target_delivery_id":"target","incarnation_id":null,"inbox_seq":0,"inbox_seq":0}]}"#.as_slice(), "I-JSON ingress rejected: duplicate I-JSON member at line 1 column 89"),
        (br#"{"issued":[{"target_delivery_id":"target","target_delivery_id":"target","inbox_seq":0}]}"#.as_slice(), "I-JSON ingress rejected: duplicate I-JSON member at line 1 column 62"),
    ] {
        let error = decode(&targets, raw, raw.starts_with(b"{\"status"))
            .err().ok_or_else(|| anyhow::anyhow!("duplicate reply accepted"))?;
        assert_eq!(error.to_string(), message);
    }
    Ok(())
}

#[tokio::test]
async fn probe_raw_wire_bytes_are_preserved() -> anyhow::Result<()> {
    use crate::session_push::tests::support::Fixture;
    let mut fixture = Fixture::raw("probe-raw-bytes")?;
    let router = fixture.context.router.clone();
    let requests = std::sync::Arc::new(Requests::default());
    let running = requests.clone();
    let task =
        tokio::spawn(async move { request::post(&router, vec!["target".into()], &running).await });
    let request = fixture.next().await?;
    let raw = r#"{ "status": 200, "body": {"issued":[{"target_delivery_id":"target","incarnation_id":null,"inbox_seq":0,"inbox_seq":1}]}}"#;
    request.respond.send((200, json!(raw))).map_err(|_| anyhow::anyhow!("probe cancelled"))?;
    let reply = tokio::time::timeout(Duration::from_secs(10), task).await???;
    assert!(reply.mesh_frame);
    assert_eq!(
        reply.bytes,
        raw.as_bytes(),
        "transport must preserve the bytes checked by the decoder"
    );
    let error = decode(&["target".into()], &reply.bytes, true)
        .err()
        .ok_or_else(|| anyhow::anyhow!("raw duplicate accepted"))?;
    assert_eq!(
        error.to_string(),
        "I-JSON ingress rejected: duplicate I-JSON member at line 1 column 114"
    );
    assert_eq!(requests.0.available_permits(), 4);
    Ok(())
}

#[tokio::test]
async fn probe_live_requests_across_batches_and_rounds() -> anyhow::Result<()> {
    use crate::session_push::tests::support::{Fixture, sink};
    let mut fixture = Fixture::raw("probe-live-budget")?;
    let (send, _) = sink();
    fixture.context.hub.population_fixture(5120, ID, &send).await;
    for _round in 0..2 {
        let hub = fixture.context.hub.clone();
        let router = fixture.context.router.clone();
        let task = tokio::spawn(async move { round(&hub, &router).await });
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(fixture.next().await?);
        }
        assert_eq!(fixture.context.hub.probe_requests.0.available_permits(), 0);
        assert!(matches!(
            fixture.requests.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(1501)).await;
        tokio::time::resume();
        for request in &mut held {
            tokio::time::timeout(Duration::from_secs(10), request.respond.closed()).await?;
        }
        let mut fifth = fixture.next().await?;
        assert_eq!(
            fifth.body["targets"].as_array().ok_or_else(|| anyhow::anyhow!("targets"))?.len(),
            1024
        );
        assert!(
            held.iter().all(|request| request.respond.is_closed()),
            "new batch outlived earlier live transport work"
        );
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(1501)).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(10), fifth.respond.closed()).await?;
        assert!(tokio::time::timeout(Duration::from_secs(10), task).await??);
        assert_eq!(fixture.context.hub.probe_requests.0.available_permits(), 4);
    }
    Ok(())
}
