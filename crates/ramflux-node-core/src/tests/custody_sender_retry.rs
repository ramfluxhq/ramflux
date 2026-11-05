// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authenticated retries attach before replay and retain typed refusals.
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
fn request(
    driver: &Driver,
    session: &CustodySession,
    envelope: ramflux_protocol::Envelope,
    nonce: u8,
) -> Result<CustodyMeshRequest> {
    let action = CustodySessionAction::Submit { envelope: Box::new(envelope) };
    let signed =
        signed_request(driver, session, &action, &ramflux_protocol::encode_base64url([nonce; 32]))?;
    Ok(CustodyMeshRequest::Request {
        session_id: session.session_id.clone(),
        request: Box::new(signed),
        action,
        connection_id: driver.connection.clone(),
    })
}
#[test]
fn native_sender_retries_attach_and_reuse_durable_assignment() -> Result {
    for mode in 0..3 {
        for abort in [false, true] {
            let root = temp_store_path(&format!("native-retry-{mode}-{abort}"))?;
            let store = crate::publication::open_durability_fixture(&root, mode)?;
            let router = RouterCore::new();
            store.bootstrap_router(&router)?;
            let (driver, service, session) = publication_session(&router, &store)?;
            let target = session.target_delivery_id.clone();
            store.initialize_inbox(&target)?;
            router.prepare_publication_target(&store, &target)?;
            let mut envelope = envelope("native-retry", &target, DeliveryClass::OpaqueEvent);
            envelope.source_principal_id = "alice".into();
            envelope.source_device_id = "primary".into();
            envelope.created_at = i64::try_from(NOW)?;
            envelope.ext.ext.insert(
                "source_root_commitment".into(),
                serde_json::json!(driver.reference.account_anchor),
            );
            envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
                [12; 32],
            );
            let original = request(&driver, &session, envelope.clone(), 31)?;
            let retry = request(&driver, &session, envelope.clone(), 32)?;
            let held = hold(root.clone(), abort);
            std::thread::scope(|scope| -> Result {
                let first = scope.spawn(|| service.mesh(&router, &store, original, PEER, NOW));
                held.arrived.recv_timeout(Duration::from_secs(30))?;
                let second = scope.spawn(|| service.mesh(&router, &store, retry, PEER, NOW));
                held.attachment.recv_timeout(Duration::from_secs(30))?;
                let mut changed = envelope.clone();
                changed.encrypted_payload.push('x');
                changed.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                    &ramflux_protocol::envelope_sender_signed_bytes(&changed)?,
                    [12; 32],
                );
                let conflict = service.mesh(
                    &router,
                    &store,
                    request(&driver, &session, changed, 33)?,
                    PEER,
                    NOW,
                );
                assert!(
                    matches!(
                        conflict,
                        CustodyServerFrame::Refused {
                            code: CustodyRefusal::IdempotencyConflict,
                            ..
                        }
                    ),
                    "{conflict:?}"
                );
                held.release.send(())?;
                for reply in [
                    first.join().map_err(|_| "original panic")?,
                    second.join().map_err(|_| "retry panic")?,
                ] {
                    if abort {
                        assert!(
                            matches!(
                                reply,
                                CustodyServerFrame::Refused {
                                    code: CustodyRefusal::AbortedRetrySafe,
                                    ..
                                }
                            ),
                            "{reply:?}"
                        );
                    } else {
                        assert!(matches!(reply, CustodyServerFrame::Submitted { .. }), "{reply:?}");
                    }
                }
                Ok(())
            })?;
            drop(held);
            for nonce in [34, 35] {
                let reply = service.mesh(
                    &router,
                    &store,
                    request(&driver, &session, envelope.clone(), nonce)?,
                    PEER,
                    NOW,
                );
                assert!(matches!(reply, CustodyServerFrame::Submitted { .. }), "{reply:?}");
            }
            assert_eq!(store.inbox_status(&target)?.1, if abort { 2 } else { 1 });
            assert_eq!(router.resume(&target, 0, 10).len(), 1);
            assert_eq!(store.sender_retry_registry_size(), 0);
            drop(service);
            drop(router);
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

struct Hold {
    arrived: mpsc::Receiver<()>,
    attachment: mpsc::Receiver<()>,
    release: mpsc::SyncSender<()>,
    _observer: crate::durability_test_hooks::Registration,
}
fn hold(root: PathBuf, abort: bool) -> Hold {
    let (entered, arrived) = mpsc::sync_channel(1);
    let (attached, attachment) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Mutex::new(wait);
    let once = AtomicBool::new(false);
    let observer = crate::durability_test_hooks::observe(
        root.clone(),
        Arc::new(move |_, op, done| {
            if op == "retry_attached" && done {
                let _ = attached.try_send(());
            }
            if op == "reserved_assignment" && done && !once.swap(true, Ordering::Relaxed) {
                entered.send(()).map_err(std::io::Error::other)?;
                wait.lock()
                    .map_err(|_| std::io::Error::other("lock"))?
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(std::io::Error::other)?;
                if abort {
                    return Err(std::io::Error::other("pre-handoff abort"));
                }
            }
            Ok(())
        }),
    );
    Hold { arrived, attachment, release, _observer: observer }
}
