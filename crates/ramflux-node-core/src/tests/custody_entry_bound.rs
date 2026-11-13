// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T3e passes authenticated native submissions through the real custody service.
use super::*;
#[test]
fn entry_admission_all_origins_native_custody() -> Result {
    for mode in 0..=1 {
        for over in [false, true] {
            let _store_directory_0 = temp_store_path(&format!("native-entry-bound-{mode}-{over}"))?;
            let root = _store_directory_0.to_path_buf();
            let store = crate::publication::open_durability_fixture(&root, mode)?;
            let router = RouterCore::new();
            store.bootstrap_router(&router)?;
            let (driver, service, session) = publication_session(&router, &store)?;
            let target = session.target_delivery_id.clone();
            let mut envelope = envelope("native-entry-bound", &target, DeliveryClass::OpaqueEvent);
            envelope.source_principal_id = "alice".into();
            envelope.source_device_id = "primary".into();
            envelope.created_at = i64::try_from(NOW)?;
            envelope.ext.ext.insert(
                "source_root_commitment".into(),
                serde_json::json!(driver.reference.account_anchor),
            );
            envelope.encrypted_payload.clear();
            envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
                [12; 32],
            );
            let base = crate::single_entry_frame_size(&envelope)?;
            envelope.encrypted_payload =
                "x".repeat(crate::ENTRY_FRAME_BYTE_CAP - base + usize::from(over));
            envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
                [12; 32],
            );
            let action = CustodySessionAction::Submit { envelope: Box::new(envelope) };
            let request = signed_request(
                &driver,
                &session,
                &action,
                &ramflux_protocol::encode_base64url([61; 32]),
            )?;
            let response = service.mesh(
                &router,
                &store,
                CustodyMeshRequest::Request {
                    session_id: session.session_id,
                    request: Box::new(request),
                    action,
                    connection_id: driver.connection,
                },
                PEER,
                NOW,
            );
            if over {
                assert_eq!(serde_json::to_value(&response)?["code"], "payload_too_large");
                assert!(
                    matches!(
                        response,
                        CustodyServerFrame::Refused { code: CustodyRefusal::PayloadTooLarge, .. }
                    ),
                    "{response:?}"
                );
                assert_eq!(store.inbox_status(&target)?.1, 0);
                assert_eq!(router.resume(&target, 0, 10), Vec::<crate::InboxEntry>::new());
                assert_eq!(store.sender_retry_registry_size(), 0);
            } else {
                assert!(matches!(response, CustodyServerFrame::Submitted { .. }), "{response:?}");
                assert_eq!(store.inbox_status(&target)?.1, 1);
            }
        }
    }
    Ok(())
}
