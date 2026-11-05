// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pending mutation receipts retain their typed refusal across real bus framing.

use super::*;
use crate::bus::mutation_intent::MutationIntent;
use serde_json::json;

type Case = Result<(), Box<dyn std::error::Error>>;

fn mutations() -> Vec<LocalBusFrame> {
    [
        ("message.send", json!({"conversation_id":"thread","message_id":"message"})),
        // Pending receipts resolve before method dispatch, including unknown methods.
        (
            "message.submit",
            json!({
                "conversation_id":"thread", "message_id":"message", "envelope_id":"envelope",
                "source_principal_id":"alice", "sender_id":"device-alice",
                "target_delivery_id":"target", "encrypted_body_base64":"", "created_at":1, "ttl":60
            }),
        ),
        ("grant.approve", json!({"grant_id":"grant"})),
    ]
    .into_iter()
    .map(|(method, body)| {
        let mut frame = request(method, "alice", method, body);
        frame.operation_id = Some(format!("pending-{method}"));
        frame
    })
    .collect()
}

async fn pending_mutations(changed_intent: bool) -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("typed-reconciliation");
            let initialize = actor_account(&root, "alice", None, Arc::new(AtomicBool::new(false)));
            let initialize: AccountInitializer = Box::new(move |index| {
                let account = initialize(index)?;
                for frame in mutations() {
                    let intent = MutationIntent::new(&frame)?;
                    let db = account.client.account_db()?;
                    assert!(intent.reserve(db)?.is_none());
                    let error = intent.reserve(db).err().ok_or_else(|| failure("pending reservation accepted"))?;
                    assert!(matches!(error, SdkError::Storage(ramflux_storage::StorageError::OperationReconciliationRequired { key }) if Some(key.as_str()) == frame.operation_id.as_deref()));
                }
                Ok(account)
            });
            let supervisor = supervisor(&root, BTreeMap::from([("alice".into(), initialize)]))?;
            let (mut socket, peer) = UnixStream::pair()?;
            let owner = Rc::clone(&supervisor);
            let handler = tokio::task::spawn_local(async move {
                crate::bus::connection::handle(peer, owner, 1).await
            });
            for mut frame in mutations() {
                if changed_intent {
                    frame.body["changed_intent"] = json!(true);
                }
                write_local_bus_frame(&mut socket, &frame).await?;
                let response =
                    tokio::time::timeout(Duration::from_secs(5), read_local_bus_frame(&mut socket))
                        .await??;
                assert_eq!(response.request_id, frame.request_id);
                let error = response.error.ok_or("pending mutation accepted")?;
                if changed_intent {
                    assert_eq!(error.code, "ValidationFailed", "{}", frame.method);
                    assert!(error.message.contains("event id conflict"));
                } else {
                    assert_eq!(error.code, "OperationReconciliationRequired", "{}", frame.method);
                    assert!(error.message.contains("operation requires reconciliation"));
                    assert!(error.message.contains(frame.operation_id.as_deref().ok_or("key")?));
                }
            }
            drop(socket);
            handler.await??;
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn mutation_reconciliation_refusal_has_typed_code() -> Case {
    pending_mutations(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn plain_event_id_conflict_stays_validation_failed() -> Case {
    // The key itself must never drive classification through diagnostic text.
    let error = ramflux_storage::StorageError::EventIdConflict(
        "operation requires reconciliation: ordinary-event-id".into(),
    );
    assert_eq!(local_bus_error_code(&error.into()), "ValidationFailed");
    pending_mutations(true).await
}
