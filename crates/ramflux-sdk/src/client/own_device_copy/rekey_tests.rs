// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live MAC consumers retain replay authority across database-key changes.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn rekey_preserves_own_sent_index_claim_and_receipt_replay_refusal() -> TestResult {
    let mut own = Fixture::new("native-copy-rekey").await?;
    let source = own.client.owned_device_identity()?;
    let envelope = "stable-copy-envelope";
    let mut bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&json!({
        "envelope_id":envelope,"message_id":"original-text-id","sender_id":source.device_id(),
        "context":{"conversation_id":"rekey-thread","participants":[own.manifest.principal_id,"peer"],"group":null,"friend":null},
        "ciphertext_hash":crate::client::own_sent_message::own_sent_ciphertext_hash(b"ciphertext"),
        "body_base64":ramflux_protocol::encode_base64url(b"copied body")
    }))?);
    let created_at = crate::time::now_unix_timestamp();
    let input = || crate::client::own_device_copy::OwnMessageInput {
        id: envelope,
        conversation: "rekey-thread",
        group: None,
        created_at,
        body: &bytes,
    };
    assert!(own.client.receive_own_sent_message(&source, input())?);
    let original_rows = own.client.direct_messages("rekey-thread")?;
    assert_eq!(original_rows.len(), 1);
    let db = own.client.account_db()?;
    let scope = db.own_sent_receipt_scope("source", "target")?;
    let claim = db.own_sent_replay_claim(&source, envelope)?;
    let receipt = Receipt {
        fingerprint: "packet-fingerprint".into(),
        scope: ReceiptScope::Private { private_scope: scope.clone() },
        valid_until: created_at + 900,
        expires_at: created_at + 1200,
        acknowledged: false,
    };
    let receipt_key = format!("{RECEIPTS}rekey-packet");
    db.persist_actor_state(&receipt_key, &receipt)?;
    let packet_key = "own-device/committed-packet/rekey-packet";
    receipts::remember(db, packet_key, "packet-fingerprint", created_at + 900, false, created_at)?;
    let before = serde_json::to_vec(&db.list_actor_states::<serde_json::Value>("own-device/")?)?;
    let mut last_key = None;
    let mut provider = ramflux_storage::LocalVaultKeyWrappingProvider::new([8; 32]);
    for stage in 0..3 {
        let key = ramflux_storage::AccountDbKey::generate()?;
        let db = own.client.active_account_db.as_mut().ok_or("db")?;
        let previous = db.wrap_current_db_key(&[8; 32])?;
        match stage {
            0 => db.rekey(&key)?,
            1 => {
                provider.fail_next_wrap();
                assert!(db.rekey_with_wrapping(&key, &mut provider, &previous).is_err());
            }
            _ => {
                db.rekey_with_wrapping(&key, &mut provider, &previous)?;
            }
        }
        if stage != 1 {
            last_key = Some(key);
        }
        own.client.active_account_db.take();
        let db = ramflux_storage::AccountDb::open(
            own.client.account_index()?,
            "native-copy-rekey",
            last_key.as_ref().ok_or("rekey key")?,
        )?
        .with_device_signer(own.client.device_branch.as_ref().ok_or("signer")?.clone());
        own.client.active_account_db = Some(db);
        assert!(own.client.receive_own_sent_message(&source, input())?);
        assert_eq!(
            own.client.direct_messages("rekey-thread")?.len(),
            1,
            "duplicate projected after rekey"
        );
        let db = own.client.account_db()?;
        assert_eq!(
            serde_json::to_vec(&db.list_actor_states::<serde_json::Value>("own-device/")?)?,
            before
        );
        assert_receipt_replay(db, &receipt_key, packet_key, created_at)?;
        assert_eq!(db.own_sent_receipt_scope("source", "target")?, scope);
        assert_eq!(db.own_sent_replay_claim(&source, envelope)?, claim);
    }
    let mut fresh_packet: serde_json::Value =
        serde_json::from_slice(&bytes[b"ramflux.own_sent_message.v1\n".len()..])?;
    fresh_packet["envelope_id"] = json!("fresh-envelope");
    fresh_packet["message_id"] = json!("fresh-original");
    fresh_packet["ciphertext_hash"] =
        json!(crate::client::own_sent_message::own_sent_ciphertext_hash(b"fresh-ciphertext"));
    let mut fresh_bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    fresh_bytes.extend(serde_json::to_vec(&fresh_packet)?);
    let fresh = crate::client::own_device_copy::OwnMessageInput {
        id: "fresh-envelope",
        body: &fresh_bytes,
        ..input()
    };
    assert!(own.client.receive_own_sent_message(&source, fresh)?);
    assert_eq!(own.client.direct_messages("rekey-thread")?.len(), 2);
    Ok(())
}

fn assert_receipt_replay(
    db: &ramflux_storage::AccountDb,
    receipt_key: &str,
    packet_key: &str,
    created_at: i64,
) -> TestResult {
    let retained = db.load_actor_state::<Receipt>(receipt_key)?.ok_or("private receipt")?;
    retained.validate(db, "source", "target", "packet-fingerprint", created_at)?;
    assert!(
        retained.validate(db, "other-source", "target", "packet-fingerprint", created_at).is_err()
    );
    assert!(
        retained.validate(db, "source", "other-target", "packet-fingerprint", created_at).is_err()
    );
    assert!(retained.validate(db, "source", "target", "different-packet", created_at).is_err());
    assert!(receipts::committed(db, packet_key, "packet-fingerprint", created_at)?);
    assert!(!receipts::committed(
        db,
        "own-device/committed-packet/fresh",
        "packet-fingerprint",
        created_at
    )?);
    assert!(receipts::committed(db, packet_key, "different-packet", created_at).is_err());
    Ok(())
}
