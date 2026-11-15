// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live MAC consumers retain replay authority across database-key changes.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn rekey_preserves_own_sent_index_claim_and_receipt_replay_refusal() -> TestResult {
    crate::client::native_test_support::watchdog::within(native_rekey()).await?
}

async fn native_rekey() -> TestResult {
    use crate::client::native_test_support::sibling_erasure;
    let mut source = Fixture::new("native-copy-rekey-source").await?;
    let mut peer = Fixture::new("native-copy-rekey-peer").await?;
    source.accept_peer(&peer)?;
    peer.accept_peer(&source)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    let (original, _) =
        sibling_erasure::authored(&source, &mut peer, &conversation, "rekey-original").await?;
    let mut own = source.enroll_sibling("native-copy-rekey", "sibling").await?;
    sibling_erasure::contact(&source, &peer, &mut own, &conversation).await?;
    sibling_erasure::deliver(&source, &mut own, original.clone()).await?;
    assert_eq!(own.client.direct_messages(&conversation)?.len(), 1);
    let source_identity = source.client.owned_device_identity()?;
    let target_identity = own.client.owned_device_identity()?;
    let created_at = crate::time::now_unix_timestamp();
    let db = own.client.account_db()?;
    let scope =
        db.own_sent_receipt_scope(source_identity.storage_key(), target_identity.storage_key())?;
    let claim = db.own_sent_replay_claim(&source_identity, &original.envelope_id)?;
    let receipt_key = format!("{RECEIPTS}rekey-packet");
    db.persist_actor_state(
        &receipt_key,
        &Receipt {
            fingerprint: "packet-fingerprint".into(),
            scope: ReceiptScope::Private { private_scope: scope.clone() },
            valid_until: created_at + 900,
            expires_at: created_at + 1200,
            acknowledged: false,
        },
    )?;
    let packet_key = "own-device/committed-packet/rekey-packet";
    receipts::remember(db, packet_key, "packet-fingerprint", created_at + 900, false, created_at)?;
    let fences = replay_rows(db, "own-device/sent-event/")?;
    let bodies = replay_rows(db, "own-device/sent-event-body/")?;
    assert_eq!(fences.len(), 1, "test: native copy must calibrate a real replay fence");
    let mut last_key = None;
    let mut provider = ramflux_storage::LocalVaultKeyWrappingProvider::new([8; 32]);
    for stage in 0..3 {
        rekey_stage(&mut own, &mut last_key, &mut provider, stage)?;
        sibling_erasure::deliver(&source, &mut own, original.clone()).await?;
        assert_eq!(
            own.client.direct_messages(&conversation)?.len(),
            1,
            "a new genuine enclosing copy after rekey must not project a duplicate",
        );
        let db = own.client.account_db()?;
        assert_eq!(replay_rows(db, "own-device/sent-event/")?, fences);
        assert_eq!(replay_rows(db, "own-device/sent-event-body/")?, bodies);
        assert_receipt_replay(
            db,
            &receipt_key,
            packet_key,
            created_at,
            source_identity.storage_key(),
            target_identity.storage_key(),
        )?;
        assert_eq!(
            db.own_sent_receipt_scope(
                source_identity.storage_key(),
                target_identity.storage_key()
            )?,
            scope,
        );
        assert_eq!(db.own_sent_replay_claim(&source_identity, &original.envelope_id)?, claim);
    }
    let (fresh, _) =
        sibling_erasure::authored(&source, &mut peer, &conversation, "rekey-fresh-original")
            .await?;
    sibling_erasure::deliver(&source, &mut own, fresh).await?;
    assert_eq!(own.client.direct_messages(&conversation)?.len(), 2);
    Ok(())
}

fn rekey_stage(
    own: &mut Fixture,
    last_key: &mut Option<ramflux_storage::AccountDbKey>,
    provider: &mut ramflux_storage::LocalVaultKeyWrappingProvider,
    stage: usize,
) -> TestResult {
    let key = ramflux_storage::AccountDbKey::generate()?;
    let db = own.client.active_account_db.as_mut().ok_or("test: account DB")?;
    let previous = db.wrap_current_db_key(&[8; 32])?;
    match stage {
        0 => db.rekey(&key)?,
        1 => {
            provider.fail_next_wrap();
            assert!(db.rekey_with_wrapping(&key, provider, &previous).is_err());
        }
        _ => {
            db.rekey_with_wrapping(&key, provider, &previous)?;
        }
    }
    if stage != 1 {
        *last_key = Some(key);
    }
    drop(own.client.active_account_db.take());
    let db = ramflux_storage::AccountDb::open(
        own.client.account_index()?,
        "native-copy-rekey",
        last_key.as_ref().ok_or("test: rekey key missing")?,
    )?
    .with_device_signer(own.client.device_branch.as_ref().ok_or("test: signer missing")?.clone());
    own.client.active_account_db = Some(db);
    Ok(())
}

fn replay_rows(
    db: &ramflux_storage::AccountDb,
    prefix: &str,
) -> TestResult<Vec<(String, serde_json::Value)>> {
    let keys = db.actor_state_key_page(prefix, 32)?;
    assert!(keys.len() < 32, "test: replay fixture namespace must remain bounded");
    keys.into_iter()
        .map(|key| {
            let value = db.load_actor_state(&key)?.ok_or("test: replay row missing")?;
            Ok((key, value))
        })
        .collect()
}

fn assert_receipt_replay(
    db: &ramflux_storage::AccountDb,
    receipt_key: &str,
    packet_key: &str,
    created_at: i64,
    source: &str,
    target: &str,
) -> TestResult {
    let retained = db.load_actor_state::<Receipt>(receipt_key)?.ok_or("private receipt")?;
    retained.validate(db, source, target, "packet-fingerprint", created_at)?;
    assert!(
        retained.validate(db, "other-source", target, "packet-fingerprint", created_at).is_err()
    );
    assert!(
        retained.validate(db, source, "other-target", "packet-fingerprint", created_at).is_err()
    );
    assert!(retained.validate(db, source, target, "different-packet", created_at).is_err());
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
