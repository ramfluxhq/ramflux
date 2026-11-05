// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The background bootstrap phases charge once and commit through the shared native verifier.

use super::*;
use crate::bus::{
    connection_manager::{AccountWork, ReceiveEntry},
    contact_backpressure::Backpressure,
    couriers::writer::Writer,
    sync_driver::source::{PreparedSource, prepare},
};
use crate::client::identity_authority::HeadUse;

#[tokio::test]
async fn native_contact_background_bootstrap_decrypts_again_without_an_inline_lookup() -> TestResult
{
    let mut sender = NativeFixture::new("alice").await?;
    let mut target = NativeFixture::new("bob").await?;
    let directory = Directory::from_records(
        &sender.root.0,
        vec![sender.manifest.clone(), target.manifest.clone()],
    )
    .await?;
    let mut state = native_state(&mut sender, &mut target, &directory)?;
    call(&mut state, "alice", "contact.add", json!({"principal_id":target.manifest.principal_id}))
        .await?;
    let envelope = directory.captured.lock().map_err(|_| "capture")?.pop().ok_or("request")?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let receiver = state.accounts.get_mut("bob").ok_or("receiver")?;
    let bucket = format!("bootstrap:{}", sender.manifest.principal_commitment);
    for _ in 0..31 {
        assert!(receiver.client.account_db()?.charge_contact_request(
            &bucket,
            32,
            3600,
            now_unix_timestamp(),
        )?);
    }
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let prepared = prepare_bootstrap(receiver, entry.clone()).await?.ok_or("prelude")?;
    let prepared = (*prepared)?;
    assert!(prepared.candidate.is_some());
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before + 2);
    let db = receiver.client.account_db()?;
    assert!(!db.contact_request_budget_available(&bucket, 32, now_unix_timestamp())?);
    assert_eq!(db.actor_state_keys("dm-pair/session/")?, Vec::<String>::new());
    assert!(db.contact_request(&sender.manifest.principal_commitment, "inbound")?.is_none());
    let mut engine = receiver.session_client().await?;
    let outcome = receiver
        .client
        .apply_routed_prepared_entry(
            &mut engine,
            &super::super::super::review::pool()?,
            &entry,
            Ok(prepared),
        )
        .await?;
    assert!(outcome.plaintext.is_none());
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before + 2);
    let db = receiver.client.account_db()?;
    assert_eq!(
        db.contact_request(&sender.manifest.principal_commitment, "inbound",)?
            .ok_or("request")?
            .state,
        "pending"
    );
    assert!(db.actor_state_exists(
        &receiver.client.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?
    )?);
    assert_eq!(db.actor_state_keys("dm-pair/session/")?.len(), 1);
    receiver.install_test_session(engine);
    Ok(())
}

async fn prepare_bootstrap(
    receiver: &mut LocalBusAccountState,
    entry: GatewayInboxEntry,
) -> Result<PreparedSource, SdkError> {
    let backpressure = Box::new(Backpressure::load(&receiver.client, now_unix_timestamp())?);
    let (sender, mut work) = tokio::sync::mpsc::channel(2);
    let writer = Writer::new(sender, 1);
    let task =
        prepare(&writer, ReceiveEntry { entry, retry_key: None, replay: false }, backpressure);
    tokio::pin!(task);
    loop {
        tokio::select! {
            result=&mut task => return result.map(|(_, _, source)| source),
            checkpoint=work.recv()=> match checkpoint {
                Some(AccountWork::Courier(checkpoint)) if checkpoint.generation == 1 => {
                    checkpoint.apply(receiver);
                }
                _ => return Err(SdkError::GatewaySessionNotEstablished),
            }
        }
    }
}
