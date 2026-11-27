// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Automatic restore/upgrade recovery regressions.
use super::r5::fresh;
use super::review::pool;
use super::session_record::{Wire, active, last};
use super::*;
pub(super) fn manifest(f: &Fixture) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    f.manifest()
}
#[tokio::test]
async fn restored_device_with_empty_allocator_bootstraps_without_manual_recovery()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for n in 0..6 {
        let entry = fresh(&alice, &bob, &format!("before-restore-{n}"))?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry).await?;
    }
    let key = super::super::bootstrap_sequence::bootstrap_sequence_key(
        &alice.client.owned_device_identity()?,
    );
    alice.client.account_db()?.remove_actor_state(&key)?;
    alice.reopen_native().await?;
    let entry = fresh(&alice, &bob, "first-after-restore")?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry).await?;
    assert_eq!(active(&bob, "alice")?, decode(&entry.envelope)?.ciphertext.session_id);
    Ok(())
}
#[tokio::test]
async fn a_clock_behind_restore_recovers_through_an_authenticated_rate_limited_reset()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let now = u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| invalid("time"))?.as_millis(),
    )
    .map_err(|_| invalid("time"))?;
    alice.client.account_db()?.persist_actor_state(
        &super::super::bootstrap_sequence::bootstrap_sequence_key(
            &alice.client.owned_device_identity()?,
        ),
        &(now + 300_000),
    )?;
    let entry = fresh(&alice, &bob, "old-future-clock")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &entry).await?;
    alice.client.account_db()?.remove_actor_state(
        &super::super::bootstrap_sequence::bootstrap_sequence_key(
            &alice.client.owned_device_identity()?,
        ),
    )?;
    alice.reopen_native().await?;
    let mut restored = alice;
    restored.client.establish_friend_link(
        "friend",
        &restored.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let entry = fresh(&restored, &bob, "clock-behind-restore")?;
    let (mut be, bsent) = Wire::engine(&bob, &restored)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &entry).await.is_err());
    let reset = last(&bsent)?;
    let (mut ae, asent) = Wire::engine(&restored, &bob)?;
    restored.client.apply_routed_entry(&mut ae, &pool()?, &reset).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&asent)?).await?;
    assert_eq!(active(&restored, "bob")?, active(&bob, "alice")?);
    let good = super::r5::seal(
        &restored,
        &bob,
        super::r5::native_outgoing(&restored, &bob, "recovered")?,
        b"recovered",
    )?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &good).await?;
    let count = bsent.lock().map_err(|_| invalid("mutex"))?.len();
    for _ in 0..5 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &entry).await.is_err());
    }
    assert_eq!(bsent.lock().map_err(|_| invalid("mutex"))?.len(), count);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn replay_watermarks_cannot_be_poisoned_by_another_principal_reusing_a_device_id()
-> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let bob = Fixture::native("bob", 61).await?;
    let entry = fresh(&alice, &bob, "scoped-watermark")?;
    let pair = RamfluxClient::pair_key(
        &bob.client.owned_device_identity()?,
        &alice.client.owned_device_identity()?,
    )?;
    bob.client
        .account_db()?
        .persist_actor_state(&format!("{pair}/bootstrap-high-water"), &9_007_199_254_740_991_u64)?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    assert_eq!(
        RamfluxClient::decode_generated_inner(&opened.body)?.0.conversation_id,
        super::r5::native_outgoing(&alice, &bob, "scope")?.conversation_id
    );
    Ok(())
}
