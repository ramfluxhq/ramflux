// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native sender-chain restore preserves old ciphertext without accepting retired distributions.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use prost::Message as _;
use ramflux_protocol::message as g;

async fn shared_pair() -> TestResult<(Fixture, Fixture)> {
    let a = Box::pin(Fixture::with_principal("chain-owner", "owner", "owner")).await?;
    let b = Box::pin(Fixture::with_principal("chain-peer", "peer", "peer")).await?;
    for manifest in [&a.manifest, &b.manifest] {
        a.client.persist_observed_identity_directory_now(manifest)?;
        b.client.persist_observed_identity_directory_now(manifest)?;
    }
    let primary = a
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native account")?
        .group_primary(a.vault.as_ref())?;
    a.client.shared_group_create_with_primary(
        "group",
        "thread",
        Some("Chains".into()),
        &a.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = a.client.shared_group_change_with_primary(
        "group",
        &a.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: b.client.owned_group_actor(&b.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    b.client.accept_shared_group_state(&state, &b.config.target_delivery_id)?;
    Ok((a, b))
}

fn seal(source: &RamfluxClient, text: &str) -> Result<g::Message, SdkError> {
    source.encrypt_generated_group_message(
        "group",
        "owner",
        &g::Message {
            text: text.into(),
            erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
            ..Default::default()
        },
    )
}

fn open(
    target: &RamfluxClient,
    source: &RamfluxClient,
    id: &str,
    message: &g::Message,
) -> TestResult<String> {
    let sealed = message.sealed_group.as_ref().ok_or("generated group wrapper")?;
    let native = crate::client::generated_group::to_native(sealed)?;
    let plaintext = target.decrypt_group_envelope_for_identity(
        &native,
        id,
        &source.owned_device_identity()?,
    )?;
    Ok(g::Message::decode(plaintext.as_slice())?.text)
}

#[tokio::test(flavor = "current_thread")]
async fn shared_restore_rekey_keeps_old_ciphertexts_and_replay_cannot_rewind_the_chain()
-> TestResult {
    crate::client::native_test_support::watchdog::within(restore_rekey()).await?
}

async fn restore_rekey() -> TestResult {
    let (a, b) = Box::pin(shared_pair()).await?;
    let a = &a.client;
    let b = &b.client;
    let epoch = a.group_state("group")?.group_epoch;
    let old = a.export_group_sender_key_distribution("group", "owner")?;
    b.import_group_sender_key_distribution(&old)?;
    let old_message = seal(a, "before restore")?;
    let source = a.owned_device_identity()?;
    let mut state = a.load_group_sender_key_state("group", &source, epoch, "send")?;
    let seed = ramflux_crypto::random_32()?;
    state.session_snapshot = ramflux_crypto::DmSession::initiator(
        seed,
        group_sender_device_hash("group", "owner", "local"),
        group_sender_device_hash("group", "owner", "remote"),
        fresh_group_transcript("group", "owner", epoch, &seed)?,
    )?
    .snapshot();
    a.persist_group_sender_key_state(&state, &source, "send", "restored")?;
    let fresh = a.export_group_sender_key_distribution("group", "owner")?;
    let mut tampered: SdkGroupSenderKeyDistribution = serde_json::from_slice(&fresh)?;
    assert_eq!(tampered.version, 4, "native restore requires the signed chain-v4 transcript");
    tampered.sender_key_seed = ramflux_crypto::random_32()?;
    assert!(
        b.import_group_sender_key_distribution(&serde_json::to_vec(&tampered)?).is_err(),
        "a changed seed cannot reuse a native signed distribution"
    );
    b.import_group_sender_key_distribution(&fresh)?;
    let first = seal(a, "after restore")?;
    assert_eq!(
        open(b, a, "new-first", &first)?,
        "after restore",
        "the receiver must accept the restored native chain"
    );
    b.import_group_sender_key_distribution(&fresh)?;
    b.import_group_sender_key_distribution(&old)?;
    let second = seal(a, "next counter")?;
    assert_eq!(
        open(b, a, "new-second", &second)?,
        "next counter",
        "distribution replay must not rewind the active native chain"
    );
    assert_eq!(
        open(b, a, "old", &old_message)?,
        "before restore",
        "the independently retained old native chain must remain decryptable"
    );
    let after = b.load_group_sender_key_state("group", &source, epoch, "recv")?;
    assert_eq!(
        after.session_snapshot.session_id(),
        state.session_snapshot.session_id(),
        "reading an archive must preserve the active restored chain"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retired_shared_v3_distribution_is_refused_without_replacing_native_chain() -> TestResult {
    crate::client::native_test_support::watchdog::within(refuse_retired_distribution()).await?
}

async fn refuse_retired_distribution() -> TestResult {
    let (a, b) = Box::pin(shared_pair()).await?;
    let source = a.client.owned_device_identity()?;
    let epoch = a.client.group_state("group")?.group_epoch;
    let bytes = a.client.export_group_sender_key_distribution("group", "owner")?;
    b.client.import_group_sender_key_distribution(&bytes)?;
    let before = serde_json::to_vec(
        &b.client.load_group_sender_key_state("group", &source, epoch, "recv")?,
    )?;
    let mut retired: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
    retired.version = 3;
    retired.sender_key_signature = None;
    assert!(
        b.client.import_group_sender_key_distribution(&serde_json::to_vec(&retired)?).is_err(),
        "retired chain-v3 input must not select an unsigned compatibility transcript"
    );
    let after = serde_json::to_vec(
        &b.client.load_group_sender_key_state("group", &source, epoch, "recv")?,
    )?;
    assert_eq!(
        after, before,
        "retired distribution refusal must leave native receive key and ratchet bytes unchanged"
    );
    assert_eq!(
        open(&b.client, &a.client, "after-refusal", &seal(&a.client, "current native traffic")?)?,
        "current native traffic",
        "a retired distribution must not poison the current chain"
    );
    Ok(())
}
