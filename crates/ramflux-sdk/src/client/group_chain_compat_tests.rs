// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender chains keep pre-rebase wire compatibility and authenticated restore rekeys.
use super::*;
use crate::client::identity_authority::test_support::public_manifest;

fn client(path: &std::path::Path, name: &str, seed: u8) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(name, [seed; 32]);
    client.create_device_branch(name, name, 1, [seed + 1; 32]);
    client.open_account_index(path)?;
    let root = client.owned_device_identity()?.root_commitment().to_owned();
    client.create_account("acct", &root)?;
    client.unlock_account("acct", b"group-chain-test")?;
    Ok(client)
}
fn shared_pair(root: &std::path::Path) -> Result<(RamfluxClient, RamfluxClient), SdkError> {
    let a = client(&root.join("a"), "owner", 11)?;
    let b = client(&root.join("b"), "peer", 21)?;
    for manifest in [public_manifest(&a)?, public_manifest(&b)?] {
        a.persist_identity_directory(&manifest)?;
        b.persist_identity_directory(&manifest)?;
    }
    a.shared_group_create("group", "thread", Some("Chains".into()), "target-owner")?;
    let state = a.shared_group_change(
        "group",
        "target-owner",
        ramflux_protocol::GroupStateChange::Add {
            member: b.owned_group_actor("target-peer")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    b.accept_shared_group_state(&state, "target-peer")?;
    Ok((a, b))
}
#[test]
fn shared_restore_rekey_keeps_old_ciphertexts_and_replay_cannot_rewind_the_chain()
-> Result<(), SdkError> {
    let root = tempfile::tempdir()?;
    let (a, b) = shared_pair(root.path())?;
    let old = a.export_group_sender_key_distribution("group", "owner")?;
    b.import_group_sender_key_distribution(&old)?;
    let old_message = a.encrypt_group_message("group", "owner", b"before restore")?;
    let source = a.owned_device_identity()?;
    let mut state = a.load_group_sender_key_state("group", &source, 2, "send")?;
    let seed = [99; 32];
    state.session_snapshot = ramflux_crypto::DmSession::initiator(
        seed,
        group_sender_device_hash("group", "owner", "local"),
        group_sender_device_hash("group", "owner", "remote"),
        fresh_group_transcript("group", "owner", 2, &seed)?,
    )?
    .snapshot();
    a.persist_group_sender_key_state(&state, &source, "send", "restored")?;
    let fresh = a.export_group_sender_key_distribution("group", "owner")?;
    let mut tampered: SdkGroupSenderKeyDistribution = serde_json::from_slice(&fresh)?;
    assert_eq!(tampered.version, 4);
    tampered.sender_key_seed = [100; 32];
    assert!(b.import_group_sender_key_distribution(&serde_json::to_vec(&tampered)?).is_err());
    b.import_group_sender_key_distribution(&fresh)?;
    let first = a.encrypt_group_message("group", "owner", b"after restore")?;
    b.send_direct_message("thread", "new-first", "owner", &first)?;
    assert_eq!(b.decrypt_group_message("thread", "new-first")?, b"after restore");
    b.import_group_sender_key_distribution(&fresh)?;
    b.import_group_sender_key_distribution(&old)?;
    let second = a.encrypt_group_message("group", "owner", b"next counter")?;
    b.send_direct_message("thread", "new-second", "owner", &second)?;
    assert_eq!(b.decrypt_group_message("thread", "new-second")?, b"next counter");
    b.send_direct_message("thread", "old", "owner", &old_message)?;
    assert_eq!(b.decrypt_group_message("thread", "old")?, b"before restore");
    let after = b.load_group_sender_key_state("group", &source, 2, "recv")?;
    assert_eq!(
        after.session_snapshot.session_id(),
        state.session_snapshot.session_id(),
        "reading an archive must not replace the active restored chain"
    );
    Ok(())
}
#[test]
fn pre_rebase_shared_v3_distributions_keep_the_legacy_transcript() -> Result<(), SdkError> {
    let root = tempfile::tempdir()?;
    let (a, b) = shared_pair(root.path())?;
    let source = a.owned_device_identity()?;
    let mut state = a.ensure_own_group_sender_key("group", &source, 2)?;
    state.chain_version = 3;
    state.session_snapshot = ramflux_crypto::DmSession::initiator(
        [77; 32],
        group_sender_device_hash("group", "owner", "local"),
        group_sender_device_hash("group", "owner", "remote"),
        group_sender_transcript_hash("group", "owner", 2),
    )?
    .snapshot();
    a.persist_group_sender_key_state(&state, &source, "send", "pre-rebase-v3")?;
    let bytes = a.export_group_sender_key_distribution("group", "owner")?;
    let dist: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
    assert_eq!(dist.version, 3);
    assert!(dist.sender_key_signature.is_none());
    b.import_group_sender_key_distribution(&bytes)?;
    let message = a.encrypt_group_message("group", "owner", b"legacy shared v3")?;
    b.send_direct_message("thread", "legacy", "owner", &message)?;
    assert_eq!(b.decrypt_group_message("thread", "legacy")?, b"legacy shared v3");
    Ok(())
}
