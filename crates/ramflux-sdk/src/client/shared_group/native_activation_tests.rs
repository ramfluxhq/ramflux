// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]
//! Group convergence and key continuity through generated snapshots and native pair delivery.
use crate::client::native_test_support::{Fixture, TestResult, directory::Directory};
use ramflux_protocol::{GroupStateChange, SharedGroupRole, message as g};

const GROUP: &str = "activation-convergence-group";
const THREAD: &str = "activation-convergence-thread";

fn change(
    source: &Fixture,
    change: GroupStateChange,
) -> TestResult<ramflux_crypto::VerifiedGroupState> {
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("test: native owner")?
        .group_primary(source.vault.as_ref())?;
    Ok(source.client.shared_group_change_with_primary(
        GROUP,
        &source.config.target_delivery_id,
        change,
        Some(&primary),
    )?)
}

async fn pair() -> TestResult<(Fixture, Fixture, ramflux_crypto::VerifiedGroupState)> {
    let source = Fixture::with_device("group-convergence-owner", "phone").await?;
    let target = Fixture::with_device("group-convergence-peer", "phone").await?;
    source.accept_peer(&target)?;
    target.accept_peer(&source)?;
    {
        // The lease holds the account's primary-signing file lock; release it before `change`
        // takes its own, or the second request waits out the lock deadline and fails Busy.
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("test: native owner")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            GROUP,
            THREAD,
            Some("Checklist".into()),
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
    }
    let state = change(
        &source,
        GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    Ok((source, target, state))
}

async fn snapshot(
    source: &Fixture,
    target: &mut Fixture,
    state: &ramflux_crypto::VerifiedGroupState,
    sequence: u64,
) -> TestResult<ramflux_protocol::Envelope> {
    target.client.accept_shared_group_state(state, &target.config.target_delivery_id)?;
    let directory = Directory::new(vec![source.manifest.clone(), target.manifest.clone()]).await?;
    directory.configure(target);
    let exact = source
        .client
        .shared_group_packet_for_recipient(state, &target.client.owned_device_identity()?)?;
    let envelope = source.seal_inner_to(target, &exact)?;
    target.receive(envelope.clone(), sequence).await?;
    Ok(envelope)
}

fn group_message(source: &Fixture, text: &str) -> TestResult<(String, Vec<u8>)> {
    let identity = source.client.allocate_generated_identity(
        THREAD,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = source.client.encrypt_generated_group_inner(
        GROUP,
        &source.config.device_id,
        identity,
        &g::Message { text: text.into(), ..Default::default() },
    )?;
    Ok((id, exact))
}

async fn deliver(
    source: &Fixture,
    target: &mut Fixture,
    id: &str,
    exact: &[u8],
    text: &str,
    sequence: u64,
) -> TestResult {
    target.receive(source.seal_inner_to(target, exact)?, sequence).await?;
    assert_eq!(
        target.client.generated_message_detail(THREAD, id)?.message.text.as_deref(),
        Some(text),
        "the native group receiver lost the generated Message"
    );
    Ok(())
}

pub(super) async fn bootstrap_continuity() -> TestResult {
    let (source, mut target, state) = Box::pin(pair()).await?;
    let original = Box::pin(snapshot(&source, &mut target, &state, 1)).await?;
    let (id, exact) = group_message(&source, "first without separate key distribution")?;
    Box::pin(deliver(
        &source,
        &mut target,
        &id,
        &exact,
        "first without separate key distribution",
        2,
    ))
    .await?;
    let key = target.client.load_group_sender_key_state(
        GROUP,
        &source.client.owned_device_identity()?,
        state.view().epoch,
        "recv",
    )?;
    let before = serde_json::to_value(key)?;
    target.receive(original.clone(), 1).await?;
    assert_eq!(
        serde_json::to_value(target.client.load_group_sender_key_state(
            GROUP,
            &source.client.owned_device_identity()?,
            state.view().epoch,
            "recv"
        )?)?,
        before,
        "replaying the generated snapshot reset the receive key counter"
    );
    let mut corrupt = original;
    corrupt.encrypted_payload = ramflux_protocol::encode_base64url(b"corrupted snapshot");
    assert!(target.receive(corrupt, 3).await.is_err(), "a forged bootstrap was admitted");
    assert_eq!(
        serde_json::to_value(target.client.load_group_sender_key_state(
            GROUP,
            &source.client.owned_device_identity()?,
            state.view().epoch,
            "recv"
        )?)?,
        before,
        "refused bootstrap mutated the committed group receiver"
    );
    let (id, exact) = group_message(&source, "second after bootstrap replay")?;
    Box::pin(deliver(&source, &mut target, &id, &exact, "second after bootstrap replay", 4))
        .await?;
    let removed = change(
        &source,
        GroupStateChange::Remove {
            root_commitment: target.client.own_account_anchor()?,
            device_id: target.config.device_id.clone(),
        },
    )?;
    target.client.accept_shared_group_state(&removed, &target.config.target_delivery_id)?;
    assert!(
        target
            .client
            .import_group_sender_key_distribution(
                &source
                    .client
                    .export_group_sender_key_distribution(GROUP, &source.config.device_id)?
            )
            .is_err(),
        "a removed member could import the new epoch's sender key"
    );
    Ok(())
}

pub(super) async fn three_devices() -> TestResult {
    let (mut source, mut peer, _) = Box::pin(pair()).await?;
    let mut sibling = source.enroll_sibling("group-convergence-sibling", "laptop").await?;
    peer.client.persist_fetched_identity_directory(&source.manifest)?;
    sibling.client.persist_fetched_identity_directory(&peer.manifest)?;
    sibling.accept_peer(&peer)?;
    let state = change(
        &source,
        GroupStateChange::Add {
            member: sibling.client.owned_group_actor(&sibling.config.target_delivery_id)?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    Box::pin(snapshot(&source, &mut peer, &state, 1)).await?;
    Box::pin(snapshot(&source, &mut sibling, &state, 1)).await?;
    let expected = source
        .client
        .account_db()?
        .shared_group_state(GROUP)?
        .ok_or("test: signed group state")?
        .view()
        .clone();
    assert_eq!(expected.members.len(), 3, "the signed state lost an explicit device member");
    assert_eq!(
        peer.client
            .account_db()?
            .shared_group_state(GROUP)?
            .ok_or("test: peer signed group state")?
            .view(),
        &expected,
        "peer did not converge"
    );
    assert_eq!(
        sibling
            .client
            .account_db()?
            .shared_group_state(GROUP)?
            .ok_or("test: sibling signed group state")?
            .view(),
        &expected,
        "sibling did not converge"
    );
    // Each certified sender starts a separate chain, including two literal phone devices.
    for sender in [&source, &peer, &sibling] {
        let distribution =
            sender.client.export_group_sender_key_distribution(GROUP, &sender.config.device_id)?;
        for receiver in [&source, &peer, &sibling] {
            if receiver.client.owned_device_identity()? != sender.client.owned_device_identity()? {
                receiver.client.import_group_key_for_identity(
                    &distribution,
                    &sender.client.owned_device_identity()?,
                )?;
            }
        }
    }
    let (id, exact) = group_message(&source, "from owner")?;
    Box::pin(deliver(&source, &mut peer, &id, &exact, "from owner", 2)).await?;
    Box::pin(deliver(&source, &mut sibling, &id, &exact, "from owner", 2)).await?;
    let (id, exact) = group_message(&peer, "from peer")?;
    Box::pin(deliver(&peer, &mut source, &id, &exact, "from peer", 3)).await?;
    Box::pin(deliver(&peer, &mut sibling, &id, &exact, "from peer", 3)).await?;
    let (id, exact) = group_message(&sibling, "from sibling")?;
    Box::pin(deliver(&sibling, &mut source, &id, &exact, "from sibling", 4)).await?;
    Box::pin(deliver(&sibling, &mut peer, &id, &exact, "from sibling", 4)).await?;
    let renamed = change(&source, GroupStateChange::SetName { name: "Reviewed".into() })?;
    for receiver in [&peer, &sibling] {
        receiver.client.accept_shared_group_state(&renamed, &receiver.config.target_delivery_id)?;
        assert_eq!(
            receiver
                .client
                .account_db()?
                .client_record("conversation", THREAD)?
                .ok_or("test: group conversation")?["title"],
            "Reviewed",
            "signed group title lost"
        );
    }
    let removed = change(
        &source,
        GroupStateChange::Remove {
            root_commitment: peer.client.own_account_anchor()?,
            device_id: peer.config.device_id.clone(),
        },
    )?;
    peer.client.accept_shared_group_state(&removed, &peer.config.target_delivery_id)?;
    assert!(
        group_message(&peer, "forbidden after removal").is_err(),
        "a removed native group sender could still encrypt"
    );
    Ok(())
}

async fn deliver_key(
    source: &Fixture,
    target: &mut Fixture,
    epoch: u64,
    sequence: u64,
) -> TestResult {
    let distribution = ramflux_protocol::parse_i_json(
        &source.client.export_group_sender_key_distribution(GROUP, &source.config.device_id)?,
    )?;
    let exact = source.client.generated_group_key_inner(
        THREAD,
        epoch,
        &distribution,
        &target.client.owned_device_identity()?,
    )?;
    target.receive(source.seal_inner_to(target, &exact)?, sequence).await?;
    Ok(())
}

pub(super) async fn implicit_sibling_history() -> TestResult {
    let (mut source, mut peer, state) = Box::pin(pair()).await?;
    Box::pin(snapshot(&source, &mut peer, &state, 1)).await?;
    let state = change(&source, GroupStateChange::SetName { name: "Signed title".into() })?;
    peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?;
    let (original, _) = group_message(&source, "history before sibling enrollment")?;
    let mut sibling = source.enroll_sibling("group-implicit-sibling", "laptop").await?;
    peer.client.persist_fetched_identity_directory(&source.manifest)?;
    sibling.client.persist_fetched_identity_directory(&peer.manifest)?;
    sibling.client.accept_shared_group_state(&state, &sibling.config.target_delivery_id)?;
    let plan =
        source.client.prepare_authored_history(&source.config)?.ok_or("test: group history")?;
    let (plan, envelope) = source
        .client
        .seal_authored_history(&source.config, plan, source.material_for(&sibling)?)?
        .ok_or("test: sealed group history")?;
    sibling.receive(envelope, 1).await?;
    source.client.complete_authored_history(&plan)?;
    assert_eq!(
        sibling.client.generated_message_detail(THREAD, &original)?.message.text.as_deref(),
        Some("history before sibling enrollment"),
        "the native history courier lost the original Message"
    );
    assert_eq!(
        sibling
            .client
            .account_db()?
            .client_record("conversation", THREAD)?
            .ok_or("test: restored group conversation")?["title"],
        "Signed title",
        "own history replaced the independently signed group title"
    );
    assert_eq!(
        sibling
            .client
            .account_db()?
            .shared_group_state(GROUP)?
            .ok_or("test: group state")?
            .view()
            .epoch,
        state.view().epoch,
        "implicit enrollment must not fabricate a group join"
    );
    Box::pin(deliver_key(&sibling, &mut peer, state.view().epoch, 2)).await?;
    let (id, exact) = group_message(&sibling, "implicit sibling first message")?;
    Box::pin(deliver(&sibling, &mut peer, &id, &exact, "implicit sibling first message", 3))
        .await?;
    Box::pin(deliver_key(&source, &mut peer, state.view().epoch, 4)).await?;
    let (id, exact) = group_message(&source, "same phone label across independent roots")?;
    Box::pin(deliver(
        &source,
        &mut peer,
        &id,
        &exact,
        "same phone label across independent roots",
        5,
    ))
    .await?;
    Ok(())
}

pub(super) async fn fork_ciphertext() -> TestResult {
    use prost::Message as _;
    let (mut left, mut receiver_left, base) = Box::pin(pair()).await?;
    let right = left.enroll_sibling("group-fork-author", "fork-author").await?;
    let receiver_right =
        receiver_left.enroll_sibling("group-fork-receiver", "fork-receiver").await?;
    for client in [&left, &right, &receiver_left, &receiver_right] {
        client.client.persist_fetched_identity_directory(&left.manifest)?;
        client.client.persist_fetched_identity_directory(&receiver_left.manifest)?;
    }
    right.client.accept_shared_group_state(&base, &right.config.target_delivery_id)?;
    let first = change(&left, GroupStateChange::SetName { name: "left".into() })?;
    let primary = left
        .client
        .born_v3_account
        .as_ref()
        .ok_or("test: native fork authority")?
        .group_primary(left.vault.as_ref())?;
    let second = right.client.shared_group_change_with_primary(
        GROUP,
        &right.config.target_delivery_id,
        GroupStateChange::SetName { name: "right".into() },
        Some(&primary),
    )?;
    assert_eq!(first.view().epoch, second.view().epoch, "the fork must share its signed epoch");
    assert_ne!(
        first.snapshot().state_hash,
        second.snapshot().state_hash,
        "the independently signed content heads must differ"
    );
    receiver_left
        .client
        .accept_shared_group_state(&first, &receiver_left.config.target_delivery_id)?;
    receiver_right
        .client
        .accept_shared_group_state(&second, &receiver_right.config.target_delivery_id)?;
    let distribution =
        left.client.export_group_sender_key_distribution(GROUP, &left.config.device_id)?;
    refuse_unknown_head(&left, &receiver_left, &distribution)?;
    receiver_left
        .client
        .import_group_key_for_identity(&distribution, &left.client.owned_device_identity()?)?;
    let mut reused: crate::SdkGroupSenderKeyDistribution =
        ramflux_protocol::parse_i_json(&distribution)?;
    reused.group_state_hash = Some(second.snapshot().state_hash.clone());
    left.client.sign_group_distribution(&mut reused)?;
    receiver_right.client.import_group_key_for_identity(
        &serde_json::to_vec(&reused)?,
        &left.client.owned_device_identity()?,
    )?;
    let source = left.client.owned_device_identity()?;
    let (id, exact) = group_message(&left, "first branch message")?;
    let inner = g::Inner::decode(exact.as_slice())?;
    let message = g::Message::decode(inner.body.as_slice())?;
    let mut sealed = crate::client::generated_group::to_native(
        message.sealed_group.as_ref().ok_or("test: sealed generated group")?,
    )?;
    let opened = receiver_left.client.decrypt_group_envelope_for_identity(&sealed, &id, &source)?;
    assert_eq!(
        g::Message::decode(opened.as_slice())?.text,
        "first branch message",
        "the original signed head must calibrate decryption"
    );
    let before = serde_json::to_value(receiver_right.client.load_group_sender_key_state(
        GROUP,
        &source,
        second.view().epoch,
        "recv",
    )?)?;
    sealed.group_state_hash = Some(second.snapshot().state_hash.clone());
    assert!(
        matches!(
            receiver_right.client.decrypt_group_envelope_for_identity(&sealed, "retagged", &source),
            Err(crate::SdkError::Crypto(ramflux_crypto::CryptoError::AeadFailed))
        ),
        "reusing the identical sender secret under a different head bypassed its AEAD binding"
    );
    sealed.group_state_hash = None;
    assert!(
        receiver_right
            .client
            .decrypt_group_envelope_for_identity(&sealed, "headless", &source)
            .is_err(),
        "a missing group head reached a legacy decryption fallback"
    );
    assert_eq!(
        serde_json::to_value(receiver_right.client.load_group_sender_key_state(
            GROUP,
            &source,
            second.view().epoch,
            "recv"
        )?)?,
        before,
        "refused fork ciphertext advanced the receiver chain"
    );
    Ok(())
}

fn refuse_unknown_head(source: &Fixture, target: &Fixture, distribution: &[u8]) -> TestResult {
    let mut unknown: crate::SdkGroupSenderKeyDistribution =
        ramflux_protocol::parse_i_json(distribution)?;
    let unknown_head = ramflux_protocol::encode_base64url([99; 32]);
    unknown.group_state_hash = Some(unknown_head.clone());
    source.client.sign_group_distribution(&mut unknown)?;
    assert!(
        matches!(target.client.import_group_key_for_identity(
        &serde_json::to_vec(&unknown)?, &source.client.owned_device_identity()?), Err(crate::SdkError::InboundPending(reason))
        if reason == "shared group state head is not verified locally"),
        "a signed key for an unverified group head was installed"
    );
    let checkpoint = crate::group::group_key_checkpoint(
        GROUP,
        &source.client.owned_device_identity()?,
        unknown.group_key_epoch,
        "recv",
        Some(&unknown_head),
    )?;
    assert!(
        target.client.projection_checkpoint(&checkpoint)?.is_none(),
        "refusing an unknown group head created a receiver checkpoint"
    );
    Ok(())
}
