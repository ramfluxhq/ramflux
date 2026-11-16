// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group authorization adversaries over generated wrappers and authenticated native pairs.
use crate::client::native_test_support::{Fixture, TestResult, directory::Directory, watchdog};
use prost::Message as _;
use ramflux_protocol::{GroupStateChange, SharedGroupRole, message as g};

const GROUP: &str = "group-auth-native";
const THREAD: &str = "group-auth-thread";

fn change(
    source: &Fixture,
    change: GroupStateChange,
) -> TestResult<ramflux_crypto::VerifiedGroupState> {
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native owner")?
        .group_primary(source.vault.as_ref())?;
    Ok(source.client.shared_group_change_with_primary(
        GROUP,
        &source.config.target_delivery_id,
        change,
        Some(&primary),
    )?)
}

async fn setup(member: bool) -> TestResult<(Fixture, Fixture, Fixture)> {
    Box::pin(setup_with_bootstrap(member, true)).await
}

async fn setup_with_bootstrap(
    member: bool,
    bootstrap: bool,
) -> TestResult<(Fixture, Fixture, Fixture)> {
    let source = Fixture::with_device("group-auth-source", "phone").await?;
    let mut target = Fixture::with_device("group-auth-target", "phone").await?;
    let outsider = Fixture::with_device("group-auth-outsider", "phone").await?;
    source.accept_peer(&target)?;
    target.accept_peer(&source)?;
    outsider.accept_peer(&target)?;
    target.accept_peer(&outsider)?;
    {
        // The primary signing lease is exclusive; release it before `change` takes its own.
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native owner")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            GROUP,
            THREAD,
            None,
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
    }
    let mut state = change(
        &source,
        GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    if member {
        state = change(
            &source,
            GroupStateChange::Add {
                member: outsider
                    .client
                    .owned_group_actor(&outsider.config.target_delivery_id)?
                    .identity,
                role: SharedGroupRole::Member,
            },
        )?;
        outsider.client.accept_shared_group_state(&state, &outsider.config.target_delivery_id)?;
    }
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    if bootstrap {
        let directory = Directory::new(vec![
            source.manifest.clone(),
            target.manifest.clone(),
            outsider.manifest.clone(),
        ])
        .await?;
        directory.configure(&mut target);
        let snapshot = source
            .client
            .shared_group_packet_for_recipient(&state, &target.client.owned_device_identity()?)?;
        target.receive(source.seal_inner_to(&target, &snapshot)?, 1).await?;
    }
    Ok((source, target, outsider))
}

fn message(source: &Fixture) -> TestResult<(String, Vec<u8>)> {
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
        &g::Message { text: "authenticated group text".into(), ..Default::default() },
    )?;
    Ok((id, exact))
}

fn reauthor(source: &Fixture, exact: &[u8]) -> TestResult<Vec<u8>> {
    let mut inner = g::Inner::decode(exact)?;
    let old = inner.identity.as_ref().ok_or("original identity")?;
    let mut identity = source.client.allocate_generated_identity(
        THREAD,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    identity.group_id = old.group_id.clone();
    identity.group_epoch = old.group_epoch;
    inner.identity = Some(identity);
    let bytes = inner.encode_to_vec();
    assert!(
        g::validation::scan_inner(&bytes).is_ok(),
        "the adversary must retain a structurally valid generated Inner"
    );
    Ok(bytes)
}

async fn adversary(member: bool, repeat: bool) -> TestResult {
    let (source, mut target, outsider) = Box::pin(setup(member)).await?;
    let (id, exact) = message(&source)?;
    // The pair and EventIdentity really belong to the outsider; the sealed group
    // payload is borrowed from a different certified sender with the same device label.
    let forged = outsider.seal_inner_to(&target, &exact)?;
    assert_group_author_refusal(
        target.receive(forged.clone(), 2).await.err().ok_or("foreign author admitted")?,
    )?;
    if repeat {
        assert_group_author_refusal(
            target.receive(forged, 2).await.err().ok_or("retry admitted a refused author")?,
        )?;
    }
    assert!(target.client.generated_message_detail(THREAD, &id).is_err());
    target.receive(source.seal_inner_to(&target, &exact)?, 3).await?;
    assert_eq!(
        target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
        Some("authenticated group text")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_nonmembers_cannot_speak_as_a_pinned_member() -> TestResult {
    watchdog::within(adversary(false, false)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn legacy_group_current_members_cannot_claim_another_members_sender_id() -> TestResult {
    watchdog::within(adversary(true, false)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn gateway_legacy_group_nonmembers_cannot_speak_as_a_pinned_member() -> TestResult {
    watchdog::within(adversary(false, true)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn previously_parked_group_messages_cannot_claim_another_members_sender_id() -> TestResult {
    // Generation 1 replays the exact committed envelope through the same executor;
    // it never reinterprets the retired private JSON pending-body table.
    watchdog::within(adversary(true, true)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn legacy_group_matching_pinned_member_remains_readable() -> TestResult {
    watchdog::within(async {
        let (source, mut target, _) = Box::pin(setup(false)).await?;
        let (id, exact) = message(&source)?;
        target.receive(source.seal_inner_to(&target, &exact)?, 2).await?;
        assert_eq!(
            target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
            Some("authenticated group text")
        );
        Ok(())
    })
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn legacy_group_messages_require_an_authentic_outer_signature() -> TestResult {
    watchdog::within(async {
        let (source, mut target, _) = Box::pin(setup(false)).await?;
        let (id, exact) = message(&source)?;
        let valid = source.seal_inner_to(&target, &exact)?;
        let mut forged = valid.clone();
        forged.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
        assert!(target.receive(forged, 2).await.is_err(), "invalid outer signature admitted");
        assert!(target.client.generated_message_detail(THREAD, &id).is_err());
        target.receive(valid, 2).await?;
        assert_eq!(
            target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
            Some("authenticated group text")
        );
        Ok(())
    })
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn legacy_group_removed_members_cannot_reuse_old_epoch_keys() -> TestResult {
    watchdog::within(async {
        let (source, mut target, outsider) = Box::pin(setup(true)).await?;
        let state = source.client.account_db()?.shared_group_state(GROUP)?.ok_or("group state")?;
        let distribution = ramflux_protocol::parse_i_json(
            &outsider
                .client
                .export_group_sender_key_distribution(GROUP, &outsider.config.device_id)?,
        )?;
        let key = outsider.client.generated_group_key_inner(
            THREAD,
            state.view().epoch,
            &distribution,
            &target.client.owned_device_identity()?,
        )?;
        target.receive(outsider.seal_inner_to(&target, &key)?, 2).await?;
        let (id, exact) = message(&outsider)?;
        let valid = outsider.seal_inner_to(&target, &exact)?;
        let removed = change(
            &source,
            GroupStateChange::Remove {
                root_commitment: outsider.client.own_account_anchor()?,
                device_id: outsider.config.device_id.clone(),
            },
        )?;
        assert!(removed.view().epoch > state.view().epoch);
        target.client.accept_shared_group_state(&removed, &target.config.target_delivery_id)?;
        assert!(target.receive(valid, 2).await.is_err(), "removed author reused an old key");
        assert!(target.client.generated_message_detail(THREAD, &id).is_err());
        Ok(())
    })
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn legacy_group_distribution_sender_is_bound_to_the_authenticated_device() -> TestResult {
    watchdog::within(async {
        let (source, mut target, outsider) = Box::pin(setup(true)).await?;
        let state = source.client.account_db()?.shared_group_state(GROUP)?.ok_or("group state")?;
        let distribution = ramflux_protocol::parse_i_json(
            &source.client.export_group_sender_key_distribution(GROUP, &source.config.device_id)?,
        )?;
        let exact = source.client.generated_group_key_inner(
            THREAD,
            state.view().epoch,
            &distribution,
            &target.client.owned_device_identity()?,
        )?;
        let forged = outsider.seal_inner_to(&target, &reauthor(&outsider, &exact)?)?;
        assert!(
            target.receive(forged, 2).await.is_err(),
            "another member imported a borrowed distribution"
        );
        target.receive(source.seal_inner_to(&target, &exact)?, 3).await?;
        let (id, body) = message(&source)?;
        target.receive(source.seal_inner_to(&target, &body)?, 4).await?;
        assert_eq!(
            target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
            Some("authenticated group text")
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn group_message_before_distribution_keeps_content_retryable() -> TestResult {
    watchdog::within(async {
        let (source, mut target, _) = Box::pin(setup_with_bootstrap(false, false)).await?;
        target.client.require_group_sender_pin(
            GROUP,
            &source.config.principal_id,
            &source.client.owned_device_identity()?,
        )?;
        let state = source.client.account_db()?.shared_group_state(GROUP)?.ok_or("group state")?;
        let (id, exact) = message(&source)?;
        let envelope = source.seal_inner_to(&target, &exact)?;
        let pending = target.receive(envelope.clone(), 1).await;
        assert!(
            pending.is_ok()
                || matches!(
                    pending
                        .as_ref()
                        .err()
                        .and_then(|error| error.downcast_ref::<crate::SdkError>()),
                    Some(crate::SdkError::InboundPending(_))
                ),
            "missing group key must stay retryable: {pending:?}"
        );
        assert!(
            target.client.generated_message_detail(THREAD, &id).is_err(),
            "missing key exposed a message"
        );
        assert!(
            target
                .client
                .load_group_sender_key_state(
                    GROUP,
                    &source.client.owned_device_identity()?,
                    state.view().epoch,
                    "recv"
                )
                .is_err()
        );
        let distribution = ramflux_protocol::parse_i_json(
            &source.client.export_group_sender_key_distribution(GROUP, &source.config.device_id)?,
        )?;
        let key = source.client.generated_group_key_inner(
            THREAD,
            state.view().epoch,
            &distribution,
            &target.client.owned_device_identity()?,
        )?;
        target.receive(source.seal_inner_to(&target, &key)?, 2).await?;
        target.receive(envelope.clone(), 1).await?;
        assert_eq!(
            target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
            Some("authenticated group text")
        );
        let before = target.client.persisted_pair_snapshot(
            &target.client.owned_device_identity()?,
            &source.client.owned_device_identity()?,
        )?;
        target.receive(envelope, 1).await?;
        assert_eq!(target.client.direct_chat_messages(THREAD)?.len(), 1);
        assert_eq!(
            target.client.persisted_pair_snapshot(
                &target.client.owned_device_identity()?,
                &source.client.owned_device_identity()?
            )?,
            before,
            "a key-delayed replay advanced the pair ratchet twice"
        );
        Ok(())
    })
    .await?
}

fn assert_group_author_refusal(error: Box<dyn std::error::Error>) -> TestResult {
    let error = error.downcast::<crate::SdkError>().map_err(|error| error.to_string())?;
    match error.as_ref() {
        crate::SdkError::InboundRejected(reason) => assert!(
            reason.contains("author")
                || reason.contains("member")
                || reason.contains("role")
                || reason.contains("root differs"),
            "the group adversary failed outside author admission: {reason}"
        ),
        crate::SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
            ramflux_protocol::GroupStateLimit::Devices,
        ))
        | crate::SdkError::Storage(ramflux_storage::StorageError::GroupPermissionDenied)
        | crate::SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Authority, ..
        } => {}
        other => {
            return Err(
                format!("the group adversary failed outside author admission: {other}").into()
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn stranger_snapshot_waits_for_creator_consent_before_native_group_delivery() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("group-consent-source").await?;
        let mut target = Fixture::new("group-consent-target").await?;
        source.client.persist_fetched_identity_directory(&target.manifest)?;
        {
            // The primary signing lease is exclusive; release it before `change` takes its own.
            let primary = source
                .client
                .born_v3_account
                .as_ref()
                .ok_or("native owner")?
                .group_primary(source.vault.as_ref())?;
            source.client.shared_group_create_with_primary(
                GROUP,
                THREAD,
                None,
                &source.config.target_delivery_id,
                Some(&primary),
            )?;
        }
        let state = change(
            &source,
            GroupStateChange::Add {
                member: target
                    .client
                    .owned_group_actor(&target.config.target_delivery_id)?
                    .identity,
                role: SharedGroupRole::Member,
            },
        )?;
        let snapshot = source
            .client
            .shared_group_packet_for_recipient(&state, &target.client.owned_device_identity()?)?;
        let envelope = source.seal_inner_to(&target, &snapshot)?;
        let directory =
            Directory::new(vec![source.manifest.clone(), target.manifest.clone()]).await?;
        directory.configure(&mut target);
        let _held = target.receive(envelope.clone(), 1).await;
        assert!(
            target.client.account_db()?.shared_group_state(GROUP)?.is_none(),
            "a stranger's snapshot installed an accepted group"
        );
        assert!(
            target
                .client
                .load_group_sender_key_state(
                    GROUP,
                    &source.client.owned_device_identity()?,
                    state.view().epoch,
                    "recv"
                )
                .is_err(),
            "pending group consent exposed its sender key"
        );
        target.accept_peer(&source)?;
        source.accept_peer(&target)?;
        target.receive(envelope, 1).await?;
        assert!(target.client.account_db()?.shared_group_state(GROUP)?.is_some(),
            "accepted creator contact supplies the signed snapshot's existing implicit-consent policy");
        target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
        let approved =
            change(&source, GroupStateChange::SetName { name: "approved group".into() })?;
        let snapshot = source.client.shared_group_packet_for_recipient(
            &approved,
            &target.client.owned_device_identity()?,
        )?;
        target.receive(source.seal_inner_to(&target, &snapshot)?, 2).await?;
        assert_eq!(
            target
                .client
                .account_db()?
                .shared_group_state(GROUP)?
                .ok_or("approved state")?
                .snapshot()
                .state_hash,
            approved.snapshot().state_hash,
            "the same snapshot path must accept after explicit group consent"
        );
        let (id, exact) = message(&source)?;
        target.receive(source.seal_inner_to(&target, &exact)?, 3).await?;
        assert_eq!(
            target.client.generated_message_detail(THREAD, &id)?.message.text.as_deref(),
            Some("authenticated group text"),
            "explicit local group acceptance did not calibrate the native delivery path"
        );
        Ok(())
    })
    .await?
}
