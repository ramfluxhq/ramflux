// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A malformed directory reply must not consume the generated snapshot's pair ratchet.
use crate::SdkError;
use crate::client::native_test_support::{Fixture, TestResult, directory::Directory, watchdog};
use ramflux_protocol::{GroupStateChange, SharedGroupRole, message as g};

#[tokio::test(flavor = "current_thread")]
async fn malformed_gateway_success_during_bootstrap_is_held_and_the_same_distribution_retries()
-> TestResult {
    watchdog::within(exercise()).await?
}

async fn exercise() -> TestResult {
    let source = Fixture::new("bootstrap-retry-source").await?;
    let mut target = Fixture::new("bootstrap-retry-target").await?;
    source.client.persist_observed_identity_directory_now(&target.manifest)?;
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native owner")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "bootstrap",
        "bootstrap-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = source.client.shared_group_change_with_primary(
        "bootstrap",
        &source.config.target_delivery_id,
        GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    // Explicit local acceptance precedes the network snapshot. The remote sender
    // still needs its current native directory proof before the pair can open.
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    let exact = source
        .client
        .shared_group_packet_for_recipient(&state, &target.client.owned_device_identity()?)?;
    let envelope = source.seal_inner_to(&target, &exact)?;
    let directory =
        Directory::malformed_once(vec![source.manifest.clone(), target.manifest.clone()]).await?;
    directory.configure(&mut target);
    let before = target.client.account_db()?.actor_state_keys("dm-pair/")?;
    let first = target.receive(envelope.clone(), 1).await;
    assert!(
        matches!(
            first.as_ref().err().and_then(|error| error.downcast_ref::<SdkError>()),
            Some(
                SdkError::InboundPending(_)
                    | SdkError::DirectoryAuthorityUnavailable { .. }
                    | SdkError::SenderManifestRequired { .. }
                    | SdkError::FreshHeadRequired { .. }
            )
        ),
        "malformed directory success must hold the original envelope: {first:?}"
    );
    let failed_fetches = directory.requests_for(&source.client.own_account_anchor()?)?;
    assert_eq!(failed_fetches, 1, "the first malformed response must stop the first attempt");
    assert_eq!(
        target.client.account_db()?.actor_state_keys("dm-pair/")?,
        before,
        "failed authorization consumed the pair ratchet"
    );
    assert_eq!(
        target
            .client
            .account_db()?
            .shared_group_state("bootstrap")?
            .ok_or("accepted state")?
            .snapshot()
            .state_hash,
        state.snapshot().state_hash,
        "failed authorization changed the independently accepted state"
    );
    target.receive(envelope, 1).await?;
    assert_eq!(
        target
            .client
            .account_db()?
            .shared_group_state("bootstrap")?
            .ok_or("group")?
            .snapshot()
            .state_hash,
        state.snapshot().state_hash
    );
    assert!(
        directory.requests_for(&source.client.own_account_anchor()?)? > failed_fetches,
        "the identical snapshot must refetch current native authority before retrying"
    );
    let identity = source.client.allocate_generated_identity(
        "bootstrap-thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let message = source.client.encrypt_generated_group_inner(
        "bootstrap",
        &source.config.device_id,
        identity,
        &g::Message { text: "after authentic bootstrap retry".into(), ..Default::default() },
    )?;
    target.receive(source.seal_inner_to(&target, &message)?, 2).await?;
    assert_eq!(
        target.client.generated_message_detail("bootstrap-thread", &id)?.message.text.as_deref(),
        Some("after authentic bootstrap retry")
    );
    Ok(())
}
