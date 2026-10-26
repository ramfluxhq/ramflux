// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A stranger-group decision is replicated through authenticated encrypted own-device delivery.
use super::*;

#[tokio::test]
async fn r6_one_invitation_acceptance_joins_an_active_sibling_without_another_prompt() -> TestResult
{
    Box::pin(check_group_decision(true)).await
}
#[tokio::test]
async fn r6_one_invitation_decline_fences_the_other_active_sibling() -> TestResult {
    Box::pin(check_group_decision(false)).await
}
async fn check_group_decision(accept: bool) -> TestResult {
    let root = runtime_tests::root("group-own-consent");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory, peer) =
        sibling_fixture_with_peer(&root, &mut source, false).await?;
    let stranger = runtime_tests::account(
        &root.join("stranger"),
        "stranger",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let state = invite_own_devices(&stranger, &source, &sibling, &config, &receiver)?;
    assert!(!source.client.friend_link_peer_is_accepted(
        stranger.client.owned_device_identity()?.root_commitment(),
    )?);
    source.client.decide_group_invitation("group", accept, &config.target_delivery_id)?;
    let gateway = fresh_sibling_gateway(&source.client, &sibling.client)?;
    let captured = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    let envelope = captured
        .lock()
        .map_err(|_| "own-copy capture")?
        .first()
        .cloned()
        .ok_or("consent copy missing")?;
    let incoming = entry(envelope, 1);
    assert!(sibling.client.receive_own_device_message(&receiver, &incoming).await?);
    assert!(sibling.client.receive_own_device_message(&receiver, &incoming).await?);
    assert_eq!(sibling.client.group_invitations()?["invitations"], json!([]));
    assert_eq!(sibling.client.local_is_group_member("group")?, accept);
    if accept {
        assert_eq!(sibling.client.group_state("group")?.group_epoch, state.view().epoch);
    } else {
        let offered = crate::client::shared_group::PreparedSharedGroup::Invitation {
            state: state.clone(),
            body: zeroize::Zeroizing::new(stranger.client.shared_group_packet(&state, false)?),
        };
        sibling.client.apply_prepared_shared_group(&offered, &receiver.target_delivery_id)?;
        assert_eq!(sibling.client.group_invitations()?["invitations"], json!([]));
        assert!(!sibling.client.local_is_group_member("group")?);
    }
    assert_eq!(sibling.client.direct_messages("group-thread")?.len(), 0);
    directory.abort();
    drop((source, sibling, stranger, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn invite_own_devices(
    stranger: &LocalBusAccountState,
    source: &LocalBusAccountState,
    sibling: &LocalBusAccountState,
    config: &GatewaySessionConfig,
    receiver: &GatewaySessionConfig,
) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
    stranger.client.shared_group_create("group", "group-thread", None, "stranger")?;
    let state = stranger.client.shared_group_change(
        "group",
        "stranger",
        ramflux_protocol::GroupStateChange::Add {
            member: source.client.owned_group_actor(&config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    for (client, target) in [
        (&source.client, &config.target_delivery_id),
        (&sibling.client, &receiver.target_delivery_id),
    ] {
        let pending = crate::client::shared_group::PreparedSharedGroup::Invitation {
            state: state.clone(),
            body: zeroize::Zeroizing::new(stranger.client.shared_group_packet(&state, false)?),
        };
        client.apply_prepared_shared_group(&pending, target)?;
        assert_eq!(client.group_invitations()?["invitations"].as_array().map(Vec::len), Some(1));
        assert!(!client.local_is_group_member("group")?);
    }
    Ok(state)
}
