// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical Sent attestations reach a newly enrolled third device without peer proofs.
use super::*;
use crate::client::routed::SendMaterial;
use prost::Message as _;
use ramflux_protocol::message as g;

impl Fixture {
    async fn restart_authored_source(&mut self) -> TestResult {
        let account = self.client.account_db()?.local_account_id.clone();
        drop(std::mem::replace(&mut self.client, RamfluxClient::new()));
        self.client.open_account_index(&self.root.0)?;
        self.client.unlock_account(&account, b"native fixture data passphrase")?;
        self.client.initialize_born_v3_branch(&self.config.device_id, self.vault.clone()).await?;
        self.config = self.config.clone().with_account_identity(&self.client)?;
        self.config.device_branch = Some(std::sync::Arc::new(
            self.client.device_branch.as_ref().ok_or("reopened branch")?.clone(),
        ));
        self.config.source_identity = Some(self.client.owned_device_identity()?);
        self.client.persist_fetched_identity_directory(&self.manifest)?;
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn own_authored_history_stages_for_a_new_third_sibling_and_erases_cached_bytes() -> TestResult
{
    let mut source = Fixture::new("authored-source").await?;
    let peer = Fixture::new("authored-peer").await?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    let own_root = source.client.own_account_anchor()?;
    let peer_root = peer.client.own_account_anchor()?;
    let conversation = g::dm_scope::derive(&own_root, &peer_root)?;
    source.client.establish_friend_link("authored-link", &own_root, &peer_root)?;
    source.client.receive_generated_own_contact(&authored_contact(&source, &peer)?)?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "authored before third enrollment".into(),
                ..Default::default()
            })),
        },
    )?;
    capture_before_enrollment(&source, &peer, &conversation, &owner, &exact)?;
    let mut second = source
        .enroll_sibling("authored-second", "second")
        .await
        .map_err(|error| format!("enroll second: {error}"))?;
    let mut third = source
        .enroll_sibling("authored-third", "third")
        .await
        .map_err(|error| format!("enroll third: {error}"))?;
    second.manifest = source.manifest.clone();
    second.client.persist_fetched_identity_directory(&source.manifest)?;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    Box::pin(bootstrap_peer_contact(&source, &peer, &mut second, &mut third, &conversation))
        .await?;
    source
        .client
        .stage_authored_history()
        .map_err(|error| format!("stage authored history: {error:?}"))?;
    let bindings = source.client.account_db()?.actor_state_keys("own-history/pending/")?;
    assert_eq!(bindings.len(), 2);
    assert_eq!(
        source.client.account_db()?.actor_state_keys("own-history/staged/")?.len(),
        0,
        "reservation is not a sealed map"
    );
    source.restart_authored_source().await.map_err(|error| format!("restart source: {error}"))?;
    source
        .client
        .stage_authored_history()
        .map_err(|error| format!("stage authored history: {error:?}"))?;
    assert_eq!(source.client.account_db()?.actor_state_keys("own-history/pending/")?, bindings);

    let plan = Box::pin(deliver_to_third(&source, &mut second, &mut third, &owner, &exact)).await?;
    let plan = Box::pin(retry_after_restart(&mut source, &mut third, plan, &conversation)).await?;
    assert_eq!(third.client.account_db()?.message_content(&owner)?, Some(exact));
    source.client.account_db()?.delete_direct_message(
        &conversation,
        &owner,
        "local",
        "erase-authored",
    )?;
    assert!(
        source
            .client
            .seal_authored_history(
                &source.config,
                plan,
                SendMaterial { manifest: None, bundle: None }
            )?
            .is_none()
    );
    assert_eq!(source.client.account_db()?.actor_state_keys("own-history/capture/")?.len(), 0);
    assert_eq!(source.client.account_db()?.actor_state_keys("own-history/pending/")?.len(), 0);
    Ok(())
}

pub(super) fn capture_before_enrollment(
    source: &Fixture,
    peer: &Fixture,
    conversation: &str,
    owner: &str,
    exact: &[u8],
) -> TestResult {
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    source.client.account_db()?.write_transaction(|| {
        let envelope = source.seal_inner_to(peer, exact)?;
        source.client.send_direct_message(
            conversation,
            owner,
            &source.config.principal_id,
            &ramflux_protocol::canonical_json_bytes(&envelope)?,
        )?;
        source.client.stage_own_sent_message(crate::client::own_sent_message::OwnSentInput {
            envelope: &envelope.envelope_id,
            conversation,
            message: owner,
            sender: &source.config.device_id,
            original_recipients: &[peer.client.owned_device_identity()?.storage_key().into()],
            group: None,
            peer: Some(&peer.manifest.principal_id),
            body: exact,
            ciphertext: &[],
            at: envelope.created_at,
        })?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

async fn deliver_to_third(
    source: &Fixture,
    second: &mut Fixture,
    third: &mut Fixture,
    owner: &str,
    exact: &[u8],
) -> TestResult<crate::client::own_sent_message::authored::delivery::Plan> {
    let mut captured = None;
    for _ in 0..2 {
        let plan = source
            .client
            .prepare_authored_history(&source.config)
            .map_err(|error| format!("prepare authored: {error:?}"))?
            .ok_or("authored plan")?;
        let target = if plan.target.device_id == second.config.device_id {
            &mut *second
        } else {
            &mut *third
        };
        let material = source.material_for(target)?;
        let (plan, attestation) = source
            .client
            .seal_authored_history(&source.config, plan, material)
            .map_err(|error| format!("seal authored: {error:?}"))?
            .ok_or("sealed attestation")?;
        target
            .receive(attestation.clone(), 1)
            .await
            .map_err(|error| format!("receive authored: {error}"))?;
        assert_eq!(target.client.account_db()?.message_content(owner)?, Some(exact.to_vec()));
        assert!(
            target
                .client
                .export_generated_history_item(&ramflux_protocol::decode_base64url(owner)?)
                .is_err(),
            "sibling attestation never becomes peer origin evidence"
        );
        if target.config.device_id == "third" {
            captured = Some(plan);
            break;
        }
        source.client.complete_authored_history(&plan)?;
    }
    captured.ok_or_else(|| "third sibling did not receive authored history".into())
}

async fn bootstrap_peer_contact(
    source: &Fixture,
    peer: &Fixture,
    second: &mut Fixture,
    third: &mut Fixture,
    conversation: &str,
) -> TestResult {
    let contact = authored_contact(source, peer)?;
    let control = crate::client::generated_control::control_from_payload(
        g::control::Payload::OwnContactSync(contact),
    )?;
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?;
    for target in [second, third] {
        let envelope = source.seal_inner_to(target, &exact)?;
        target.receive(envelope, 1).await?;
    }
    Ok(())
}

async fn retry_after_restart(
    source: &mut Fixture,
    third: &mut Fixture,
    plan: crate::client::own_sent_message::authored::delivery::Plan,
    conversation: &str,
) -> TestResult<crate::client::own_sent_message::authored::delivery::Plan> {
    let expected = plan.envelope.clone().ok_or("cached envelope")?;
    let before = third.client.generated_message_changes(conversation, 0, 100)?.next_after;
    source.restart_authored_source().await?;
    let (plan, cached) = source
        .client
        .seal_authored_history(&source.config, plan, SendMaterial { manifest: None, bundle: None })?
        .ok_or("cached plan after reopen")?;
    assert_eq!(cached, expected, "reopen reuses the exact sealed bytes and staging id");
    third.receive(cached, 3).await?;
    assert!(third.client.generated_message_changes(conversation, before, 100)?.changes.is_empty());
    assert!(
        (1..=2)
            .contains(&source.client.account_db()?.actor_state_keys("own-history/staged/")?.len())
    );
    Ok(plan)
}

pub(super) fn authored_contact(source: &Fixture, peer: &Fixture) -> TestResult<g::OwnContactSync> {
    let link = source.client.account_db()?.friend_link("authored-link")?;
    Ok(g::OwnContactSync {
        manifest: Some(g::NativeDeviceManifest::decode(
            source.client.encode_generated_task_manifest(&peer.manifest)?.as_slice(),
        )?),
        link: Some(g::FriendLinkRecord {
            link_id: link.link_id,
            requester_id: link.requester_id,
            target_id: link.target_id,
            state: link.state,
            remove_scope: link.remove_scope,
            blocked: link.blocked,
            capability_revoked_at: link.capability_revoked_at,
        }),
    })
}
