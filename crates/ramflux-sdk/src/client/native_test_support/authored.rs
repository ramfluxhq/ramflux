// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical Sent attestations reach a newly enrolled third device without peer proofs.
use super::*;
use crate::SdkError;
use crate::client::own_sent_message::OwnSentInput;
use crate::client::routed::SendMaterial;
use ramflux_protocol::message as g;

impl Fixture {
    async fn restart_authored_source(&mut self) -> TestResult {
        let account = self.client.account_db()?.local_account_id.clone();
        drop(std::mem::replace(&mut self.client, RamfluxClient::new()));
        self.client.open_account_index(&self.root.0)?;
        self.client.unlock_account(&account, b"native fixture data passphrase")?;
        self.client.initialize_born_v3_branch(&self.config.device_id, self.vault.clone()).await?;
        self.config = self.config.clone().with_account_identity(&self.client)?;
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
    let envelope = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    capture_before_enrollment(&source, &peer_root, &conversation, &owner, &envelope, &exact)?;
    let mut second = source.enroll_sibling("authored-second", "second").await.map_err(|error| format!("enroll second: {error}"))?;
    let mut third = source.enroll_sibling("authored-third", "third").await.map_err(|error| format!("enroll third: {error}"))?;
    second.manifest = source.manifest.clone();
    second.client.persist_fetched_identity_directory(&source.manifest)?;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    source.client.stage_authored_history().map_err(|error| format!("stage authored history: {error:?}"))?;
    let bindings = source.client.account_db()?.actor_state_keys("own-history/staged/")?;
    assert_eq!(bindings.len(), 2);
    source.restart_authored_source().await.map_err(|error| format!("restart source: {error}"))?;
    source.client.stage_authored_history().map_err(|error| format!("stage authored history: {error:?}"))?;
    assert_eq!(source.client.account_db()?.actor_state_keys("own-history/staged/")?, bindings);

    let mut captured = None;
    for _ in 0..2 {
        let plan =
            source.client.prepare_authored_history(&source.config).map_err(|error| format!("prepare authored: {error:?}"))?.ok_or("authored plan")?;
        let target = if plan.request.prekey.as_deref()
            == Some(second.client.owned_device_identity()?.storage_key())
        {
            &mut second
        } else {
            &mut third
        };
        let material = source.material_for(target)?;
        let (plan, attestation) = source
            .client
            .seal_authored_history(&source.config, plan, material).map_err(|error| format!("seal authored: {error:?}"))?
            .ok_or("sealed attestation")?;
        target.receive(attestation.clone(), 1).await.map_err(|error| format!("receive authored: {error}"))?;
        assert_eq!(target.client.account_db()?.message_content(&owner)?, Some(exact.clone()));
        assert!(
            target
                .client
                .export_generated_history_item(&ramflux_protocol::decode_base64url(&owner)?)
                .is_err(),
            "sibling attestation never becomes peer origin evidence"
        );
        if target.config.device_id == "third" {
            captured = Some(plan);
            break;
        }
        source.client.complete_authored_history(&plan)?;
    }
    let plan = captured.ok_or("third sibling did not receive authored history")?;
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

fn capture_before_enrollment(
    source: &Fixture,
    peer_root: &str,
    conversation: &str,
    owner: &str,
    envelope: &str,
    exact: &[u8],
) -> TestResult {
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    source.client.account_db()?.write_transaction(|| {
        source.client.capture_own_authored_revision(OwnSentInput {
            envelope,
            conversation,
            message: owner,
            sender: &source.config.principal_id,
            original_recipients: &[],
            group: None,
            peer: Some(peer_root),
            body: exact,
            ciphertext: &[],
            at: 123,
        })?;
        source.client.send_direct_message(
            conversation,
            owner,
            &source.config.principal_id,
            b"original recipient ciphertext",
        )?;
        Ok::<(), SdkError>(())
    })?;
    Ok(())
}
