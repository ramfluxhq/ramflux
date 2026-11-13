// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own group history forwards exact pre-seal plaintext with independently installed group authority.
use super::*;
use prost::Message as _;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn own_authored_group_history_preserves_plaintext_nonce_for_a_later_third_sibling()
-> TestResult {
    let mut source = Fixture::new("authored-group-source").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native account")?
        .group_primary(source.vault.as_ref())?;
    let state = source.client.shared_group_create_with_primary(
        "authored-group",
        "authored-group-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let identity = source.client.allocate_generated_identity(
        "authored-group-thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let wrapper = source.client.encrypt_generated_group_inner(
        "authored-group",
        &source.config.device_id,
        identity,
        &g::Message { text: "group revision before third enrollment".into(), ..Default::default() },
    )?;
    let outer_message = g::Message::decode(g::Inner::decode(wrapper.as_slice())?.body.as_slice())?;
    assert!(outer_message.sealed_group.is_some());
    assert_eq!(outer_message.erasure_nonce.len(), 0);
    let captured: serde_json::Value = source
        .client
        .account_db()?
        .load_actor_state(&format!("own-history/capture/{owner}"))?
        .ok_or("plaintext capture")?;
    let sent: g::OwnSentMessage = serde_json::from_value(captured["sent"].clone())?;
    let plaintext =
        g::Message::decode(g::Inner::decode(sent.exact_inner.as_slice())?.body.as_slice())?;
    assert!(plaintext.sealed_group.is_none());
    assert_eq!(plaintext.erasure_nonce.len(), 32);
    assert!(sent.ciphertext_digest.is_none());
    let mut second = source.enroll_sibling("authored-group-second", "second").await?;
    let mut third = source.enroll_sibling("authored-group-third", "third").await?;
    second.manifest = source.manifest.clone();
    second.client.persist_fetched_identity_directory(&source.manifest)?;
    // A copied context cannot grant membership: both siblings explicitly verify/install
    // the independently signed native group snapshot through the native consent API.
    for target in [&second, &third] {
        target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    }
    for _ in 0..2 {
        let plan = source.client.prepare_authored_history(&source.config)?.ok_or("group plan")?;
        let target =
            if plan.target.device_id == second.config.device_id { &mut second } else { &mut third };
        let (plan, envelope) = source
            .client
            .seal_authored_history(&source.config, plan, source.material_for(target)?)?
            .ok_or("group sealed")?;
        target.receive(envelope, 1).await?;
        assert_eq!(
            target.client.account_db()?.message_content(&owner)?,
            Some(sent.exact_inner.clone())
        );
        assert!(
            target
                .client
                .export_generated_history_item(&ramflux_protocol::decode_base64url(&owner)?)
                .is_err()
        );
        source.client.complete_authored_history(&plan)?;
    }
    let view = third.client.generated_message_detail("authored-group-thread", &owner)?;
    assert_eq!(view.message.text.as_deref(), Some("group revision before third enrollment"));
    Ok(())
}
