// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed clients through the real gateway and separately persisted router process.
use super::*;
use crate::pre_auth_transport_tests::{
    auth_for,
    support::{Fixture as Gateway, Route},
};
use ramflux_node_core::{GatewayClientFrame, GatewayServerFrame};

#[tokio::test]
#[ignore = "requires a separately built same-tree router binary"]
async fn activation_admits_new_classes_and_refuses_missing_binding() -> Result {
    if std::env::var("RAMFLUX_TEST_ACTIVATION_CHILD").as_deref() == Ok("1") {
        tokio::time::timeout(Duration::from_secs(120), run()).await?
    } else {
        isolated().await
    }
}
async fn isolated() -> Result {
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command.args(["--exact",
        "custody::tests::schema_activation_ingress::activation_admits_new_classes_and_refuses_missing_binding",
        "--ignored", "--nocapture"])
        .env("RAMFLUX_TEST_ACTIVATION_CHILD", "1")
        .env("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", ramflux_crypto::public_key_base64url_from_seed([8;32]))
        .env("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED", ramflux_protocol::encode_base64url([9;32]))
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(150), command.status()).await??;
    assert!(status.success(), "isolated native gateway/router regression failed: {status}");
    Ok(())
}

async fn run() -> Result {
    assert!(ramflux_protocol::schema_profile::schema_v1_live(), "test requires generation 1");
    let now = ramflux_node_core::now_unix_seconds();
    let account = authority(now)?;
    let gateway = Gateway::new_custody(Some(&account.node)).await?;
    let mut client =
        super::pre_auth_matrix::handoff(&gateway, Route::Tcp, "127.0.0.66", &account, true).await?;
    let anchor = &account.publication.record.body.account_anchor;
    let target = ramflux_protocol::qualified_device_id(anchor, "primary")?;
    let mut open = crate::pre_auth_transport_tests::open("generation-one", 1, None)?;
    open.device_id = "primary".into();
    open.target_delivery_id.clone_from(&target);
    let authenticated = auth_for(&open, [3; 32], "alice", anchor)?;
    assert!(
        matches!(
            client.exchange(open, authenticated).await?,
            GatewayServerFrame::SessionEstablished { .. }
        ),
        "native client must establish a real authenticated gateway session"
    );
    for (number, class) in
        [ramflux_protocol::DeliveryClass::Message, ramflux_protocol::DeliveryClass::CallWake]
            .into_iter()
            .enumerate()
    {
        let accepted = submission(&account, number, class, now)?;
        client
            .stream
            .send_frame(&serde_json::to_vec(&GatewayClientFrame::Submit {
                submit: accepted.clone(),
            })?)
            .await?;
        let response: GatewayServerFrame =
            serde_json::from_slice(&client.stream.recv_frame().await?)?;
        let GatewayServerFrame::Deliver { entry } = response else {
            return Err(format!("active class was not accepted: {response:?}").into());
        };
        assert_eq!(
            entry.envelope.envelope_id, accepted.envelope.envelope_id,
            "gateway acceptance must identify the submitted envelope"
        );
        assert_eq!(
            entry.inbox_seq,
            u64::try_from(number)? + 1,
            "accepted classes must allocate real router inbox sequences"
        );
        let mut submit = submission(&account, number + 100, class, now)?;
        submit.envelope.collapse_tag = None;
        submit.signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            &ramflux_protocol::canonical_json_bytes(&submit.envelope)?,
        );
        submit.signed_request.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(
                &account.branch,
                &submit.signed_request,
            )?;
        let before = {
            let mut state = crate::gateway_state(&gateway.context.state)?;
            state.replay_guard_state_mut().clone()
        };
        client
            .stream
            .send_frame(&serde_json::to_vec(&GatewayClientFrame::Submit {
                submit: submit.clone(),
            })?)
            .await?;
        let response: GatewayServerFrame =
            serde_json::from_slice(&client.stream.recv_frame().await?)?;
        assert!(
            matches!(response, GatewayServerFrame::Nack { reason } if reason.contains("delivery_mode_refused")),
            "gateway must refuse a missing named binding before signed-request replay persistence"
        );
        let after = {
            let mut state = crate::gateway_state(&gateway.context.state)?;
            state.replay_guard_state_mut().clone()
        };
        assert!(after == before, "missing binding must leave gateway replay state unchanged");
        let rejected: ramflux_node_core::EnvelopeSubmitResponse = crate::router_post_json_async(
            &gateway.context.router,
            "/mvp0/envelope",
            &submit.envelope,
        )
        .await?;
        assert_eq!(
            rejected.outcome, "rejected_security:delivery_mode_refused",
            "router ingress must refuse independently"
        );
        assert!(rejected.inbox_seq.is_none(), "refusal must not allocate an inbox sequence");
    }
    Ok(())
}

fn submission(
    account: &AuthorityFixture,
    number: usize,
    class: ramflux_protocol::DeliveryClass,
    now: u64,
) -> Result<ramflux_node_core::GatewaySubmitFrame> {
    let runtime = crate::session::submit_fixtures::test_runtime()?;
    let anchor = &account.publication.record.body.account_anchor;
    let target = ramflux_protocol::qualified_device_id(anchor, "primary")?;
    let mut submit = crate::session::submit_fixtures::signed_submit(&runtime, i64::try_from(now)?)?;
    submit.envelope.envelope_id = format!("generation-one-{number}");
    submit.envelope.source_principal_id = "alice".into();
    submit.envelope.source_device_id = "primary".into();
    submit.envelope.target_delivery_id.clone_from(&target);
    submit.envelope.signed.signing_key_id = "primary".into();
    submit.envelope.ext.ext.insert("source_root_commitment".into(), serde_json::json!(anchor));
    submit.envelope.delivery_class = class;
    submit.envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&account.branch, &submit.envelope)?;
    submit.signed_request.source_device_id = "primary".into();
    submit.signed_request.signed.signing_key_id = "primary".into();
    submit.signed_request.request_id = format!("generation-one-{number}");
    submit.signed_request.nonce.clone_from(&submit.signed_request.request_id);
    submit.signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&submit.envelope)?,
    );
    submit.signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(
            &account.branch,
            &submit.signed_request,
        )?;
    Ok(submit)
}
