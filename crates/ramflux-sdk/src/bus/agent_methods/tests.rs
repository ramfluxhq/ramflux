// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation through the bus methods on two roots of one human account: the desktop and the
//! primary phone, with the staged packets delivered through the real own-device receive path.
//! No node is involved; the packets are captured from the outbox and applied on the other root.
use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use crate::bus::own_device_copy;
use crate::bus::state::LocalBusAccountState;
use crate::client::agent_custody::AgentCustodySend;
use crate::client::native_test_support::bus::receive_copy;
use crate::client::shared_group::tests::{
    install_native_directories, native_person, native_sibling,
};
use crate::custody::agent_creation::AgentCreationState;
use crate::{GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, SdkError};
use ramflux_protocol::custody::{
    RegisterCancel, RegisterPlan, decode_register_plan, encode_register_cancel,
};
use ramflux_protocol::message as g;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn block_on(future: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(future)
}

fn create_body(confirmed: Option<bool>) -> g::AgentCreate {
    g::AgentCreate {
        persona: Some(g::AgentPersona {
            name: "Support agent".into(),
            avatar: String::new(),
            responsibility: "answers questions".into(),
        }),
        host: None,
        config: Some(g::AgentConfigData {
            provider: "openai".into(),
            model: "gpt".into(),
            prompt: None,
            autonomy: "full".into(),
            tools: vec!["*".into()],
            enabled: Some(true),
            limits: None,
        }),
        confirmed,
        access: Some(g::AgentAccessPolicy {
            dm: "owner".into(),
            group_inviters: "owner".into(),
            allowed_humans: Vec::new(),
        }),
        role: "named".into(),
    }
}

fn decide_body(
    request_id: &str,
    request_hash: &str,
    approved: Option<bool>,
) -> g::AgentCreationDecide {
    g::AgentCreationDecide {
        request_id: request_id.into(),
        request_hash: request_hash.into(),
        approved,
    }
}

/// The primary phone and one paired desktop of the same human account.
fn pair(id: &str) -> Result<(LocalBusAccountState, LocalBusAccountState), SdkError> {
    let mut phone = native_person(&format!("owner-{id}"), "phone")?;
    let laptop = native_sibling(&mut phone, &format!("laptop-{id}"), "laptop")?;
    install_native_directories(&[&phone, &laptop])?;
    crate::client::native_test_support::bus::seed_pair(&phone.client, &laptop.client)?;
    Ok((phone, laptop))
}

fn now() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(crate::custody::network_now()?)
}

fn vault_of(client: &RamfluxClient) -> Result<Arc<dyn crate::custody::PrimaryVault>, SdkError> {
    client.born_v3_vault.clone().ok_or(SdkError::CustodyVaultUnavailable)
}

/// Flush the one staged packet of `source` and return it as the inbox entry a receiver gets.
async fn outbound(
    source: &mut LocalBusAccountState,
    sequence: u64,
) -> Result<GatewayInboxEntry, Box<dyn std::error::Error>> {
    let gateway = RecordingGateway::new(Arc::default());
    let attempted = gateway.attempted.clone();
    let engine =
        GatewaySessionEngine::with_test_transport(source.gateway_config.clone(), Box::new(gateway));
    source.install_test_session(engine);
    assert_eq!(own_device_copy::flush(source).await?, 1, "one staged packet leaves the outbox");
    let packet = attempted.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: sequence,
        target_delivery_id: packet.target_delivery_id.clone(),
        envelope: packet,
    })
}

/// Capture the one staged packet of `source` and apply it on `target` through the own-device
/// receive path (the same sequence the own-device surface tests use).
async fn deliver(
    source: &mut LocalBusAccountState,
    target: &mut LocalBusAccountState,
    sequence: u64,
) -> TestResult {
    let entry = outbound(source, sequence).await?;
    assert!(receive_copy(&mut target.client, &target.gateway_config, &entry).await?);
    Ok(())
}

/// The cancel of one request as its initiating desktop holds it, with the plan it names.
fn cancel_of(
    initiator: &LocalBusAccountState,
    request_id: &str,
) -> Result<(Vec<u8>, RegisterPlan), Box<dyn std::error::Error>> {
    let record =
        initiator.client.agent_creation_store()?.load(request_id)?.ok_or("initiator record")?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let cancel = encode_register_cancel(&RegisterCancel {
        request_id: request_id.into(),
        request_hash: record.request_hash.clone(),
    })?;
    Ok((cancel, plan))
}

/// Stage a cancel from `sender` to `target` (both on one root) and return the entry the target gets.
async fn stage_cancel(
    sender: &mut LocalBusAccountState,
    target: &LocalBusAccountState,
    (cancel, plan): (Vec<u8>, RegisterPlan),
    request_id: &str,
    sequence: u64,
) -> Result<GatewayInboxEntry, Box<dyn std::error::Error>> {
    let device = target.client.owned_device_identity()?;
    sender.client.stage_agent_custody(AgentCustodySend {
        target: &device,
        owner_anchor: &plan.owner_anchor,
        agent_anchor: &plan.agent_anchor,
        correlation_id: request_id,
        custody: g::AgentCustodyPacket {
            value: Some(g::agent_custody_packet::Value::CancelJson(cancel)),
        },
        now: now()?,
    })?;
    outbound(sender, sequence).await
}

fn refused_with<T: std::fmt::Debug>(result: Result<T, SdkError>, token: &str) -> TestResult {
    match result {
        Err(SdkError::AgentCreationRefused(found)) if found == token => Ok(()),
        other => Err(format!("expected refusal {token}, got {other:?}").into()),
    }
}

#[test]
fn create_on_the_primary_refuses_desktop_required() -> TestResult {
    let (phone, _laptop) = pair("desktop-required")?;
    let vault = vault_of(&phone.client)?;
    refused_with(
        phone.client.agent_create(vault.as_ref(), &create_body(Some(true)), now()?),
        "desktop_required",
    )
}

#[test]
fn create_refuses_a_missing_or_false_confirmation_before_any_effect() -> TestResult {
    let (_phone, laptop) = pair("confirmation")?;
    let vault = vault_of(&laptop.client)?;
    refused_with(
        laptop.client.agent_create(vault.as_ref(), &create_body(None), now()?),
        "confirmation_required",
    )?;
    refused_with(
        laptop.client.agent_create(vault.as_ref(), &create_body(Some(false)), now()?),
        "confirmation_required",
    )?;
    let none = laptop.client.agent_creation_store()?.pending()?;
    assert!(none.is_empty(), "a refused create leaves no request behind");
    Ok(())
}

#[test]
fn create_refuses_when_the_authority_has_no_current_primary_branch() -> TestResult {
    let (_phone, laptop) = pair("pairing")?;
    let vault = vault_of(&laptop.client)?;
    // Past every branch lease of the authority: no current primary is paired.
    refused_with(
        laptop.client.agent_create(vault.as_ref(), &create_body(Some(true)), u64::MAX / 2),
        "creation_pairing_required",
    )
}

#[test]
fn operation_get_returns_the_stored_status_and_refuses_an_unknown_request() -> TestResult {
    let (mut phone, mut laptop) = pair("operation")?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        let read = laptop.client.agent_operation_status(&status.request_id)?;
        assert_eq!(read.state, "authorization_pending");
        assert_eq!(read.request_id, status.request_id);
        assert!(read.agent_anchor.is_some(), "the operation names the agent anchor");
        assert!(read.request_json.is_some(), "the operation carries the frozen plan");
        refused_with(
            laptop.client.agent_operation_status("no-such-operation"),
            "creation_request_unknown",
        )?;
        // Before the plan arrives nothing waits for the primary's decision; the desktop never
        // sees its own request as waiting for it.
        refused_with(phone.client.agent_operation_status(""), "creation_request_unknown")?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let waiting = phone.client.agent_operation_status("")?;
        assert_eq!(waiting.request_id, status.request_id, "the primary finds the request by itself");
        assert_eq!(waiting.state, "authorization_pending");
        assert_eq!(waiting.request_json, read.request_json, "it carries the frozen plan to decide on");
        refused_with(laptop.client.agent_operation_status(""), "creation_request_unknown")?;
        Ok(())
    })
}

#[test]
fn cancel_from_the_initiating_desktop_tombstones_the_primary_plan() -> TestResult {
    let (mut phone, mut laptop) = pair("cancel")?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let cancel = cancel_of(&laptop, &status.request_id)?;
        let entry = stage_cancel(&mut laptop, &phone, cancel, &status.request_id, 2).await?;
        assert!(receive_copy(&mut phone.client, &phone.gateway_config, &entry).await?);
        let store = phone.client.agent_creation_store()?;
        let record = store.load(&status.request_id)?.ok_or("primary record")?;
        assert_eq!(record.state, AgentCreationState::Cancelled, "the primary tombstones the plan");
        let replay =
            crate::custody::agent_creation::receive_plan(&store, &record.plan_bytes()?, now()?)?;
        assert_eq!(replay.state, AgentCreationState::Cancelled, "a replayed plan never revives it");
        Ok(())
    })
}

#[test]
fn cancel_from_another_source_is_refused() -> TestResult {
    let (mut phone, mut laptop) = pair("cancel-other")?;
    // A second paired desktop of the same human account: it did not initiate the request.
    let mut tablet = native_sibling(&mut phone, "tablet-cancel-other", "tablet")?;
    // Only the newest manifests are shared: the laptop's is one epoch behind after the enrolment.
    let newest = |account: &LocalBusAccountState| {
        account
            .client
            .native_bus_fixture
            .as_ref()
            .map(|material| material.manifest.clone())
            .ok_or(SdkError::CustodySetupInvalid)
    };
    let (phone_manifest, tablet_manifest) = (newest(&phone)?, newest(&tablet)?);
    phone.client.persist_observed_identity_directory_now(&tablet_manifest)?;
    tablet.client.persist_observed_identity_directory_now(&phone_manifest)?;
    laptop.client.persist_observed_identity_directory_now(&tablet_manifest)?;
    crate::client::native_test_support::bus::seed_pair(&phone.client, &tablet.client)?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let cancel = cancel_of(&laptop, &status.request_id)?;
        let entry = stage_cancel(&mut tablet, &phone, cancel, &status.request_id, 2).await?;
        assert!(
            receive_copy(&mut phone.client, &phone.gateway_config, &entry).await.is_err(),
            "a cancel from a device other than the initiating desktop is refused"
        );
        let record = phone
            .client
            .agent_creation_store()?
            .load(&status.request_id)?
            .ok_or("primary record")?;
        assert_eq!(
            record.state,
            AgentCreationState::AuthorizationPending,
            "the refused cancel leaves the plan pending"
        );
        Ok(())
    })
}

#[test]
fn decide_refuses_a_missing_approval_and_an_unknown_request() -> TestResult {
    let (phone, _laptop) = pair("approval")?;
    let vault = vault_of(&phone.client)?;
    refused_with(
        phone.client.agent_creation_decide(
            vault.as_ref(),
            &decide_body("no-such-request", "hash", None),
            now()?,
        ),
        "approval_required",
    )?;
    refused_with(
        phone.client.agent_creation_decide(
            vault.as_ref(),
            &decide_body("no-such-request", "hash", Some(true)),
            now()?,
        ),
        "creation_request_unknown",
    )
}

#[test]
fn create_plan_reaches_the_primary_store() -> TestResult {
    let (mut phone, mut laptop) = pair("create")?;
    block_on(async {
        let vault = vault_of(&laptop.client)?;
        let status =
            laptop.client.agent_create(vault.as_ref(), &create_body(Some(true)), now()?)?;
        assert_eq!(status.state, "authorization_pending", "the operation waits for the primary");
        deliver(&mut laptop, &mut phone, 1).await?;
        let stored = phone.client.agent_creation_store()?.load(&status.request_id)?;
        let stored = stored.ok_or("the primary stores the plan")?;
        assert_eq!(stored.state, AgentCreationState::AuthorizationPending);
        assert!(stored.account_id.is_none(), "the primary holds no secret and no account");
        Ok(())
    })
}

#[test]
fn approve_authorizes_the_desktop_request() -> TestResult {
    let (mut phone, mut laptop) = pair("approve")?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let hash = laptop
            .client
            .agent_creation_store()?
            .load(&status.request_id)?
            .ok_or("desktop record")?
            .request_hash;
        phone
            .client
            .native_bus_fixture
            .as_ref()
            .ok_or("the primary fixture vault")?
            .vault
            .arm_agent_decision(&hash)?;
        let primary = vault_of(&phone.client)?;
        let decided = phone.client.agent_creation_decide(
            primary.as_ref(),
            &decide_body(&status.request_id, &hash, Some(true)),
            now()?,
        )?;
        assert_eq!(decided.state, "authorized", "the primary records the approval");
        deliver(&mut phone, &mut laptop, 2).await?;
        let desktop = laptop.client.agent_creation_store()?.load(&status.request_id)?;
        assert_eq!(
            desktop.ok_or("desktop record")?.state,
            AgentCreationState::Authorized,
            "the desktop request becomes authorized"
        );
        Ok(())
    })
}

#[test]
fn deny_refuses_and_deletes_the_pending_keys() -> TestResult {
    let (mut phone, mut laptop) = pair("deny")?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let record = laptop
            .client
            .agent_creation_store()?
            .load(&status.request_id)?
            .ok_or("desktop record")?;
        let hash = record.request_hash.clone();
        let primary_reference = record.vault_refs.get(1).ok_or("primary reference")?.clone();
        phone
            .client
            .native_bus_fixture
            .as_ref()
            .ok_or("the primary fixture vault")?
            .vault
            .arm_agent_decision(&hash)?;
        let primary = vault_of(&phone.client)?;
        phone.client.agent_creation_decide(
            primary.as_ref(),
            &decide_body(&status.request_id, &hash, Some(false)),
            now()?,
        )?;
        deliver(&mut phone, &mut laptop, 2).await?;
        let refused = laptop.client.agent_creation_store()?.load(&status.request_id)?;
        assert_eq!(refused.ok_or("desktop record")?.state, AgentCreationState::Refused);
        assert!(
            desk.load_primary(&primary_reference).is_err(),
            "the pending primary key is deleted on deny"
        );
        Ok(())
    })
}

#[test]
fn decide_refuses_a_non_primary_and_an_altered_stored_plan() -> TestResult {
    let (mut phone, mut laptop) = pair("decide")?;
    block_on(async {
        let desk = vault_of(&laptop.client)?;
        let status = laptop.client.agent_create(desk.as_ref(), &create_body(Some(true)), now()?)?;
        deliver(&mut laptop, &mut phone, 1).await?;
        let hash = laptop
            .client
            .agent_creation_store()?
            .load(&status.request_id)?
            .ok_or("desktop record")?
            .request_hash;
        refused_with(
            laptop.client.agent_creation_decide(
                desk.as_ref(),
                &decide_body(&status.request_id, &hash, Some(true)),
                now()?,
            ),
            "creation_not_primary",
        )?;
        // The primary's stored plan is altered on disk after it was stored: its hash no longer
        // matches. The store itself refuses such a save, so the file is rewritten directly.
        let store = phone.client.agent_creation_store()?;
        let mut plan = ramflux_protocol::custody::decode_register_plan(
            &store.load(&status.request_id)?.ok_or("primary record")?.plan_bytes()?,
        )?;
        plan.display_name = "Altered agent".into();
        let file = store
            .root()
            .join("custody_accounts")
            .join(phone.client.account_db()?.local_account_id.clone())
            .join("agent_creation")
            .join(format!("{}.json", status.request_id));
        let mut json: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
        json["plan_b64"] = serde_json::Value::String(ramflux_protocol::encode_base64url(
            ramflux_protocol::custody::encode_register_plan(&plan)?,
        ));
        std::fs::write(&file, serde_json::to_vec(&json)?)?;
        let primary = vault_of(&phone.client)?;
        refused_with(
            phone.client.agent_creation_decide(
                primary.as_ref(),
                &decide_body(&status.request_id, &hash, Some(true)),
                now()?,
            ),
            "creation_plan_changed",
        )
    })
}

#[test]
fn an_agent_sync_packet_cannot_start_a_creation() -> TestResult {
    let (mut phone, mut laptop) = pair("sync-start")?;
    block_on(async {
        let owner = phone.client.own_account_anchor()?;
        let target = laptop.client.owned_device_identity()?;
        let agent = ramflux_protocol::encode_base64url([8_u8; 32]);
        for (correlation, value) in [
            ("sync-plan", g::agent_custody_packet::Value::RequestJson(b"{}".to_vec())),
            ("sync-decision", g::agent_custody_packet::Value::DecisionJson(b"{}".to_vec())),
        ] {
            phone.client.stage_agent_custody(AgentCustodySend {
                target: &target,
                owner_anchor: &owner,
                agent_anchor: &agent,
                correlation_id: correlation,
                custody: g::AgentCustodyPacket { value: Some(value) },
                now: now()?,
            })?;
            let gateway = RecordingGateway::new(Arc::default());
            let attempted = gateway.attempted.clone();
            let engine = GatewaySessionEngine::with_test_transport(
                phone.gateway_config.clone(),
                Box::new(gateway),
            );
            phone.install_test_session(engine);
            assert_eq!(own_device_copy::flush(&mut phone).await?, 1);
            let packet =
                attempted.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
            let entry = GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 9,
                target_delivery_id: packet.target_delivery_id.clone(),
                envelope: packet,
            };
            assert!(
                receive_copy(&mut laptop.client, &laptop.gateway_config, &entry).await.is_err(),
                "an agent_sync custody packet without a stored plan refuses on the desktop"
            );
        }
        assert!(
            laptop.client.agent_creation_store()?.pending()?.is_empty(),
            "no creation request exists on the desktop after agent_sync packets"
        );
        Ok(())
    })
}
