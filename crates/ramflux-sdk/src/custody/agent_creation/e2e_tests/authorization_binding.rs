// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `agent_creation_authorization_binding` (contract 7.2 and 7.4, decision r14). An approved request
//! is bound to its exact plan, signer, owner, device and epoch, human head, keys, capability,
//! decision identity and signature, and a remote packet confirms nothing by its own flag.
//! SDK-side refusals run the production machine, client and store code on the desktop and phone
//! roots. Node-side refusals run the real admission over TLS through `connect_for_proof` and
//! `prove`; the node's full input matrix already exists in `node-core`
//! (`custody_service/admission/agent_publish_tests.rs`) and is not repeated here.
//! The primary phone is the native fixture of `test_support`, not a network-paired device.
use super::super::test_support::{
    OwnRouter, Pair, TestNode, TestResult, assert_items_gone, assert_items_present,
    assert_no_account, capable, decide_body, desk_create, desk_record, now, pair, phone_decides,
    primary_decision_as, root_of, store_of, vault_of,
};
use crate::SdkError;
use crate::custody::CustodyConnection;
use crate::custody::agent_creation::{
    AgentCreationState, AgentFailure, apply_decision, commit_approved,
    first_action, load_publishing, primary_branch_public_key, receive_plan,
    require_agent_custody_authorization,
};
use crate::time::FixedClock;
use ramflux_protocol::custody::{
    CustodyProofAction, CustodyRefusal, CustodyServerFrame, DeviceRef,
    RegisterPlan, RegisterPurpose, decode_register_decision, decode_register_plan,
    encode_register_decision, encode_register_plan, register_plan_hash,
};
use ramflux_protocol::{PrincipalKind, encode_base64url};

fn scenario(case: impl std::future::Future<Output = TestResult>) -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(crate::bus::credentials::contract_tests::deadline(Box::pin(case)))
}

/// The desktop store of the human account of `pair`.
fn desk_store(pair: &Pair) -> TestResult<crate::custody::agent_creation::AgentCreationStore> {
    let human = pair.laptop.client.account_db()?.local_account_id.clone();
    Ok(store_of(&root_of(&pair.laptop)?, &human)?)
}

/// The on-disk file of one creation record of the desktop (`agent_creation/<request>.json`).
fn record_file(pair: &Pair, request_id: &str) -> TestResult<std::path::PathBuf> {
    let human = pair.laptop.client.account_db()?.local_account_id.clone();
    let path = root_of(&pair.laptop)?
        .join("custody_accounts")
        .join(human)
        .join("agent_creation")
        .join(format!("{request_id}.json"));
    if !path.exists() {
        return Err(format!("test: the desktop record file is at {}", path.display()).into());
    }
    Ok(path)
}

/// Every plan field, each changed on its own. Changing any one of them must break the bind
/// between the approved decision and the stored plan.
fn plan_mutations(plan: &RegisterPlan) -> Vec<(&'static str, RegisterPlan)> {
    let mut mutated = Vec::new();
    let mut push = |name: &'static str, change: fn(&mut RegisterPlan)| {
        let mut changed = plan.clone();
        change(&mut changed);
        mutated.push((name, changed));
    };
    push("schema", |p| p.schema.push('x'));
    push("version", |p| p.version += 1);
    push("request_id", |p| p.request_id.push('x'));
    push("purpose", |p| {
        p.purpose = match p.purpose {
            RegisterPurpose::Create => RegisterPurpose::Rebind,
            RegisterPurpose::Rebind => RegisterPurpose::Create,
        }
    });
    push("owner_anchor", |p| p.owner_anchor = encode_base64url([0x51; 32]));
    push("human_head_hash", |p| p.human_head_hash = encode_base64url([0x52; 32]));
    push("human_primary", |p| p.human_primary.device_id.push('x'));
    push("desktop", |p| p.desktop.device_id.push('x'));
    push("agent_anchor", |p| p.agent_anchor = encode_base64url([0x53; 32]));
    push("principal_id", |p| p.principal_id.push('x'));
    push("agent_device", |p| p.agent_device.device_id.push('x'));
    push("master_public_key", |p| p.master_public_key = encode_base64url([0x54; 32]));
    push("self_signing_public_key", |p| p.self_signing_public_key = encode_base64url([0x55; 32]));
    push("branch_signing_public_key", |p| {
        p.branch_signing_public_key = encode_base64url([0x56; 32]);
    });
    push("agreement_public_key", |p| p.agreement_public_key = encode_base64url([0x57; 32]));
    push("capabilities", |p| p.capabilities.push("extra".into()));
    push("display_name", |p| p.display_name.push('x'));
    push("certificate_issued_at", |p| p.certificate_issued_at += 1);
    push("branch_not_before", |p| p.branch_not_before += 1);
    push("branch_expires_at", |p| p.branch_expires_at += 1);
    push("master_cert_id", |p| p.master_cert_id.push('x'));
    push("branch_cert_id", |p| p.branch_cert_id.push('x'));
    push("profile", |p| p.profile.responsibility.push('x'));
    push("issued_at", |p| p.issued_at += 1);
    push("expires_at", |p| p.expires_at += 1);
    push("previous_agent_head_hash", |p| {
        p.previous_agent_head_hash = Some(encode_base64url([0x58; 32]));
    });
    push("previous_master_certificate_hash", |p| {
        p.previous_master_certificate_hash = Some(encode_base64url([0x59; 32]));
    });
    push("next_range", |p| p.next_range += 1);
    mutated
}

#[test]
fn every_altered_plan_field_after_approval_is_refused_by_the_desktop_store() -> TestResult {
    let mut pair = pair("binding-fields")?;
    scenario(altered_fields_case(&mut pair))
}

/// The desktop holds an approved request. Each altered plan field, written to the record file
/// with the approval kept, is refused by the store's own consistency check that every read runs.
async fn altered_fields_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let store = desk_store(pair)?;
    let approved = desk_record(pair, &record.request_id)?;
    assert_eq!(approved.state, AgentCreationState::Authorized);
    let file = record_file(pair, &record.request_id)?;
    let original = std::fs::read(&file)?;
    let plan = decode_register_plan(&approved.plan_bytes()?)?;
    let mutations = plan_mutations(&plan);
    assert_eq!(mutations.len(), 28, "every field of the 28-field plan is covered");
    for (name, changed) in &mutations {
        let mut altered = approved.clone();
        altered.plan_b64 = encode_base64url(
            ramflux_protocol::canonical_json_bytes(changed).map_err(|_| "test: the plan serialises")?,
        );
        std::fs::write(&file, serde_json::to_vec(&altered)?)?;
        assert!(store.load(&record.request_id).is_err(), "an altered `{name}` is refused");
    }
    std::fs::write(&file, &original)?;
    assert_eq!(desk_record(pair, &record.request_id)?.state, AgentCreationState::Authorized);
    Ok(())
}

#[test]
fn a_decision_for_another_request_a_forged_signature_and_a_swapped_key_are_refused() -> TestResult {
    let mut pair = pair("binding-decision")?;
    scenario(decision_case(&mut pair))
}

/// One desktop, two requests. The phone approves the first; its decision is then offered to the
/// second request (replay), with a forged signature and with a different primary key. Each is
/// refused, and the genuine decision for the first request is accepted.
async fn decision_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let at = now()?;
    let first = desk_create(pair, vault.as_ref(), at)?;
    let router = OwnRouter::new()?;
    router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let hash = first.request_hash.clone();
    let fixture = pair.phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&hash)?;
    pair.phone.client.agent_creation_decide(
        phone_vault.as_ref(),
        &decide_body(&first.request_id, &hash, Some(true)),
        now()?,
    )?;
    let phone_store = store_of(&root_of(&pair.phone)?, &pair.phone.client.account_db()?.local_account_id)?;
    let decision = phone_store.load(&first.request_id)?.ok_or("test: the phone decision")?.decision_bytes()?.ok_or("test: the decision is saved")?;
    let second = desk_create(pair, vault.as_ref(), at)?;
    let store = desk_store(pair)?;
    let plan = decode_register_plan(&first.plan_bytes()?)?;
    let key = primary_branch_public_key(pair.laptop.client.born_v3_account.as_deref().ok_or("test: the human record")?.record(), &plan.human_primary, now()?)?;
    let at_decision = now()?;

    let replayed = apply_decision(&store, vault.as_ref(), &second.request_id, &decision, &key, at_decision);
    assert!(replayed.is_err(), "a decision for one request is not accepted for another");
    assert_eq!(desk_record(pair, &second.request_id)?.state, AgentCreationState::AuthorizationPending);

    let forger_key = ramflux_crypto::create_device_branch_from_seed("forger", "forger-device", 1, &[0x66; 32]);
    let genuine = decode_register_decision(&decision)?;
    let forged_envelope =
        ramflux_crypto::custody::sign_register_decision(&forger_key, genuine.body.clone())?;
    let forged_bytes = encode_register_decision(&forged_envelope)?;
    assert!(apply_decision(&store, vault.as_ref(), &first.request_id, &forged_bytes, &key, at_decision).is_err());

    let swapped = encode_base64url([0x42; 32]);
    assert!(apply_decision(&store, vault.as_ref(), &first.request_id, &decision, &swapped, at_decision).is_err());
    assert_eq!(desk_record(pair, &first.request_id)?.state, AgentCreationState::AuthorizationPending);

    let accepted = apply_decision(&store, vault.as_ref(), &first.request_id, &decision, &key, at_decision)?;
    assert_eq!(accepted.state, AgentCreationState::Authorized, "the genuine decision authorizes");
    Ok(())
}

#[test]
fn only_the_plan_primary_device_can_sign_a_decision() -> TestResult {
    let mut pair = pair("binding-signer")?;
    signer_case(&mut pair)
}

/// The secondary desktop cannot approve (client refusal `creation_not_primary`). A decision signed
/// for a different owner, device or epoch than the plan's primary is refused by the signing itself;
/// the plan's own primary is accepted with the same armed approval.
fn signer_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let refused = pair.laptop.client.agent_creation_decide(
        vault.as_ref(),
        &decide_body(&record.request_id, &record.request_hash, Some(true)),
        at,
    );
    assert!(
        matches!(refused, Err(SdkError::AgentCreationRefused("creation_not_primary"))),
        "the secondary never approves: {refused:?}"
    );
    let plan_bytes = record.plan_bytes()?;
    let plan = decode_register_plan(&plan_bytes)?;
    let phone_root = root_of(&pair.phone)?;
    let fixture = pair.phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&record.request_hash)?;
    let mut wrong_owner = plan.human_primary.clone();
    wrong_owner.account_anchor = encode_base64url([0x71; 32]);
    let mut wrong_device = plan.human_primary.clone();
    wrong_device.device_id.push('x');
    let mut wrong_epoch = plan.human_primary.clone();
    wrong_epoch.device_epoch += 1;
    let desktop: DeviceRef = plan.desktop.clone();
    for signer in [&wrong_owner, &wrong_device, &wrong_epoch, &desktop] {
        let signed = primary_decision_as(&pair.phone, &phone_root, &plan_bytes, signer, at);
        assert!(signed.is_err(), "a decision for {signer:?} is not the plan's primary");
    }
    let primary = primary_decision_as(&pair.phone, &phone_root, &plan_bytes, &plan.human_primary, at);
    assert!(primary.is_ok(), "the plan's own primary signs with the same approval");
    Ok(())
}

#[test]
fn a_stale_human_head_refuses_the_commit_and_closes_the_request() -> TestResult {
    let mut pair = pair("binding-head")?;
    scenario(stale_head_case(&mut pair))
}

/// The plan names a human head that is not the current one. The commit refuses, the request
/// closes as `creation_primary_changed`, its pending items are deleted and no account exists.
async fn stale_head_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let store = desk_store(pair)?;
    let approved = desk_record(pair, &record.request_id)?;
    let before = approved.vault_refs.clone();
    let mut plan = decode_register_plan(&approved.plan_bytes()?)?;
    assert_items_present(vault.as_ref(), &plan, &before);
    plan.human_head_hash = encode_base64url([0x72; 32]);
    let mut stale = approved.clone();
    stale.plan_b64 = encode_base64url(encode_register_plan(&plan)?);
    stale.request_hash = register_plan_hash(&plan)?;
    store.save(&stale)?;
    let human = pair.laptop.client.account_db()?.local_account_id.clone();
    let refused = commit_approved(&store, vault.as_ref(), &human, &record.request_id, &capable(), now()?);
    assert!(refused.is_err(), "a stale human head is not committed");
    let closed = store.load(&record.request_id)?.ok_or("test: the closed record")?;
    assert_eq!(closed.state, AgentCreationState::Refused);
    assert_eq!(closed.failure, Some(AgentFailure::CreationPrimaryChanged));
    assert_items_gone(vault.as_ref(), &plan, &before, &closed);
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    assert_no_account(&root_of(&pair.laptop)?, &agent_id, now()?);
    Ok(())
}

#[test]
fn commit_without_the_agent_custody_capability_has_no_effect() -> TestResult {
    let mut pair = pair("binding-capability")?;
    scenario(capability_case(&mut pair))
}

/// The selected node does not advertise `agent_custody_authorization_v1` (or advertises another
/// name). The commit is a typed unsupported refusal before any write: the request stays
/// `authorized` and no agent account exists.
async fn capability_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let store = desk_store(pair)?;
    let human = pair.laptop.client.account_db()?.local_account_id.clone();
    let root = root_of(&pair.laptop)?;
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    let empty: Vec<String> = Vec::new();
    let other = vec!["agent_custody_authorization_v0".to_owned()];
    for advertised in [&empty, &other] {
        assert!(require_agent_custody_authorization(advertised).is_err());
        let refused = commit_approved(&store, vault.as_ref(), &human, &record.request_id, advertised, now()?);
        assert!(matches!(refused, Err(SdkError::AgentCustodyUnsupported)), "{refused:?}");
        assert_eq!(desk_record(pair, &record.request_id)?.state, AgentCreationState::Authorized);
        assert_no_account(&root, &agent_id, now()?);
    }
    Ok(())
}

#[test]
fn a_plain_or_tampered_publication_is_refused_by_the_sdk_and_the_node() -> TestResult {
    let mut pair = pair("binding-node")?;
    scenario(node_case(&mut pair))
}

/// The committed agent account, reached through the real admission. A plain `Publish` of the
/// headless record is refused as authorization required (and refused locally by `first_action`
/// without a saved approval). Tampered `AgentPublish` actions are refused: a bad plan hash
/// (`InvalidInput`), a decision signed as if by the agent branch (`BindingRefused`), and an
/// expired decision (`InvalidInput`). Then the untouched action is admitted with a receipt.
async fn node_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    phone_decides(pair, &OwnRouter::new()?, &record, true, now()?).await?;
    let phone_root = root_of(&pair.phone)?;
    let phone_id = pair.phone.client.account_db()?.local_account_id.clone();
    let phone_device = pair.phone.client.owned_device_identity()?.device_id().to_owned();
    let laptop_root = root_of(&pair.laptop)?;
    let human = pair.laptop.client.account_db()?.local_account_id.clone();
    let agent_id = record.account_id.clone().ok_or("test: the request reserves its account")?;
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let node = TestNode::start(2, None).await?;
    node.publish_current(&phone_root, &phone_id, &phone_device, phone_vault).await?;
    commit_approved(&desk_store(pair)?, vault.as_ref(), &human, &record.request_id, &capable(), now()?)?;
    let mut proof = CustodyConnection::connect_for_proof(
        node.config(&laptop_root, &agent_id, &plan.agent_device.device_id),
        vault.clone(),
    )
    .await?;
    let publication = proof.account().publication();
    assert!(matches!(
        first_action(PrincipalKind::HeadlessAi, None, &publication),
        Err(SdkError::CustodyNetwork(CustodyRefusal::AgentAuthorizationRequired))
    ));
    let plain_result = proof.prove(CustodyProofAction::Publish { publication: Box::new(publication.clone()) }).await;
    assert!(
        matches!(plain_result, Err(SdkError::CustodyNetwork(CustodyRefusal::AgentAuthorizationRequired))),
        "the node refuses a plain publish of a headless record: {plain_result:?}"
    );
    let saved = load_publishing(&laptop_root, proof.account())?.ok_or("the saved approval")?;
    let CustodyProofAction::AgentPublish { publication: pub_box, agent_profile, plan: plan_box, authorization } =
        saved.publish_action(&publication)
    else {
        return Err("test: the saved approval builds an AgentPublish".into());
    };
    let mut bad_hash = (*authorization).clone();
    bad_hash.body.request_hash = encode_base64url([0x21; 32]);
    let bad_hash_action = CustodyProofAction::AgentPublish {
        publication: pub_box.clone(),
        agent_profile: agent_profile.clone(),
        plan: plan_box.clone(),
        authorization: Box::new(bad_hash),
    };
    let refused = proof.prove(bad_hash_action).await;
    assert!(matches!(refused, Err(SdkError::CustodyNetwork(CustodyRefusal::InvalidInput))), "{refused:?}");
    let (_, agent_credentials) =
        proof.account().credentials(vault.as_ref(), &plan.agent_device.device_id, now()?)?;
    let as_agent = ramflux_crypto::custody::sign_register_decision(
        &agent_credentials.signing,
        authorization.body.clone(),
    )?;
    let non_primary = CustodyProofAction::AgentPublish {
        publication: pub_box.clone(),
        agent_profile: agent_profile.clone(),
        plan: plan_box.clone(),
        authorization: Box::new(as_agent),
    };
    let refused = proof.prove(non_primary).await;
    assert!(matches!(refused, Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused))), "{refused:?}");
    {
        let _clock = FixedClock::set(i64::try_from(plan.expires_at + 1)?);
        let expired = proof
            .prove(CustodyProofAction::AgentPublish {
                publication: pub_box.clone(),
                agent_profile: agent_profile.clone(),
                plan: plan_box.clone(),
                authorization: authorization.clone(),
            })
            .await;
        assert!(matches!(expired, Err(SdkError::CustodyNetwork(CustodyRefusal::InvalidInput))), "{expired:?}");
    }
    let admitted = proof
        .prove(CustodyProofAction::AgentPublish {
            publication: pub_box,
            agent_profile,
            plan: plan_box,
            authorization,
        })
        .await?;
    let CustodyServerFrame::AgentPublished { receipt } = admitted else {
        return Err("test: the untouched action is admitted with a receipt".into());
    };
    assert_eq!(receipt.request_hash, register_plan_hash(&plan)?, "the receipt names the plan");
    drop(proof);
    node.finish().await
}

#[test]
fn remote_packets_cannot_confirm_by_themselves() -> TestResult {
    let mut pair = pair("binding-remote")?;
    remote_confirm_case(&mut pair)
}

/// A plan or a decision that carries its own `confirmed: true` is refused: the signed bodies are
/// strict, so the only approval is the primary's signature over the exact plan.
fn remote_confirm_case(pair: &mut Pair) -> TestResult {
    let vault = vault_of(&pair.laptop.client)?;
    let at = now()?;
    let record = desk_create(pair, vault.as_ref(), at)?;
    let plan_bytes = record.plan_bytes()?;
    let mut with_flag: serde_json::Value = serde_json::from_slice(&plan_bytes)?;
    with_flag["confirmed"] = true.into();
    let phone_store = store_of(&root_of(&pair.phone)?, &pair.phone.client.account_db()?.local_account_id)?;
    assert!(receive_plan(&phone_store, &serde_json::to_vec(&with_flag)?, at).is_err());
    assert!(phone_store.load(&record.request_id)?.is_none(), "the phone stores nothing");
    let hash = record.request_hash.clone();
    let fixture = pair.phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&hash)?;
    let signed = primary_decision_as(&pair.phone, &root_of(&pair.phone)?, &plan_bytes, &decode_register_plan(&plan_bytes)?.human_primary, at)?;
    let mut body_flag: serde_json::Value = serde_json::from_slice(&signed)?;
    body_flag["body"]["confirmed"] = true.into();
    let store = desk_store(pair)?;
    let key = primary_branch_public_key(pair.laptop.client.born_v3_account.as_deref().ok_or("test: the human record")?.record(), &decode_register_plan(&plan_bytes)?.human_primary, at)?;
    assert!(apply_decision(&store, vault.as_ref(), &record.request_id, &serde_json::to_vec(&body_flag)?, &key, at).is_err());
    assert_eq!(desk_record(pair, &record.request_id)?.state, AgentCreationState::AuthorizationPending);
    Ok(())
}
