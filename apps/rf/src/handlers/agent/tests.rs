// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Argument parsing and body shaping of `rf agent` (AGENT-IDENTITY-01 E5). The bus is not opened.
use super::request_of;
use crate::cli::{AgentAction, Cli, Command};
use clap::Parser;
use serde_json::Value;

/// Parses `rf agent --account alice <rest>` and returns the action.
fn action(rest: &[&str]) -> Result<AgentAction, clap::Error> {
    let mut args = vec!["rf", "agent", "--account", "alice"];
    args.extend_from_slice(rest);
    let cli = Cli::try_parse_from(args)?;
    let Command::Agent(command) = cli.command else {
        panic!("test: the agent command was not parsed");
    };
    Ok(command.action)
}

fn shaped(rest: &[&str]) -> Result<(&'static str, Value), Box<dyn std::error::Error>> {
    Ok(request_of(action(rest)?)?)
}

const PERSONA: [&str; 4] = ["--name", "Helper", "--responsibility", "answers"];

#[test]
fn create_sends_the_persona_and_access_and_confirmation_only_when_confirmed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut create = vec!["create"];
    create.extend_from_slice(&PERSONA);
    create.extend_from_slice(&["--provider", "provider-a", "--model", "model-a"]);
    create.extend_from_slice(&["--dm", "contacts", "--allowed-human", "bob"]);
    let (method, body) = shaped(&create)?;
    assert_eq!(method, "agent.create");
    assert_eq!(body["persona"]["name"], "Helper");
    assert_eq!(body["access"]["dm"], "contacts", "the access policy is passed through");
    assert_eq!(body["access"]["allowed_humans"][0], "bob");
    assert_eq!(body["config"]["provider"], "provider-a", "the creation request carries the provider");
    assert_eq!(body["config"]["model"], "model-a", "and the model: the SDK refuses without them");
    assert_eq!(body["role"], "named", "the default role");
    assert!(body.get("confirmed").is_none(), "no confirmation without --confirm");

    create.push("--confirm");
    let (_, confirmed) = shaped(&create)?;
    assert_eq!(confirmed["confirmed"], true, "--confirm sends the owner's confirmation");
    Ok(())
}

#[test]
fn decide_requires_the_approval_and_sends_it() -> Result<(), Box<dyn std::error::Error>> {
    let refused = Cli::try_parse_from([
        "rf",
        "agent",
        "--account",
        "alice",
        "decide",
        "--request-id",
        "r",
        "--request-hash",
        "h",
    ]);
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(clap::error::ErrorKind::MissingRequiredArgument),
        "approved is mandatory"
    );
    let (method, body) =
        shaped(&["decide", "--request-id", "r", "--request-hash", "h", "--approved", "false"])?;
    assert_eq!(method, "agent.creation.decide");
    assert_eq!(body["approved"], false, "a denial is sent as a denial");
    assert_eq!(body["request_hash"], "h");
    Ok(())
}

#[test]
fn list_starts_at_the_first_page() -> Result<(), Box<dyn std::error::Error>> {
    let (method, body) = shaped(&["list"])?;
    assert_eq!(method, "agent.list");
    assert_eq!(body["limit"], 50);
    assert!(body["cursor"].is_null(), "no cursor on the first page");
    let (_, next) = shaped(&["list", "--cursor", "agent-7", "--limit", "5"])?;
    assert_eq!(next["cursor"], "agent-7");
    Ok(())
}

#[test]
fn show_status_and_delete_name_their_methods() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(shaped(&["show", "--agent", "a1"])?.0, "agent.get");
    assert_eq!(shaped(&["status", "--operation-id", "op"])?.0, "agent.operation.get");
    let (method, body) = shaped(&["delete", "--agent", "a1"])?;
    assert_eq!(method, "agent.delete");
    assert!(body.get("confirmed").is_none(), "delete without --confirm is not confirmed");
    assert_eq!(shaped(&["delete", "--agent", "a1", "--confirm"])?.1["confirmed"], true);
    Ok(())
}

#[test]
fn edit_and_access_carry_their_confirmation_and_base() -> Result<(), Box<dyn std::error::Error>> {
    let mut edit = vec!["edit", "--agent", "a1"];
    edit.extend_from_slice(&PERSONA);
    let (method, body) = shaped(&edit)?;
    assert_eq!(method, "agent.persona.edit");
    assert!(body.get("confirmed").is_none());
    assert_eq!(body["persona"]["responsibility"], "answers");

    let base = r#"{"id":"AQ","conversation_id":"agent-record:a1","hlc":5,"device_sequence":2}"#;
    let (method, access) = shaped(&["access", "--agent", "a1", "--base", base, "--confirm"])?;
    assert_eq!(method, "agent.access.set");
    assert_eq!(access["base"]["hlc"], 5, "the base is the identity object as given");
    assert_eq!(access["confirmed"], true);
    assert_eq!(access["access"]["dm"], "owner", "the default policy");
    Ok(())
}

#[test]
fn access_refuses_a_base_that_is_not_an_identity_object() {
    let refused = shaped(&["access", "--agent", "a1", "--base", "[1,2]"]);
    assert!(refused.is_err(), "an array is not an identity");
    assert!(shaped(&["access", "--agent", "a1", "--base", "not json"]).is_err());
}

#[test]
fn no_body_carries_a_secret_field() -> Result<(), Box<dyn std::error::Error>> {
    let samples: [&[&str]; 5] = [
        &["create", "--name", "n", "--responsibility", "r", "--provider", "p", "--model", "m"],
        &["decide", "--request-id", "r", "--request-hash", "h", "--approved", "true"],
        &["delete", "--agent", "a1", "--confirm"],
        &["status", "--operation-id", "op"],
        &["pending"],
    ];
    for rest in samples {
        let (_, body) = shaped(rest)?;
        let text = body.to_string().to_ascii_lowercase();
        for word in ["secret", "passphrase", "phrase", "password", "private", "api_key"] {
            assert!(!text.contains(word), "{word} must not be sent by {rest:?}");
        }
    }
    Ok(())
}

#[test]
fn create_without_a_provider_or_model_does_not_parse() {
    let refused = Cli::try_parse_from([
        "rf", "agent", "--account", "alice", "create", "--name", "n", "--responsibility", "r",
        "--confirm",
    ]);
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(clap::error::ErrorKind::MissingRequiredArgument),
        "the CLI never sends a creation the SDK would refuse with metadata_pending"
    );
}

#[test]
fn pending_asks_for_the_next_request_with_an_empty_operation_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (method, body) = shaped(&["pending"])?;
    assert_eq!(method, "agent.operation.get");
    assert_eq!(body["operation_id"], "");
    Ok(())
}

#[test]
fn the_review_names_what_the_owner_decides_and_the_hash_decide_repeats()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_protocol::custody::{decode_register_plan, encode_register_plan, register_plan_hash};
    let plan = sample_plan();
    let bytes = encode_register_plan(&plan)?;
    use base64::Engine as _;
    let standard = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let review = super::review_of(&serde_json::json!({ "requestJson": standard }))
        .ok_or("the review is built from the plan")?;
    assert_eq!(review["agent_name"], plan.display_name);
    assert_eq!(review["provider"], plan.profile.provider);
    assert_eq!(review["model"], plan.profile.model);
    assert_eq!(review["request_hash"], register_plan_hash(&decode_register_plan(&bytes)?)?);
    assert!(review.to_string().find("secret").is_none(), "the review carries no secret");
    assert!(super::review_of(&serde_json::json!({})).is_none(), "no plan, no review");
    Ok(())
}

fn sample_plan() -> ramflux_protocol::custody::RegisterPlan {
    use ramflux_protocol::custody::{
        AGENT_REGISTER_VERSION, AgentRegisterProfile, DeviceRef, GENESIS_BRANCH_CAPABILITIES,
        REGISTER_PLAN_SCHEMA, RegisterPlan, RegisterPurpose,
    };
    let key = |byte: u8| ramflux_protocol::encode_base64url([byte; 32]);
    let device = |anchor: u8, id: &str| DeviceRef {
        account_anchor: key(anchor),
        device_id: id.to_owned(),
        device_epoch: 1,
    };
    RegisterPlan {
        schema: REGISTER_PLAN_SCHEMA.to_owned(),
        version: AGENT_REGISTER_VERSION,
        request_id: "req-1".to_owned(),
        purpose: RegisterPurpose::Create,
        owner_anchor: key(1),
        human_head_hash: key(2),
        human_primary: device(1, "phone"),
        desktop: device(1, "desktop"),
        agent_anchor: key(3),
        principal_id: "principal-agent".to_owned(),
        agent_device: device(3, "agent-desktop"),
        master_public_key: key(4),
        self_signing_public_key: key(5),
        branch_signing_public_key: key(6),
        agreement_public_key: key(7),
        capabilities: GENESIS_BRANCH_CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
        display_name: "Helper".to_owned(),
        certificate_issued_at: 1_800_000_000,
        branch_not_before: 1_800_000_000,
        branch_expires_at: 1_800_086_400,
        master_cert_id: "master-cert-1".to_owned(),
        branch_cert_id: "branch-cert-1".to_owned(),
        profile: AgentRegisterProfile {
            responsibility: "Answers questions".to_owned(),
            provider: "provider".to_owned(),
            model: "model".to_owned(),
            persona_version: 1,
            persona_hash: key(8),
            profile_epoch: 1,
        },
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
        previous_agent_head_hash: None,
        previous_master_certificate_hash: None,
        next_range: 1,
    }
}
