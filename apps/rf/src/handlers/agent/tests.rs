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
    create.extend_from_slice(&["--dm", "contacts", "--allowed-human", "bob"]);
    let (method, body) = shaped(&create)?;
    assert_eq!(method, "agent.create");
    assert_eq!(body["persona"]["name"], "Helper");
    assert_eq!(body["access"]["dm"], "contacts", "the access policy is passed through");
    assert_eq!(body["access"]["allowed_humans"][0], "bob");
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
    let samples: [&[&str]; 4] = [
        &["create", "--name", "n", "--responsibility", "r"],
        &["decide", "--request-id", "r", "--request-hash", "h", "--approved", "true"],
        &["delete", "--agent", "a1", "--confirm"],
        &["status", "--operation-id", "op"],
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
