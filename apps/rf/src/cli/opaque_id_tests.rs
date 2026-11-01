// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opaque base64url selectors remain values even when their first character is a hyphen.
use super::*;
#[test]
fn call_selectors_accept_hyphen_prefixed_ids_in_split_and_equals_forms() -> Result<(), clap::Error>
{
    for verb in ["answer", "reject", "hangup"] {
        Cli::try_parse_from([
            "rf",
            "call",
            verb,
            "--account",
            "bob",
            "--call",
            "-Qsc6qZXSp04Afm7j2ArYQ",
        ])?;
        Cli::try_parse_from([
            "rf",
            "call",
            verb,
            "--account",
            "bob",
            "--call=-Qsc6qZXSp04Afm7j2ArYQ",
        ])?;
    }
    Cli::try_parse_from(["rf", "call", "invite", "--account", "bob", "--conversation", "-thread"])?;
    Ok(())
}
#[test]
fn other_opaque_message_and_surface_selectors_accept_hyphen_prefixed_values()
-> Result<(), clap::Error> {
    Cli::try_parse_from(["rf", "dm", "read", "--account", "bob", "--conversation", "-thread"])?;
    Cli::try_parse_from([
        "rf",
        "surface",
        "get",
        "--account",
        "bob",
        "--surface-id",
        "-surface",
        "--conversation",
        "-thread",
    ])?;
    Cli::try_parse_from([
        "rf",
        "surface",
        "list",
        "--account",
        "bob",
        "--conversation",
        "-thread",
        "--cursor",
        "-cursor",
    ])?;
    Ok(())
}

#[test]
fn itest_legacy_creation_is_a_separate_feature_gated_command() -> Result<(), clap::Error> {
    Cli::try_parse_from(["rf", "account", "create", "--display-name", "Alice"])?;
    Cli::try_parse_from([
        "rf",
        "account",
        "create",
        "--display-name",
        "Service",
        "--kind",
        "headless_ai",
        "--custodian",
        "alice",
    ])?;
    Cli::try_parse_from([
        "rf",
        "account",
        "export-agent-credentials",
        "--account",
        "agent",
        "--out",
        "/tmp/agent.bundle",
    ])?;
    assert!(Cli::try_parse_from(["rf", "account", "create", "--account", "alice"]).is_err());
    let fixture = [
        "rf",
        "account",
        "itest-legacy-create",
        "--account",
        "alice",
        "--principal",
        "alice-principal",
        "--device",
        "alice-device",
        "--target",
        "alice-target",
        "--secret",
        "fixture-secret",
        "--expected-commitment",
        "-abc",
    ];
    if cfg!(feature = "itest-legacy-accounts") {
        Cli::try_parse_from(fixture)?;
    } else {
        assert!(Cli::try_parse_from(fixture).is_err());
    }
    Ok(())
}

#[test]
fn contact_selectors_preserve_hyphen_leading_commitments() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from([
        "rf",
        "contact",
        "safety-number",
        "--account",
        "bob",
        "--contact",
        "-abc",
    ])?;
    assert!(matches!(cli.command, Command::Contact(ContactCommand {
        action: ContactAction::SafetyNumber(selector),
    }) if selector.contact == "-abc"));
    Ok(())
}

fn parse_both(command: &str) -> Result<(), clap::Error> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    Cli::try_parse_from(std::iter::once("rf").chain(words.iter().copied()))?;
    let mut joined = vec!["rf".to_owned()];
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        if word.starts_with("--") {
            if let Some(value) = words.next() {
                joined.push(format!("{word}={value}"));
            } else {
                joined.push(word.to_owned());
            }
        } else {
            joined.push(word.to_owned());
        }
    }
    Cli::try_parse_from(joined)?;
    Ok(())
}

#[test]
fn group_selectors_accept_hyphen_values_for_every_membership_operation() -> Result<(), clap::Error>
{
    for command in [
        "group create --account -abc --group -abc --creator -abc --creator-signing-public-key -abc --creator-target-delivery -abc --member -abc --member-target-delivery -abc --source-node -abc --target-node -abc",
        "group member add --account -abc --group -abc --member-device -abc --member-signing-public-key -abc --member-principal-commitment -abc --target-delivery -abc",
        "group invite create --account -abc --group -abc --actor -abc --invitee-device -abc --invitee-signing-public-key -abc --invitee-principal-commitment -abc --target-delivery -abc --expires-at 100",
        "group invite accept --account -abc --group -abc --actor -abc --invite-id -abc --target-delivery -abc --member-principal-commitment -abc",
        "group role set --account -abc --group -abc --actor -abc --member-device -abc --role member",
        "group send --account -abc --group -abc --conversation -abc --message -abc --sender -abc --body hello --source-principal -abc --envelope -abc --target -abc",
        "group rename --account -abc --group -abc --name title --request-id -abc",
        "group read --account -abc --group -abc --conversation -abc",
    ] {
        parse_both(command)?;
    }
    for verb in ["remove", "kick", "ban"] {
        parse_both(&format!(
            "group member {verb} --account -abc --group -abc --actor -abc --member-device -abc"
        ))?;
    }
    Ok(())
}

#[test]
fn contact_selectors_accept_hyphen_values_for_links_and_federation() -> Result<(), clap::Error> {
    for verb in ["accept", "request"] {
        parse_both(&format!(
            "contact {verb} --account -abc --link -abc --requester -abc --target -abc --conversation -abc --message -abc --envelope -abc --source-principal -abc --sender -abc --recipient-device -abc --target-delivery -abc --federation-url https://node.example --source-node -abc --target-node -abc"
        ))?;
    }
    for verb in ["reject", "block", "unblock", "remove"] {
        parse_both(&format!("contact {verb} --account -abc --link -abc"))?;
    }
    for verb in ["safety-number", "verify", "verification status"] {
        parse_both(&format!("contact {verb} --account -abc --contact -abc"))?;
    }
    parse_both("contact add --account -abc --target -abc --link -abc --requester -abc")?;
    parse_both("contact add --account -abc --card card --replace-provisional-root -abc")?;
    Ok(())
}

macro_rules! selector_group_test {
    ($name:ident, $($command:literal),+ $(,)?) => {
        #[test]
        fn $name() -> Result<(), clap::Error> {
            $(parse_both($command)?;)+
            Ok(())
        }
    };
}
selector_group_test!(
    device_ids_accept_hyphens,
    "device activate --account -abc --device -abc --target -abc --node -abc",
    "device refresh --account -abc --principal-commitment -abc"
);
selector_group_test!(
    dm_ids_accept_hyphens,
    "dm send --account -abc --conversation -abc --message -abc --envelope -abc --source-principal -abc --sender -abc --recipient-device -abc --recipient-principal-commitment -abc --target -abc --body hello --source-node -abc --target-node -abc"
);
selector_group_test!(
    account_ids_accept_hyphens,
    "account status --account -abc",
    "account create --display-name agent --kind headless_ai --custodian -abc"
);
selector_group_test!(
    node_ids_and_public_keys_accept_hyphens,
    "node confirm -abc --pin-source operator --expected-public-key -abc",
    "node custody-init --node-id -abc --node-signing-seed seed --expected-public-key -abc --output-dir output"
);
selector_group_test!(object_ids_accept_hyphens, "object list --account -abc");
selector_group_test!(
    call_account_ids_accept_hyphens,
    "call invite --account -abc --conversation -abc"
);
selector_group_test!(
    bot_ids_accept_hyphens,
    "bot trust add --account -abc --bot -abc --public-key -abc --signing-key-id -abc",
    "bot install --account -abc --manifest manifest --grant grant --consent -abc"
);
selector_group_test!(
    grant_ids_accept_hyphens,
    "grant request --account -abc --grant -abc --server -abc --tool -abc --capability -abc"
);
selector_group_test!(
    mcp_ids_accept_hyphens,
    "mcp server add --account -abc --server -abc --tool -abc --capability -abc"
);
selector_group_test!(keychain_account_ids_accept_hyphens, "keychain status --account -abc");
selector_group_test!(a2i_ids_accept_hyphens, "a2i ack --account -abc --event -abc");
selector_group_test!(
    a2ui_ids_accept_hyphens,
    "a2ui render --account -abc --surface surface --catalog -abc --permission -abc"
);
selector_group_test!(
    surface_ids_accept_hyphens,
    "surface get --account -abc --surface-id -abc --conversation -abc"
);
selector_group_test!(
    admin_node_ids_accept_hyphens,
    "admin federation peer --node-a-id -abc --node-b-id -abc --node-a-admin-url https://a.example --node-b-admin-url https://b.example --node-a-token token --node-b-token token --node-a-well-known-url https://a.example --node-b-well-known-url https://b.example"
);

#[test]
fn every_opaque_string_argument_allows_hyphen_values() {
    use clap::CommandFactory;
    fn inspect(command: &clap::Command) {
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            let opaque = matches!(
                id,
                "account"
                    | "node"
                    | "node_id"
                    | "node_a_id"
                    | "node_b_id"
                    | "custodian"
                    | "principal"
                    | "principal_commitment"
                    | "expected_commitment"
                    | "contact"
                    | "link"
                    | "requester"
                    | "replace_provisional_root"
                    | "creator"
                    | "member"
                    | "actor"
                    | "author"
                    | "tool"
                    | "capability"
                    | "supported_catalog"
                    | "permission"
                    | "consent"
            ) || id.ends_with("_device")
                || id.ends_with("_principal")
                || id.ends_with("_commitment")
                || id.ends_with("_public_key")
                || id.ends_with("_target_delivery")
                || id.ends_with("_node")
                || matches!(id, "target_delivery" | "request_id" | "invite_id");
            if opaque && arg.get_value_parser().type_id() == std::any::TypeId::of::<String>() {
                assert!(arg.is_allow_hyphen_values_set(), "{}: {id}", command.get_name());
            }
        }
        for child in command.get_subcommands() {
            inspect(child);
        }
    }
    let mut command = Cli::command();
    command.build();
    inspect(&command);
    assert!(
        Cli::try_parse_from([
            "rf",
            "contact",
            "safety-number",
            "--account",
            "bob",
            "--contact",
            "-abc",
            "--unknown"
        ])
        .is_err()
    );
}
