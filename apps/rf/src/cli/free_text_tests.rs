// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Free text accepts hyphens while administrative tokens keep explicit parsing.
use super::*;
use clap::CommandFactory;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Case {
    path: &'static [&'static str],
    selectors: &'static [&'static str],
    flag: &'static str,
    text: &'static str,
}

#[test]
fn free_text_hyphen_values_are_preserved_in_split_and_equals_forms() -> TestResult {
    let cases = [
        Case {
            path: &["dm", "send"],
            selectors: &[
                "--account",
                "alice",
                "--conversation",
                "thread",
                "--message",
                "message",
                "--envelope",
                "envelope",
                "--source-principal",
                "alice",
                "--sender",
                "alice",
                "--target",
                "bob",
            ],
            flag: "body",
            text: "-1",
        },
        Case {
            path: &["group", "send"],
            selectors: &[
                "--account",
                "alice",
                "--group",
                "group",
                "--conversation",
                "thread",
                "--message",
                "message",
                "--sender",
                "alice",
            ],
            flag: "body",
            text: "--message-starts-with-hyphens",
        },
        Case {
            path: &["group", "rename"],
            selectors: &["--account", "alice", "--group", "group"],
            flag: "name",
            text: "-team",
        },
    ];
    for case in cases {
        for equals in [false, true] {
            let mut args = vec!["rf".to_owned()];
            args.extend(case.path.iter().chain(case.selectors).map(ToString::to_string));
            if equals {
                args.push(format!("--{}={}", case.flag, case.text));
            } else {
                args.push(format!("--{}", case.flag));
                args.push(case.text.into());
            }
            let matches = Cli::command().try_get_matches_from(args)?;
            let mut selected = &matches;
            for component in case.path {
                selected = selected.subcommand_matches(component).ok_or("subcommand")?;
            }
            assert_eq!(selected.get_one::<String>(case.flag).map(String::as_str), Some(case.text));
        }
    }
    Ok(())
}

fn admin_peer_args(selected: &str, equals: bool) -> Vec<String> {
    let mut args = vec!["rf".into(), "admin".into(), "federation".into(), "peer".into()];
    for (flag, normal) in [
        ("node-a-admin-url", "https://a.example"),
        ("node-a-token", "token-a"),
        ("node-a-id", "node-a"),
        ("node-a-well-known-url", "https://a.example"),
        ("node-b-admin-url", "https://b.example"),
        ("node-b-token", "token-b"),
        ("node-b-id", "node-b"),
        ("node-b-well-known-url", "https://b.example"),
    ] {
        let value = if flag == selected { "-token" } else { normal };
        if equals && flag == selected {
            args.push(format!("--{flag}={value}"));
        } else {
            args.extend([format!("--{flag}"), value.into()]);
        }
    }
    args
}

fn inspect_admin_tokens(command: &clap::Command) -> usize {
    let mut count = 0;
    for arg in command.get_arguments() {
        if arg.get_long().is_some_and(|name| {
            matches!(
                name,
                "admin-token" | "federation-admin-token" | "node-a-token" | "node-b-token"
            )
        }) {
            assert!(!arg.is_allow_hyphen_values_set(), "{}: {}", command.get_name(), arg.get_id());
            count += 1;
        }
    }
    count + command.get_subcommands().map(inspect_admin_tokens).sum::<usize>()
}

#[test]
fn free_text_admin_tokens_keep_explicit_value_parsing() -> TestResult {
    Cli::try_parse_from(admin_peer_args("", false))?;
    for flag in ["node-a-token", "node-b-token"] {
        let error = Cli::try_parse_from(admin_peer_args(flag, false))
            .err()
            .ok_or("split token accepted")?;
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        Cli::try_parse_from(admin_peer_args(flag, true))?;
    }
    let mut command = Cli::command();
    command.build();
    assert!(inspect_admin_tokens(&command) >= 2);
    Ok(())
}
