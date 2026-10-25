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
