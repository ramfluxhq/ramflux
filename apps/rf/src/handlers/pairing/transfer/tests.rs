// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! CLI intent is explicit; neither private phrase nor restored SAS approval is an argument.
use super::*;
use clap::Parser;
#[test]
fn pairing_transfer_cli_has_explicit_full_intent_and_separate_candidate_affirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let base = [
        "rf",
        "transfer",
        "--account",
        "a",
        "begin",
        "--display-name",
        "phone",
        "--lease-not-before",
        "1",
        "--lease-expires-at",
        "100",
        "--invitation-out",
        "private-invitation",
    ];
    let parsed = crate::cli::Cli::try_parse_from(base)?;
    let crate::cli::Command::Transfer(command) = parsed.command else {
        return Err("test: missing transfer verb".into());
    };
    let (request, _) = begin_request(command.action)?;
    assert_eq!(request.version, 3, "test: full transfer fell back to selected-key v2 intent");
    assert_eq!(request.recipient_mode, "new", "test: new destination intent was lost");
    assert!(
        request.destination_ref.is_none(),
        "test: new destination received a foreign linked reference"
    );
    let mut incomplete = base.to_vec();
    incomplete.extend(["--destination-device", "linked", "--destination-epoch", "1"]);
    assert!(
        crate::cli::Cli::try_parse_from(incomplete).is_err(),
        "test: linked destination accepted an unqualified device id"
    );
    let missing = [
        "rf",
        "transfer",
        "--account",
        "a",
        "affirm",
        "--operation-id",
        "op",
        "--generation",
        "1",
        "--transcript-hash",
        "th",
        "--new-record-hash",
        "candidate",
    ];
    assert!(
        crate::cli::Cli::try_parse_from(missing).is_err(),
        "test: source affirmation defaulted to positive approval"
    );
    let mut explicit = missing.to_vec();
    explicit.extend(["--approved", "false"]);
    assert!(
        crate::cli::Cli::try_parse_from(&explicit).is_ok(),
        "test: explicit negative source approval was rejected by CLI grammar"
    );
    explicit.extend(["--phrase", "must-not-be-an-argument"]);
    assert!(
        crate::cli::Cli::try_parse_from(explicit).is_err(),
        "test: private phrase was accepted in argv"
    );
    Ok(())
}
