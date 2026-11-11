// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use clap::Parser;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_cli_keeps_bearers_out_of_argv_and_requires_explicit_confirmation() {
    assert!(
        crate::cli::Cli::try_parse_from([
            "rf",
            "pairing",
            "--account",
            "a",
            "join",
            "--display-name",
            "B",
            "--token",
            "bearer"
        ])
        .is_err()
    );
    let mut confirm = vec![
        "rf",
        "pairing",
        "--account",
        "a",
        "confirm",
        "--operation-id",
        "op",
        "--generation",
        "1",
        "--transcript-hash",
        "hash",
    ];
    assert!(crate::cli::Cli::try_parse_from(&confirm).is_err());
    confirm.extend(["--matches", "true"]);
    assert!(crate::cli::Cli::try_parse_from(&confirm).is_ok());
}
#[test]
fn pairing_invitation_output_is_private_exclusive_and_cleans_failed_writes() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-pairing-private-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&root)?;
    let pending = root.join("pending");
    {
        let output = InvitationOutput::create(pending.clone())?;
        assert_eq!(output.file.metadata()?.permissions().mode() & 0o777, 0o600);
        assert!(InvitationOutput::create(pending.clone()).is_err());
    }
    assert!(!pending.exists());
    let saved = root.join("saved");
    let mut output = InvitationOutput::create(saved.clone())?;
    output.commit(b"protected bearer fixture")?;
    drop(output);
    assert_eq!(std::fs::read(&saved)?, b"protected bearer fixture");
    let link = root.join("link");
    std::os::unix::fs::symlink(&saved, &link)?;
    assert!(read_invitation(&link).is_err());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
