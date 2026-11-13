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

#[test]
fn pairing_owned_registry_reopens_and_refuses_replaced_files() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-pair-registry-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&root)?;
    let socket = root.join("bus.sock");
    let operation = ramflux_protocol::encode_base64url([19; 32]);
    let intended = root.join("invitation");
    let mut output = InvitationOutput::create(intended.clone())?;
    output.commit(b"invitation-private-canary")?;
    registry::Registry::open(&socket)?.register(&operation, &output)?;
    let sidecar = root.join("invitation.op");
    assert_eq!(std::fs::read(&sidecar)?, operation.as_bytes());
    let saved = root.join("original");
    std::fs::rename(&intended, &saved)?;
    std::fs::write(&intended, b"unrelated same-path replacement")?;
    assert!(registry::Registry::open(&socket)?.cleanup(&operation).is_err());
    assert_eq!(std::fs::read(&intended)?, b"unrelated same-path replacement");
    assert!(sidecar.exists());
    std::fs::remove_file(&intended)?;
    std::os::unix::fs::symlink(&saved, &intended)?;
    assert!(registry::Registry::open(&socket)?.cleanup(&operation).is_err());
    assert!(saved.exists());
    std::fs::remove_file(&intended)?;
    std::fs::rename(&saved, &intended)?;
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    assert!(!intended.exists());
    assert!(!sidecar.exists());
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    let joined = root.join("joined");
    let mut output = InvitationOutput::create(joined.clone())?;
    output.commit(b"joined bearer")?;
    registry::Registry::open(&socket)?.register(&operation, &output)?;
    registry::JoinedFile::open(&joined)?.remove()?;
    assert!(!joined.exists());
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    assert!(!root.join("joined.op").exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
