// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use clap::Parser;
const MAX_SCRIPT_FRAME_BYTES: usize = 64 * 1024;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().to_path_buf();
    let socket = root.join("bus.sock");
    let operation = ramflux_protocol::encode_base64url([19; 32]);
    let intended = root.join("invitation");
    let mut output = InvitationOutput::create(intended.clone())?;
    output.commit(b"invitation-private-canary")?;
    registry::Registry::open(&socket)?.register(&operation, &output, "a")?;
    let sidecar = root.join("invitation.op");
    assert_eq!(
        std::fs::read(&sidecar)?,
        operation.as_bytes(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    let saved = root.join("original");
    std::fs::rename(&intended, &saved)?;
    std::fs::write(&intended, b"unrelated same-path replacement")?;
    assert!(
        registry::Registry::open(&socket)?.cleanup(&operation).is_err(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    assert_eq!(
        std::fs::read(&intended)?,
        b"unrelated same-path replacement",
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    assert!(
        sidecar.exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    std::fs::remove_file(&intended)?;
    std::os::unix::fs::symlink(&saved, &intended)?;
    assert!(
        registry::Registry::open(&socket)?.cleanup(&operation).is_err(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    assert!(
        saved.exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    std::fs::remove_file(&intended)?;
    std::fs::rename(&saved, &intended)?;
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    assert!(
        !intended.exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    assert!(
        !sidecar.exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    let joined = root.join("joined");
    let mut output = InvitationOutput::create(joined.clone())?;
    output.commit(b"joined bearer")?;
    registry::Registry::open(&socket)?.register(&operation, &output, "a")?;
    registry::JoinedFile::open(&joined)?.remove()?;
    assert!(
        !joined.exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    registry::Registry::open(&socket)?.cleanup(&operation)?;
    assert!(
        !root.join("joined.op").exists(),
        "test: operation-owned cleanup altered ownership or left managed files"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pairing_cli_outcome_exit_codes_preserve_retry_and_refusal_categories() {
    for (value, expected) in [
        (None, 0),
        (Some("InvalidInput"), 2),
        (Some("Busy"), 3),
        (Some("PublicationPending"), 3),
        (Some("SasMismatch"), 4),
        (Some("PrimaryRequired"), 5),
        (Some("UpdateRequired"), 6),
        (Some("VaultUnavailable"), 7),
    ] {
        assert_eq!(
            output::code(value),
            expected,
            "test: operation-owned cleanup altered ownership or left managed files"
        );
    }
    for (error, expected) in [
        (RfError::Sdk(ramflux_sdk::SdkError::PairingCode("Busy")), 3),
        (RfError::Message("never display this input".into()), 1),
    ] {
        let fixed = output::failure(error);
        assert_eq!(
            fixed.to_string(),
            "Pairing command did not complete.",
            "test: operation-owned cleanup altered ownership or left managed files"
        );
        assert!(
            matches!(fixed, RfError::PairingExit { code } if code == expected),
            "test: operation-owned cleanup altered ownership or left managed files"
        );
    }
}

#[tokio::test]
async fn pairing_registry_fresh_process_helper() -> TestResult {
    deadline(async {
        let Ok(socket) = std::env::var("RF_PAIRING_REGISTRY_TEST_SOCKET") else { return Ok(()) };
        let action = std::env::var("RF_PAIRING_REGISTRY_TEST_ACTION")?;
        let operation_id = std::env::var("RF_PAIRING_REGISTRY_TEST_OPERATION")?;
        let operation = crate::cli::PairingOperation { operation_id, generation: 1 };
        let command = PairingCommand {
            account: "a".into(),
            sas_out: Some(Path::new(&socket).with_extension("sas")),
            action: match action.as_str() {
                "join" => PairingAction::Join {
                    display_name: "B".into(),
                    invitation_file: std::env::var("RF_PAIRING_REGISTRY_TEST_FILE")?.into(),
                },
                "cancel" => PairingAction::Cancel(operation),
                _ => PairingAction::Status(operation),
            },
        };
        let expected: i32 = std::env::var("RF_PAIRING_REGISTRY_TEST_EXIT")?.parse()?;
        let result = handle(socket.into(), command).await;
        let actual = match result {
            Ok(()) => 0,
            Err(RfError::PairingExit { code }) => code,
            Err(error) => return Err(error.into()),
        };
        assert_eq!(actual, expected, "fresh-process cleanup result changed");
        Ok(())
    })
    .await
}
#[tokio::test]
async fn pairing_cli_invitation_cleanup_uses_owned_registry() -> TestResult {
    deadline(async {

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().to_path_buf();
    let socket = root.join("bus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/ramflux-protocol/fixtures/pairing_v2/channel_local/maxima.json"
    ))?;
    let join: Join =
        serde_json::from_str(vectors["Join"]["wire"].as_str().ok_or("join fixture missing")?)?;
    let token = join.token.to_wire_bytes().map_err(|_| invalid())?;
    for (index, action, phase, replaced, exit) in [
        (1, "cancel", "cancelled", false, 2),
        (2, "status", "expired", false, 2),
        (3, "status", "cancelled", true, 1),
        (4, "join", "commitments", false, 0),
    ] {
        let operation = if action=="join" {join.token.invitation.body.request_id.clone()} else {ramflux_protocol::encode_base64url([index;32])};
        let file = root.join(format!("invitation-{index}"));
        let mut output = InvitationOutput::create(file.clone())?;
        output.commit(&token)?;
        if action != "join" { registry::Registry::open(&socket)?.register(&operation, &output, "a")?; }
        let sidecar = root.join(format!("invitation-{index}.op"));
        if action != "join" { assert_eq!(std::fs::read(&sidecar)?, operation.as_bytes(), "test: operation-owned cleanup altered ownership or left managed files"); }
        let original = root.join(format!("original-{index}"));
        if replaced {
            std::fs::rename(&file, &original)?;
            let mut replacement = InvitationOutput::create(file.clone())?;
            replacement.commit(b"unrelated private replacement")?;
        }
        let mut child = tokio::process::Command::new(std::env::current_exe()?);
        child
            .args([
                "--exact",
                "handlers::pairing::tests::pairing_registry_fresh_process_helper",
                "--nocapture",
            ])
            .env("RF_PAIRING_REGISTRY_TEST_SOCKET", &socket)
            .env("RF_PAIRING_REGISTRY_TEST_ACTION", action)
            .env("RF_PAIRING_REGISTRY_TEST_OPERATION", &operation)
            .env("RF_PAIRING_REGISTRY_TEST_FILE", &file)
            .env("RF_PAIRING_REGISTRY_TEST_EXIT", exit.to_string());
        let mut process = ChildTask(tokio::spawn(run_child(child)));
        let (mut stream, _) = listener.accept().await?;
        let len = usize::try_from(stream.read_u32().await?)?;
        assert!(len <= MAX_SCRIPT_FRAME_BYTES, "test: operation-owned cleanup altered ownership or left managed files");
        let mut bytes = zeroize::Zeroizing::new(vec![0; len]);
        stream.read_exact(&mut bytes).await?;
        let request: ramflux_sdk::LocalBusFrame = serde_json::from_slice(&bytes)?;
        assert_eq!(request.method, format!("device.pair.{action}"), "test: operation-owned cleanup altered ownership or left managed files");
        let terminal = phase != "commitments";
        let result = serde_json::json!({"schema":"ramflux.pairing.LocalResult.v2","version":2,
            "outcome":{"tag":"update","value":{"schema":"ramflux.pairing.Update.v2","version":2,
            "operation_id":operation,"generation":1,"phase":phase,"expires_at":300,
            "transcript_hash":null,"emoji_indices":null,"peer_ref":null,"peer_name":null,
            "capabilities":["message"],"lease_not_before":1,"lease_expires_at":2,
            "proposal_hash":null,"record_hash":null,"result":if terminal {Some(if phase=="expired" {"Expired"} else {"Retired"})} else {None},"cleanup":"done"}}});
        let response = ramflux_sdk::LocalBusFrame {
            kind: ramflux_sdk::LocalBusFrameKind::Response,
            body: result,
            ..request
        };
        let bytes = ramflux_protocol::canonical_json_bytes(&response)?;
        stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        let child = (&mut process.0).await??;
        assert!(
            child.status.success(),
            "fresh-process pairing cleanup failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        if replaced {
            assert_eq!(std::fs::read(&file)?, b"unrelated private replacement", "test: operation-owned cleanup altered ownership or left managed files");
            assert!(sidecar.exists(), "test: operation-owned cleanup altered ownership or left managed files");
            assert!(original.exists(), "test: operation-owned cleanup altered ownership or left managed files");
        } else {
            assert!(!file.exists(), "fresh-process cleanup left the invitation");
            if action != "join" {
                assert!(!sidecar.exists(), "test: operation-owned cleanup altered ownership or left managed files");
            }
        }
    }
    std::fs::remove_dir_all(root)?;
    Ok(())

    }).await
}

pub(super) async fn deadline<T>(
    work: impl std::future::Future<Output = TestResult<T>>,
) -> TestResult<T> {
    tokio::time::timeout(std::time::Duration::from_secs(60), work)
        .await
        .map_err(|_| "test: pairing CLI deadline exceeded")?
}
struct ChildTask(tokio::task::JoinHandle<std::io::Result<std::process::Output>>);
impl Drop for ChildTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn run_child(mut command: tokio::process::Command) -> std::io::Result<std::process::Output> {
    use tokio::io::AsyncReadExt;
    const OUTPUT_MAX: usize = 65536;
    const READ_MAX: u64 = 65537;
    let mut child = command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout =
        child.stdout.take().ok_or_else(|| std::io::Error::other("test: child stdout missing"))?;
    let stderr =
        child.stderr.take().ok_or_else(|| std::io::Error::other("test: child stderr missing"))?;
    let capture = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let read_out = async { stdout.take(READ_MAX).read_to_end(&mut out).await };
        let read_err = async { stderr.take(READ_MAX).read_to_end(&mut err).await };
        tokio::try_join!(read_out, read_err)?;
        Ok::<_, std::io::Error>((out, err))
    };
    let (status, (stdout, stderr)) = tokio::try_join!(child.wait(), capture)?;
    if stdout.len() > OUTPUT_MAX || stderr.len() > OUTPUT_MAX {
        return Err(std::io::Error::other("test: child output exceeded cap"));
    }
    Ok(std::process::Output { status, stdout, stderr })
}
