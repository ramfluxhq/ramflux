// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::cli::PairingOperation;
use ramflux_protocol::custody::pairing::local_dto::Update;
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const MAX_SCRIPT_FRAME_BYTES: usize = 64 * 1024;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
mod resumed;
struct Refuse;
impl ramflux_sdk::custody::pairing::LocalCredentialProvider for Refuse {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<ramflux_sdk::custody::pairing::CredentialOutcome, ramflux_sdk::SdkError> {
        Ok(ramflux_sdk::custody::pairing::CredentialOutcome::Refused)
    }
}
fn current(operation: &str, indices: &[u64]) -> LocalResult {
    LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::Update {
            value: Box::new(Update {
                schema: "ramflux.pairing.Update.v2".into(),
                version: 2,
                operation_id: operation.into(),
                generation: 1,
                phase: "sas_pending".into(),
                expires_at: 300,
                transcript_hash: Some(ramflux_protocol::encode_base64url([44; 32])),
                emoji_indices: Some(indices.into()),
                peer_ref: Some(ramflux_protocol::custody::DeviceRef {
                    account_anchor: ramflux_protocol::encode_base64url([9; 32]),
                    device_id: ramflux_protocol::encode_base64url([10; 32]),
                    device_epoch: 1,
                }),
                peer_name: Some("Other device".into()),
                capabilities: vec!["message".into()],
                lease_not_before: 1,
                lease_expires_at: 2,
                proposal_hash: None,
                record_hash: None,
                result: None,
                cleanup: "none".into(),
            }),
        },
    }
}
fn write_sas(
    socket: &Path,
    path: &Path,
    operation: &str,
    indices: &[u64],
    role: &str,
) -> TestResult {
    let action =
        PairingAction::Status(PairingOperation { operation_id: operation.into(), generation: 1 });
    registry::Registry::open(socket)?.record_role(operation, "a", role)?;
    let prepared = preflight(&action, Some(path))?;
    let display = Display {
        socket,
        account: "a",
        sas_out: Some(path),
        prepared: std::cell::RefCell::new(prepared),
    };
    let mut result = current(operation, indices);
    result.validate_method("pair.status").map_err(|_| invalid())?;
    super::display(&display, &mut result)?;
    assert!(
        matches!(result.outcome, Outcome::Update {value} if value.emoji_indices.is_none()),
        "test: SAS indices escaped the private display/file sink into stdout metadata"
    );
    Ok(())
}
async fn receive(stream: &mut tokio::net::UnixStream) -> TestResult<LocalBusFrame> {
    let len = usize::try_from(stream.read_u32().await?)?;
    if len > MAX_SCRIPT_FRAME_BYTES {
        return Err("oversize scripted request".into());
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
async fn respond(
    stream: &mut tokio::net::UnixStream,
    request: LocalBusFrame,
    result: LocalResult,
) -> TestResult {
    let frame = LocalBusFrame {
        kind: LocalBusFrameKind::Response,
        body: serde_json::to_value(result)?,
        ..request
    };
    let bytes = ramflux_protocol::canonical_json_bytes(&frame)?;
    stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
async fn confirm_case(socket: &Path, operation: &str, peer: &Path, expected: bool) -> TestResult {
    let listener = tokio::net::UnixListener::bind(socket)?;
    let mut client = PairingBusClient::connect(socket, Arc::new(Refuse)).await?;
    let server = async {
        let (mut stream, _) = listener.accept().await?;
        let request = receive(&mut stream).await?;
        assert_eq!(
            request.method, "device.pair.status",
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
        respond(&mut stream, request, current(operation, &[0, 1, 2, 3, 4, 5, 6])).await?;
        let request = receive(&mut stream).await?;
        assert_eq!(
            request.method, "device.pair.confirm",
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
        assert_eq!(
            request.body["match"], expected,
            "CLI flag bypassed current seven-name comparison"
        );
        let mut result = current(operation, &[0, 1, 2, 3, 4, 5, 6]);
        if let Outcome::Update { value } = &mut result.outcome {
            value.phase = if expected { "mutually_confirmed" } else { "rejected" }.into();
            value.result = if expected { None } else { Some("SasMismatch".into()) };
            if !expected {
                value.emoji_indices = None;
            }
        }
        respond(&mut stream, request, result).await
    };
    let display =
        Display { socket, account: "a", sas_out: None, prepared: std::cell::RefCell::new(None) };
    let confirm = super::confirm(
        &mut client,
        "a",
        &display,
        Confirm {
            schema: "ramflux.pairing.Confirm.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: 1,
            transcript_hash: ramflux_protocol::encode_base64url([44; 32]),
            r#match: true,
        },
        Some(peer.into()),
        true,
    );
    let (delivery, result) = tokio::join!(server, confirm);
    delivery?;
    if expected {
        result?;
    } else {
        assert!(
            matches!(result, Err(RfError::PairingExit { code: 4 })),
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
    }
    Ok(())
}
#[tokio::test]
async fn pairing_cli_peer_file_uses_current_sas_and_cleans_both_devices() -> TestResult {
    super::super::tests::deadline(async {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_path_buf();
        let operation = ramflux_protocol::encode_base64url([30; 32]);
        for device in ["a", "b", "c"] {
            std::fs::create_dir_all(root.join(device))?;
        }
        let a = root.join("a/bus.sock");
        let b = root.join("b/bus.sock");
        let sa = root.join("a/sas");
        let sb = root.join("b/sas");
        write_sas(&a, &sa, &operation, &[0, 1, 2, 3, 4, 5, 6], "initiator")?;
        write_sas(&b, &sb, &operation, &[0, 1, 2, 3, 4, 5, 6], "responder")?;
        let pa = root.join("a/peer");
        let pb = root.join("b/peer");
        for (source, target) in [(&sa, &pb), (&sb, &pa)] {
            let mut output = InvitationOutput::create(target.clone())?;
            output.commit(&std::fs::read(source)?)?;
        }
        confirm_case(&a, &operation, &pa, true).await?;
        assert!(
            !sa.exists() && !pa.exists(),
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
        confirm_case(&b, &operation, &pb, true).await?;
        assert!(
            !sb.exists() && !pb.exists(),
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
        let c = root.join("c/bus.sock");
        let sc = root.join("c/sas");
        write_sas(&c, &sc, &operation, &[0, 1, 2, 3, 4, 5, 6], "initiator")?;
        let pc = root.join("c/peer");
        let mut wrong = InvitationOutput::create(pc.clone())?;
        let Outcome::Update { value } = current(&operation, &[6, 5, 4, 3, 2, 1, 0]).outcome else {
            return Err("test: missing comparison update".into());
        };
        wrong.commit(&comparison::encode(&value, "responder")?)?;
        confirm_case(&c, &operation, &pc, false).await?;
        assert!(
            !sc.exists() && !pc.exists(),
            "test: seven-name comparison or consumed SAS-file cleanup changed"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    })
    .await
}

#[test]
fn pairing_cli_comparison_refuses_foreign_context_and_unattended_provenance() -> TestResult {
    let operation = ramflux_protocol::encode_base64url([31; 32]);
    let Outcome::Update { value } = current(&operation, &[0, 1, 2, 3, 4, 5, 6]).outcome else {
        return Err("test: missing current SAS update".into());
    };
    let peer = comparison::encode(&value, "responder")?;
    assert!(
        comparison::peer_matches(&value, "initiator", &peer)?,
        "test: exact attended peer context refused"
    );
    let encoded: serde_json::Value = serde_json::from_slice(&peer)?;
    for (key, replacement) in [
        ("role", serde_json::json!("initiator")),
        ("transcript_hash", serde_json::json!(ramflux_protocol::encode_base64url([32; 32]))),
        ("operation_id", serde_json::json!(ramflux_protocol::encode_base64url([33; 32]))),
        ("generation", serde_json::json!(0)),
        ("source", serde_json::json!("relay")),
    ] {
        let mut foreign = encoded.clone();
        foreign[key] = replacement;
        assert!(
            comparison::peer_matches(&value, "initiator", &serde_json::to_vec(&foreign)?).is_err(),
            "test: foreign role/context or node-provided comparison DTO accepted: {key}"
        );
    }
    assert!(
        comparison::peer_matches(&value, "initiator", names(&[0, 1, 2, 3, 4, 5, 6])?.as_bytes())
            .is_err(),
        "test: bare names bypassed role and transcript binding"
    );
    let temporary = tempfile::tempdir()?;
    let output = temporary.path().join("unattended-sas");
    let action = PairingAction::Confirm {
        operation: PairingOperation { operation_id: operation, generation: 1 },
        transcript_hash: ramflux_protocol::encode_base64url([44; 32]),
        matches: true,
        peer_sas_file: Some(temporary.path().join("node-provided")),
        peer_sas_attended: false,
    };
    assert!(
        preflight(&action, Some(&output)).is_err(),
        "test: file flag substituted for attended provenance"
    );
    assert!(!output.exists(), "test: unattended refusal created an output before validation");
    Ok(())
}
