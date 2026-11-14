// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Valid original-source signatures and valid AEAD still cannot grant another tail context.
use super::*;
use ed25519_dalek::Signer as _;
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    full_transfer::{FullError, ManifestKind, SourceManifest, U64},
};
use std::sync::atomic::{AtomicBool, Ordering};
#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    Parent,
    Transfer,
    DeltaAfterJ6,
}
pub(super) async fn run(fault: Fault) -> TestResult {
    let (mut rig, mut source, client, mut target, request) = Box::pin(setup()).await?;
    let before = rig.wire_evidence.admitted_sends();
    let applied = Arc::new(AtomicBool::new(false));
    let participant = rig.participant_a.clone();
    let changed = applied.clone();
    drive(
        Box::pin(rig.primary.replace_unstarted_tail_manifest_for_test(
            &request.operation_id,
            Box::new(move |manifest| {
                let manifest = forge(manifest, fault, &participant)?;
                changed.store(true, Ordering::Release);
                Ok(manifest)
            }),
        )),
        &mut source,
        &rig.source.client,
    )
    .await?;
    let mut refused = false;
    for _ in 0..96 {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.sync_relay()), &mut source, &rig.source.client).await?;
        rig.clock.advance_ms(1001);
        let receiver = drive(Box::pin(rig.secondary.sync_relay()), &mut target, &client).await;
        let result = rig.secondary.transfer_status(&request).await?;
        if matches!(result.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Pending && matches!(value.result, Some(FullError::WrongContext | FullError::ManifestMismatch)))
        {
            refused = true;
            break;
        }
        receiver?;
    }
    assert!(
        applied.load(Ordering::Acquire),
        "test: source never constructed the signed {fault:?} attack"
    );
    assert!(
        rig.wire_evidence.admitted_sends() > before,
        "test: native relay did not admit the opaque signed {fault:?} packet"
    );
    assert!(refused, "test: B did not specifically refuse the signed {fault:?} tail context");
    client.account_db()?.check_object_identity("driver-tail", "driver-manifest")?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(&client, &rig.participant_b.account_id)?,
        "test: malformed data revoked positively installed B authority"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(&client, &rig.participant_b.account_id)?,
        "test: hostile tail shutdown revoked B's ordinary session"
    );
    Ok(())
}
fn forge(
    mut value: SourceManifest,
    fault: Fault,
    participant: &LocalPairingParticipant,
) -> Result<SourceManifest, SdkError> {
    match fault {
        Fault::Parent => {
            value.manifest.parent_manifest_hash =
                Some(ramflux_protocol::encode_base64url([91; 32]));
        }
        Fault::Transfer => {
            value.manifest.transfer_id = ramflux_protocol::encode_base64url([92; 32]);
        }
        Fault::DeltaAfterJ6 => {
            value.manifest.kind = ManifestKind::Delta;
            value.manifest.snapshot_cut = U64(8);
            value.manifest.previous_cut = Some(U64(7));
        }
    }
    let now = crate::custody::network_now()?;
    let native = crate::custody::load_account(&participant.root, &participant.account_id, now)?;
    let (_, credentials) =
        native.credentials(participant.vault.as_ref(), native.local_device_id()?, now)?;
    let bytes =
        value.manifest.signing_bytes().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    value.source_signature =
        ramflux_protocol::encode_base64url(credentials.signing.signing_key.sign(&bytes).to_bytes());
    value.validate().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    Ok(value)
}
