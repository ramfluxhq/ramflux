// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex, PreparedFullSource};
fn prepared(root: &std::path::Path, snapshot: u8) -> Result<PreparedFullSource> {
    let index = AccountIndex::open(root)?;
    index.create_account("acct", "principal")?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"source-test-key"))?;
    let mut source = db.prepare_full_transfer_source()?;
    let snapshot = encode_base64url([snapshot; 32]);
    source.capture_base_cut(&snapshot)?;
    source.encode_fixed_base_source(&snapshot, std::io::sink())?;
    Ok(source.close_ready()?)
}
fn sign_manifest(
    request: &FullSourceManifestSigningRequest<'_>,
) -> std::result::Result<String, SdkError> {
    if request.local_account_id() != "acct" {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    Ok(ramflux_crypto::sign_canonical_bytes_with_seed(
        &request.manifest().signing_bytes().map_err(|error| wire(&error))?,
        [70; 32],
    ))
}
#[test]
fn pairing_full_prepared_manifest_uses_confirmed_context_and_freezes_start_before_grant() -> Result
{
    let Fixture { a, context, node, mut grant, now, .. } = fixture()?;
    let root = tempfile::tempdir()?;
    let source = prepared(root.path(), 50)?;
    let mut owner = FullBootstrap::new(PairingRole::Initiator, a, context.clone(), node, now)?;
    let (manifest, start) = owner.prepare_source_start(&source, now, sign_manifest)?;
    assert_eq!(manifest.manifest.source_ref, context.initiator.device_ref);
    assert_eq!(manifest.manifest.destination_ref, context.responder.device_ref);
    assert_eq!(manifest.manifest.base_record_hash, context.initiator.common.record_hash);
    assert_eq!(manifest.manifest.total_bytes.0, source.encoding().total_bytes);
    assert_eq!(manifest.manifest.chunks_root, encode_base64url(source.encoding().chunks_root));
    assert_eq!(start.snapshot_id, source.snapshot_id());
    assert_eq!(
        start.manifest_hash,
        encode_base64url(ramflux_protocol::custody::pairing::full_transfer::manifest_hash(
            &manifest
        )?)
    );
    let calls = AtomicUsize::new(0);
    let (same_manifest, same_start) = owner.prepare_source_start(&source, now, |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(SdkError::PairingCode("WrongContext"))
    })?;
    assert_eq!(same_manifest, manifest);
    assert_eq!(
        FullSasControl::Start(same_start).encode_secret()?.as_slice(),
        FullSasControl::Start(start.clone()).encode_secret()?.as_slice()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    grant.opaque_commitment = start.opaque_commitment.clone();
    let frames = owner.begin_source(start, &grant, now, sign)?;
    assert_eq!(frames.len(), 2);
    Ok(())
}
#[test]
fn pairing_full_prepared_manifest_refuses_changed_start_before_original_branch_signer() -> Result {
    let Fixture { a, context, node, mut grant, now, .. } = fixture()?;
    let root = tempfile::tempdir()?;
    let source = prepared(root.path(), 51)?;
    let mut owner = FullBootstrap::new(PairingRole::Initiator, a, context, node, now)?;
    let (_, mut start) = owner.prepare_source_start(&source, now, sign_manifest)?;
    grant.opaque_commitment = start.opaque_commitment.clone();
    start.snapshot_id = encode_base64url([99; 32]);
    let calls = AtomicUsize::new(0);
    assert!(
        owner
            .begin_source(start, &grant, now, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(SdkError::PairingCode("WrongContext"))
            })
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn pairing_full_prepared_manifest_cancel_refuses_before_data_signature() -> Result {
    let Fixture { a, context, node, now, .. } = fixture()?;
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"source-test-key"))?;
    let mut source = db.prepare_full_transfer_source()?;
    let snapshot = encode_base64url([52; 32]);
    source.capture_base_cut(&snapshot)?;
    source.encode_fixed_base_source(&snapshot, std::io::sink())?;
    let cancel = source.cancel_handle();
    let source = source.close_ready()?;
    let mut owner = FullBootstrap::new(PairingRole::Initiator, a, context, node, now)?;
    cancel.cancel();
    let calls = AtomicUsize::new(0);
    assert!(
        owner
            .prepare_source_start(&source, now, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(SdkError::PairingCode("WrongContext"))
            })
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
