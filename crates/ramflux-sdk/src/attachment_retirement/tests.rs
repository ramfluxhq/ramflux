// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::{
    memory_vault::MemoryPrimaryVault,
    tests::{Root, create},
};
use ed25519_dalek::Signer;
use ramflux_protocol::large_attachment::{QualifiedOwner, ScopedAttachmentGrant};
use ramflux_storage::{AccountDbKey, ObjectReferenceAdmission, ObjectReferenceOwner, ObjectWrite};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn sdk_retirement_pending_is_durable_and_only_exact_source_ack_settles() -> Result {
    let now = 1_700_000_001;
    let root = Root::new()?;
    let vault = MemoryPrimaryVault::default();
    let account = create(&root.0, "human", &vault, now)?;
    let index = AccountIndex::open(&root.0)?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "human", &key)?;
    let (actor, credentials) = account.credentials(&vault, "primary", now)?;
    let signer = &credentials.signing.signing_key;
    let owner = QualifiedOwner {
        account_anchor: actor.account_anchor,
        device_id: actor.device_id,
        device_epoch: actor.device_epoch,
        signing_public_key: signer.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    let grant = ScopedAttachmentGrant {
        grant_id: [2; 32],
        reference_id: [3; 32],
        object_id: [4; 32],
        manifest_hash: [5; 32],
        owner: owner.clone(),
        grantee: owner,
        epoch: 1,
        rights: 31,
        issued_at: now,
        expires_at: now + 1000,
    };
    let signature = signer.sign(&grant.signing_bytes()?).to_bytes();
    let verified = ScopedAttachmentGrant::decode_signed(&grant.signed_bytes(&signature)?)?;
    let source_key = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    let public = source_key.verifying_key().to_bytes();
    let source =
        RetirementSource { authority: "source", generation: 1, signing_public_key: &public };
    let receipt = AttachmentRegistrationReceipt {
        grant_hash: grant.hash()?,
        grant_epoch: 1,
        source_authority: "source".into(),
        authority_generation: 1,
        expires_at: now + 1000,
    };
    let sig = source_key.sign(&receipt.signing_bytes()?).to_bytes();
    let capability = receipt.capability(&verified, &sig, &public)?;
    let wire = ramflux_protocol::encode_base64url([4; 32]);
    let manifest = ramflux_protocol::encode_base64url([5; 32]);
    db.upsert_object(&ObjectWrite {
        object_id: &wire,
        manifest_hash: &manifest,
        nonce: "nonce",
        ciphertext: b"ciphertext",
        plaintext_hash: "plaintext",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[1; 32]),
        object: &serde_json::json!({"object_id":wire,"tombstoned":false}),
        updated_at: 1,
    })?;
    db.send_direct_message("thread", "message", "peer", b"message")?;
    db.register_object_reference(ObjectReferenceAdmission::FreshMessage,&ObjectReferenceOwner { reference_hash:"authenticated-reference",wire_id:&wire,manifest_hash:&manifest,selector:&wire,message_id:"message",reference:&serde_json::json!({"reference":{"object_id":wire,"manifest_hash":manifest,"plaintext_hash":"plaintext"}}),metadata:&serde_json::json!({"object_id":wire,"owner":"peer","message_id":"message"}) })?;
    let outbox = AttachmentRetirementOutbox::new(&db, &index, &account)?;
    outbox.bind_registered("message", "authenticated-reference", &capability, &source, now)?;
    outbox.begin(&[3; 32], &vault, now)?;
    let pending = outbox.pending(None, 1)?;
    assert_eq!(pending.len(), 1);
    let request = pending[0].signed.request();
    outbox.apply_authenticated_response(
        request,
        &source,
        RetirementDeliveryStatus::RevocationPending,
    )?;
    assert_eq!(outbox.pending(None, 64)?.len(), 1);
    let wrong = RetirementSource { generation: 2, ..source };
    assert!(
        outbox
            .apply_authenticated_response(request, &wrong, RetirementDeliveryStatus::Retired)
            .is_err()
    );
    drop(db);
    let db = AccountDb::open(&index, "human", &key)?;
    let outbox = AttachmentRetirementOutbox::new(&db, &index, &account)?;
    let resumed = outbox.pending(None, 1)?;
    assert_eq!(resumed[0].signed.request(), request);
    outbox.apply_authenticated_response(request, &source, RetirementDeliveryStatus::Retired)?;
    outbox.begin(&[3; 32], &vault, now + 1)?;
    assert!(outbox.pending(None, 64)?.is_empty());
    Ok(())
}
