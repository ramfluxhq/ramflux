// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{
    AccountDbKey, AccountIndex, BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner,
    ObjectWrite,
};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::QualifiedOwner;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn association(db: &AccountDb) -> Result<NativeGrantAssociation> {
    let key = SigningKey::from_bytes(&[11; 32]);
    let owner = QualifiedOwner {
        account_anchor: db.object_erasure_root().into(),
        device_id: "device".into(),
        device_epoch: 1,
        signing_public_key: key.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    let g = ScopedAttachmentGrant {
        grant_id: [2; 32],
        reference_id: [3; 32],
        object_id: [4; 32],
        manifest_hash: [5; 32],
        owner: owner.clone(),
        grantee: owner,
        epoch: 1,
        rights: 31,
        issued_at: 100,
        expires_at: 10000,
    };
    Ok(NativeGrantAssociation {
        grant: ScopedAttachmentGrant::decode_signed(
            &g.signed_bytes(&key.sign(&g.signing_bytes()?).to_bytes())?,
        )?,
        source_authority: "source".into(),
        authority_generation: 1,
    })
}
fn bind_live(db: &AccountDb) -> Result {
    let wire = id(&[4; 32]);
    let hash = id(&[5; 32]);
    db.upsert_object(&ObjectWrite {
        object_id: &wire,
        manifest_hash: &hash,
        nonce: "nonce",
        ciphertext: b"cipher",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[1; 32]),
        object: &serde_json::json!({"object_id":wire,"tombstoned":false}),
        updated_at: 1,
    })?;
    db.send_direct_message("thread", "message", "peer", b"message")?;
    db.register_object_reference(ObjectReferenceAdmission::FreshMessage,&ObjectReferenceOwner {reference_hash:"ref",wire_id:&wire,manifest_hash:&hash,selector:&wire,message_id:"message",reference:&serde_json::json!({"reference":{"object_id":wire,"manifest_hash":hash,"plaintext_hash":"plain"}}),metadata:&serde_json::json!({"message_id":"message","object_id":wire,"owner":"peer"})})?;
    Ok(())
}
fn assert_veto(db: &AccountDb, a: &NativeGrantAssociation) -> Result {
    assert!(!db.message_is_deleted("message")?);
    db.check_object_identity(&id(&[4; 32]), &id(&[5; 32]))?;
    let live:bool=db.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_message_reference WHERE message_id='message' AND reference_hash='ref')",[],|r|r.get(0))?;
    assert!(live);
    assert!(matches!(db.bind_native_grant("message", "ref", a), Err(StorageError::ObjectErased)));
    Ok(())
}
#[test]
fn sealed_reference_veto_refuses_live_and_second_generation_restored_grant_binding() -> Result {
    let (root, db) = crate::tests::test_db("sealed-native-veto")?;
    bind_live(&db)?;
    let a = association(&db)?;
    db.bind_native_grant("message", "ref", &a)?;
    let old_path = root.join("old.db");
    let old = db.write_backup_snapshot(&old_path)?;
    let signer = SigningKey::from_bytes(&[11; 32]);
    let grants = db.native_reference_grants(&[3; 32])?;
    let requests = super::tests::signed_requests(&grants, &signer)?;
    db.enqueue_native_reference_retirement(&[3; 32], &requests)?;
    assert_veto(&db, &a)?;
    let sealed_path = root.join("sealed.db");
    let sealed = db.write_backup_snapshot(&sealed_path)?;
    drop(db);
    for incoming_sealed in [true, false] {
        let (target, target_key, incoming, incoming_key) = if incoming_sealed {
            (&old_path, &old.key, &sealed_path, &sealed.key)
        } else {
            (&sealed_path, &sealed.key, &old_path, &old.key)
        };
        let candidate_path = root.join(format!("candidate-{incoming_sealed}.db"));
        let candidate_key = AccountDbKey::generate()?;
        BackupDatabase::open(target, target_key)?.copy_to(&candidate_path, &candidate_key)?;
        let mut candidate = BackupDatabase::open(&candidate_path, &candidate_key)?;
        candidate.merge_backup(incoming, incoming_key, || Ok(()))?;
        let second_path = root.join(format!("second-{incoming_sealed}.db"));
        let second_key = AccountDbKey::generate()?;
        candidate.copy_to(&second_path, &second_key)?;
        drop(candidate);
        let mut second = BackupDatabase::open(&second_path, &second_key)?;
        second.merge_backup(&old_path, &old.key, || Ok(()))?;
        let restored_root = root.join(format!("restored-{incoming_sealed}"));
        let index = AccountIndex::open(&restored_root)?;
        let record = index.create_account("acct", "principal")?;
        let restored_key = AccountDbKey::generate()?;
        second.copy_to(&restored_root.join(record.db_relative_path), &restored_key)?;
        drop(second);
        let restored = AccountDb::open(&index, "acct", &restored_key)?;
        assert_veto(&restored, &a)?;
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}
