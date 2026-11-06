// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{AccountDbKey, AccountIndex};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::QualifiedOwner;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn retirement_outbox_seals_complete_fanout_and_reopens_with_indexed_pages() -> Result {
    let root = std::env::temp_dir().join(format!(
        "rf-retirement-outbox-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let index = AccountIndex::open(&root)?;
    let anchor = ramflux_protocol::encode_base64url([1; 32]);
    index.create_account("human", &anchor)?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "human", &key)?;
    db.write_transaction(|| { db.connection.execute("INSERT INTO object_retention_payload VALUES('c',?1,?2,'lookup','imported',NULL,0)",params![id(&[4;32]),id(&[5;32])])?;
        db.connection.execute_batch("INSERT INTO object_retention_reference VALUES('ref','c','alias','selector',x'7b7d'); INSERT INTO object_message_reference VALUES('message','ref',x'7b7d');")?; Ok::<_,StorageError>(()) })?;
    let signer = SigningKey::from_bytes(&[11; 32]);
    let owner = QualifiedOwner {
        account_anchor: anchor,
        device_id: "device".into(),
        device_epoch: 1,
        signing_public_key: signer.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    let mut g = ScopedAttachmentGrant {
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
    let association = |g: &ScopedAttachmentGrant| -> Result<NativeGrantAssociation> {
        let sig = signer.sign(&g.signing_bytes()?).to_bytes();
        Ok(NativeGrantAssociation {
            grant: ScopedAttachmentGrant::decode_signed(&g.signed_bytes(&sig)?)?,
            source_authority: "source".into(),
            authority_generation: 1,
        })
    };
    db.bind_native_grant("message", "ref", &association(&g)?)?;
    g.grant_id = [6; 32];
    db.bind_native_grant("message", "ref", &association(&g)?)?;
    let grants = db.native_reference_grants(&[3; 32])?;
    assert_eq!(grants.len(), 2);
    let requests = signed_requests(&grants, &signer)?;
    assert!(db.enqueue_native_reference_retirement(&[3; 32], &requests[..1]).is_err());
    assert!(!db.native_reference_retirement_started(&[3; 32])?);
    assert!(db.pending_attachment_retirements(None, 64)?.is_empty());
    db.enqueue_native_reference_retirement(&[3; 32], &requests)?;
    g.grant_id = [7; 32];
    assert!(db.bind_native_grant("message", "ref", &association(&g)?).is_err());
    // Complete unrelated signed associations exercise the real budget and reference seek.
    for n in 0..1024_u64 {
        let mut other = g.clone();
        other.grant_id = [90; 32];
        other.grant_id[..8].copy_from_slice(&n.to_be_bytes());
        other.reference_id = other.grant_id;
        db.bind_native_grant("message", "ref", &association(&other)?)?;
    }
    // Acked unrelated volume must not make the pending-work page a scan.
    db.write_transaction(|| { db.connection.execute("INSERT INTO runtime_attachment_retirement SELECT grant_id,grant_id,?1,?2,?3,0 FROM runtime_attachment_grant WHERE grant_id<>?4 AND grant_id<>?5",params![requests[0].request().canonical_bytes().map_err(invalid)?,requests[0].signature().as_slice(),requests[0].signer().as_slice(),requests[0].request().grant_id.as_slice(),requests[1].request().grant_id.as_slice()])?; Ok::<_,StorageError>(()) })?;
    assert_hot_query_plans(&db)?;
    drop(db);
    let db = AccountDb::open(&index, "human", &key)?;
    let first = db.pending_attachment_retirements(None, 1)?;
    assert_eq!(first.len(), 1);
    let second =
        db.pending_attachment_retirements(Some(&first[0].signed.request().operation_id), 1)?;
    assert_eq!(second.len(), 1);
    assert_ne!(first[0].signed.request().operation_id, second[0].signed.request().operation_id);
    let mut wrong = first[0].signed.request().clone();
    wrong.authority_generation += 1;
    assert!(db.acknowledge_attachment_retirement(&wrong).is_err());
    db.acknowledge_attachment_retirement(first[0].signed.request())?;
    db.enqueue_native_reference_retirement(&[3; 32], &requests)?;
    assert_eq!(db.pending_attachment_retirements(None, 64)?.len(), 1);
    drop(db);
    let db = AccountDb::open(&index, "human", &key)?;
    assert!(db.native_reference_retirement_started(&[3; 32])?);
    assert_eq!(db.pending_attachment_retirements(None, 64)?.len(), 1);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_hot_query_plans(db: &AccountDb) -> Result {
    for (sql, param) in [
        (
            "SELECT body,signature,signer FROM runtime_attachment_retirement WHERE pending=1 AND operation>?1 ORDER BY operation LIMIT 1",
            vec![],
        ),
        (
            "SELECT signed_grant,source,generation FROM runtime_attachment_grant WHERE reference_id=?1 ORDER BY grant_id LIMIT 65",
            vec![3_u8; 32],
        ),
        ("SELECT sealed FROM runtime_attachment_reference WHERE reference_id=?1", vec![3_u8; 32]),
    ] {
        let mut query = db.connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let plan = query
            .query_map(params![param], |r| r.get::<_, String>(3))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(plan.iter().any(|s| s.contains("SEARCH")), "{plan:?}");
        assert!(!plan.iter().any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")), "{plan:?}");
    }
    Ok(())
}

fn signed_requests(
    grants: &[NativeGrantAssociation],
    signer: &SigningKey,
) -> Result<Vec<VerifiedAttachmentRetirement>> {
    let mut requests = Vec::new();
    for (i, a) in grants.iter().enumerate() {
        let g = a.grant.grant();
        let r = AttachmentRetirement {
            reference_id: g.reference_id,
            grant_id: g.grant_id,
            grant_hash: g.hash()?,
            grant_epoch: 1,
            source_authority: "source".into(),
            authority_generation: 1,
            operation_id: [u8::try_from(i + 8)?; 32],
            issued_at: 101,
        };
        let sig = signer.sign(&r.signing_bytes()?).to_bytes();
        requests.push(AttachmentRetirement::verify(
            &r.canonical_bytes()?,
            &sig,
            &signer.verifying_key().to_bytes(),
        )?);
    }
    Ok(requests)
}
