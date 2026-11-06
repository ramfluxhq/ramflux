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
    assert_reclamation(&db)?;
    g.reference_id = [77; 32];
    g.grant_id = [78; 32];
    g.issued_at = 10_001;
    g.expires_at = 20_000;
    db.bind_native_grant("message", "ref", &association(&g)?)?;
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

#[test]
fn restore_keeps_target_attachment_authority_and_recounts_its_budgets() -> Result {
    use crate::BackupDatabase;
    let root = std::env::temp_dir().join(format!(
        "rf-retirement-restore-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("account", "owner")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "account", &key)?;
    // Deliberately no actor/object/reference provenance. Runtime state is not imported authority.
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO runtime_attachment_reference VALUES(?1,'target','target',0,0)",
            params![[1_u8; 32].as_slice()],
        )?;
        db.connection.execute(
            "INSERT INTO runtime_attachment_grant VALUES(?1,?2,?3,'target-source',1)",
            params![[2_u8; 32].as_slice(), [1_u8; 32].as_slice(), restore_grant(2, 1)?],
        )?;
        db.connection.execute("UPDATE runtime_attachment_budget SET grants=9", [])?;
        Ok::<_, StorageError>(())
    })?;
    let target_path = root.join("target.db");
    let target = db.write_backup_snapshot(&target_path)?;
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO runtime_attachment_reference VALUES(?1,'incoming','incoming',1,0)",
            params![[3_u8; 32].as_slice()],
        )?;
        db.connection.execute(
            "INSERT INTO runtime_attachment_grant VALUES(?1,?2,?3,'untrusted-source',2)",
            params![[4_u8; 32].as_slice(), [3_u8; 32].as_slice(), restore_grant(4, 3)?],
        )?;
        Ok::<_, StorageError>(())
    })?;
    let incoming_path = root.join("incoming.db");
    let incoming = db.write_backup_snapshot(&incoming_path)?;
    let mut candidate = BackupDatabase::open(&target_path, &target.key)?;
    candidate.merge_backup(&incoming_path, &incoming.key, || Ok(()))?;
    assert_eq!(
        candidate.db.query_row("SELECT count(*) FROM runtime_attachment_grant", [], |r| r
            .get::<_, u64>(0))?,
        1
    );
    assert_eq!(
        candidate.db.query_row("SELECT grants FROM runtime_attachment_budget", [], |r| r
            .get::<_, u64>(0))?,
        1
    );
    assert_eq!(
        candidate.db.query_row("SELECT grants FROM runtime_attachment_reference", [], |r| r
            .get::<_, u64>(0))?,
        1
    );
    assert!(!candidate.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_attachment_reference WHERE message_id='incoming')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    drop(candidate);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_reclamation(db: &AccountDb) -> Result {
    for (sql, index) in [
        (
            "SELECT grant_id FROM runtime_attachment_retirement WHERE pending=0 ORDER BY operation LIMIT 64",
            "runtime_attachment_retirement_pending",
        ),
        (
            "SELECT grant_id FROM runtime_attachment_expiry WHERE expires<=10001 ORDER BY expires,grant_id LIMIT 64",
            "runtime_attachment_expiry_due",
        ),
    ] {
        let mut q = db.connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let plan = q
            .query_map([], |r| r.get::<_, String>(3))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(plan.iter().any(|s| s.contains(index)), "{plan:?}");
        assert!(!plan.iter().any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")), "{plan:?}");
    }
    let before: u64 =
        db.connection
            .query_row("SELECT grants FROM runtime_attachment_budget", [], |r| r.get(0))?;
    assert_eq!(db.gc_attachment_retirements(101, 64)?, 64);
    assert_eq!(
        db.connection.query_row("SELECT grants FROM runtime_attachment_budget", [], |r| r
            .get::<_, u64>(0))?,
        before - 64
    );
    // Expired pending work is settled without any relay row/ACK, in bounded pages.
    while db.gc_attachment_retirements(10_001, 64)? > 0 {}
    assert!(db.pending_attachment_retirements(None, 64)?.is_empty());
    assert_eq!(
        db.connection.query_row("SELECT grants FROM runtime_attachment_budget", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT sum(grants) FROM runtime_attachment_reference",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    Ok(())
}

fn restore_grant(id: u8, reference: u8) -> std::result::Result<Vec<u8>, StorageError> {
    let key = SigningKey::from_bytes(&[11; 32]);
    let owner = QualifiedOwner {
        account_anchor: "owner".into(),
        device_id: "device".into(),
        device_epoch: 1,
        signing_public_key: key.verifying_key().to_bytes(),
        home_node_id: "home".into(),
    };
    let grant = ScopedAttachmentGrant {
        grant_id: [id; 32],
        reference_id: [reference; 32],
        object_id: [8; 32],
        manifest_hash: [7; 32],
        owner: owner.clone(),
        grantee: owner,
        epoch: 1,
        rights: 31,
        issued_at: 100,
        expires_at: 10000,
    };
    let signature = key.sign(&grant.signing_bytes().map_err(invalid)?).to_bytes();
    grant.signed_bytes(&signature).map_err(invalid)
}
