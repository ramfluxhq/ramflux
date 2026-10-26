// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consent, held-message erasure and authority floors remain monotonic through restore merge.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex};
#[test]
fn r3_merge_preserves_contact_release_delete_and_denial_fences_and_maximum_authority_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-contact-fences-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let si = AccountIndex::open(root.join("source"))?;
    let li = AccountIndex::open(root.join("local"))?;
    si.create_account("a", "root")?;
    li.create_account("a", "root")?;
    let source = AccountDb::open(&si, "a", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&li, "a", &AccountDbKey::generate()?)?;
    for id in ["released", "deleted", "unseen"] {
        source.connection.execute("INSERT INTO contact_message_request VALUES('peer','sender',?1,'thread',x'7b7d',2,999,1)",rusqlite::params![id])?;
    }
    for id in ["released", "deleted"] {
        local.connection.execute("INSERT INTO contact_message_request VALUES('peer','sender',?1,'thread',x'7b7d',2,999,1)",rusqlite::params![id])?;
    }
    local.discard_contact_messages("peer")?;
    source.connection.execute_batch("INSERT INTO contact_request_authority_floor VALUES('floor',9,'higher',200); INSERT INTO contact_request_fence VALUES('denied','declined',200); INSERT INTO contact_request_projection VALUES('request','inbound','request-id','peer','link','blocked',x'7b7d',999,10);")?;
    local.connection.execute_batch("INSERT INTO contact_request_authority_floor VALUES('floor',5,'lower',300); INSERT INTO contact_request_fence VALUES('denied','blocked',100); INSERT INTO contact_request_projection VALUES('request','inbound','request-id','peer','link','pending',x'7b7d',999,10);")?;
    let path = root.join("incoming.db");
    let saved = source.write_backup_snapshot(&path)?;
    let target = root.join("target.db");
    let snapshot = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
    merged.merge_backup(&path, &saved.key, || Ok(()))?;
    let held: u64 = merged.db.query_row(
        "SELECT count(*) FROM contact_message_request WHERE message_id IN ('released','deleted')",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(held, 0, "released/deleted held messages must never be resurrected");
    assert_eq!(
        merged.db.query_row(
            "SELECT count(*) FROM contact_message_request WHERE message_id='unseen'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1,
        "unseen private history is retained"
    );
    assert_eq!(
        merged.db.query_row(
            "SELECT epoch FROM contact_request_authority_floor WHERE root='floor'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        9
    );
    assert_eq!(
        merged.db.query_row(
            "SELECT until FROM contact_request_authority_floor WHERE root='floor'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        300
    );
    assert_eq!(
        merged.db.query_row(
            "SELECT state FROM contact_request_fence WHERE root='denied'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "blocked"
    );
    assert_eq!(
        merged.db.query_row(
            "SELECT until FROM contact_request_fence WHERE root='denied'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        200
    );
    assert_eq!(merged.db.query_row("SELECT state FROM contact_request_projection WHERE contact_identity_commitment='request'",[],|r|r.get::<_,String>(0))?,"blocked");
    drop(merged);
    drop(source);
    drop(local);
    drop(si);
    drop(li);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
