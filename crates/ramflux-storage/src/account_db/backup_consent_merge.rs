// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Newer explicit consent, including lifts, wins across authenticated snapshot merge.
use super::backup_database::BackupDatabase;
use crate::StorageError;
/// Orders consent states for an exact `decided_at` tie: a restriction never loses to a lift
/// stamped in the same tick, and a block outranks a decline (same rule as the projections).
fn consent_rank(state: &str) -> String {
    format!("CASE {state} WHEN 'blocked' THEN 2 WHEN 'declined' THEN 1 ELSE 0 END")
}
/// True when decision `new` supersedes decision `old`: strictly later, or tied and stricter.
pub(super) fn consent_supersedes(new: &str, old: &str) -> String {
    format!(
        "({new}.decided_at>{old}.decided_at OR ({new}.decided_at={old}.decided_at AND {}>{}))",
        consent_rank(&format!("{new}.state")),
        consent_rank(&format!("{old}.state"))
    )
}
impl BackupDatabase {
    pub(super) fn merge_consent_decisions(&self) -> Result<(), StorageError> {
        self.db.execute_batch("CREATE TABLE backup_local_consent AS SELECT * FROM contact_request_decision;
            CREATE TABLE backup_source_consent(root TEXT PRIMARY KEY,state TEXT NOT NULL,decided_at INTEGER NOT NULL);")?;
        let modern: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='contact_request_decision')", [], |r|r.get(0))?;
        if modern {
            self.db.execute_batch("INSERT INTO backup_source_consent SELECT * FROM incoming.contact_request_decision;")?;
        }
        // Old archives have no lift tombstones. Their retained request time is a conservative
        // fallback, but it cannot supersede a later explicit local decision.
        self.db.execute_batch(&format!("INSERT OR IGNORE INTO backup_source_consent
            SELECT f.root,f.state,coalesce((SELECT min(max(max(updated_at),0),9223372036854775)*1000 FROM incoming.contact_request_projection WHERE contact_identity_commitment=f.root),0) FROM incoming.contact_request_fence f;
            INSERT INTO contact_request_decision SELECT * FROM backup_source_consent WHERE 1
            ON CONFLICT(root) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at
            WHERE {upsert};
            DELETE FROM contact_request_fence WHERE root IN (SELECT root FROM contact_request_decision WHERE state='lifted');
            INSERT INTO contact_request_fence
            SELECT f.root,f.state,f.until FROM incoming.contact_request_fence f
              JOIN backup_source_consent s USING(root) LEFT JOIN backup_local_consent l USING(root)
              WHERE s.state=f.state AND (l.root IS NULL OR {fence})
            ON CONFLICT(root) DO UPDATE SET state=excluded.state,until=excluded.until;
            UPDATE contact_request_fence SET until=CASE WHEN until=0 OR (SELECT f.until FROM incoming.contact_request_fence f WHERE f.root=contact_request_fence.root)=0 THEN 0 ELSE max(until,coalesce((SELECT f.until FROM incoming.contact_request_fence f WHERE f.root=contact_request_fence.root),until)) END
            WHERE root IN (SELECT s.root FROM backup_source_consent s JOIN backup_local_consent l USING(root) WHERE s.decided_at=0 AND l.decided_at=0 AND l.state<>'lifted');
",
            upsert = consent_supersedes("excluded", "contact_request_decision"),
            fence = consent_supersedes("s", "l"),
        ))?;
        self.merge_link_consent_decisions()?;
        Ok(())
    }
    fn merge_link_consent_decisions(&self) -> Result<(), StorageError> {
        self.db.execute_batch("CREATE TABLE backup_local_link_consent AS SELECT * FROM contact_link_decision; CREATE TABLE backup_source_link_consent(link_id TEXT PRIMARY KEY,state TEXT NOT NULL,decided_at INTEGER NOT NULL);")?;
        let modern: bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='contact_link_decision')", [], |r|r.get(0))?;
        if modern {
            self.db.execute_batch("INSERT INTO backup_source_link_consent SELECT * FROM incoming.contact_link_decision;")?;
        }
        self.db.execute_batch(&format!("INSERT OR IGNORE INTO backup_source_link_consent SELECT link_id,CASE WHEN blocked=1 THEN 'blocked' WHEN state='rejected' THEN 'declined' ELSE 'lifted' END,min(max(updated_at,0),9223372036854775)*1000 FROM incoming.friend_link_projection WHERE state IN ('accepted','blocked','rejected');
            INSERT INTO contact_link_decision SELECT * FROM backup_source_link_consent WHERE 1 ON CONFLICT(link_id) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at WHERE {};", consent_supersedes("excluded", "contact_link_decision")))?;
        Ok(())
    }
}
