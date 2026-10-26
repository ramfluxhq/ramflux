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
    supersedes(
        &format!("{new}.decided_at"),
        &format!("{new}.state"),
        &format!("{old}.decided_at"),
        &format!("{old}.state"),
    )
}
fn supersedes(new_at: &str, new_state: &str, old_at: &str, old_state: &str) -> String {
    format!(
        "({new_at}>{old_at} OR ({new_at}={old_at} AND {}>{}))",
        consent_rank(new_state),
        consent_rank(old_state)
    )
}
/// Legacy projections have second-resolution decision bounds and no explicit decision row.
pub(super) fn consent_supersedes_projection(new: &str, old: &str, state: &str) -> String {
    supersedes(
        &format!("{new}.decided_at"),
        &format!("{new}.state"),
        &format!(
            "coalesce({old}.decided_at,min(max(coalesce(l.updated_at,0),0),9223372036854775)*1000)"
        ),
        &format!("coalesce({old}.state,{state})"),
    )
}
impl BackupDatabase {
    pub(super) fn merge_consent_decisions(&self) -> Result<(), StorageError> {
        // Missing local decisions use the same conservative projection bounds as old archives.
        self.db.execute_batch("CREATE TABLE backup_local_consent AS SELECT * FROM contact_request_decision;
            CREATE TABLE backup_source_consent(root TEXT PRIMARY KEY,state TEXT NOT NULL,decided_at INTEGER NOT NULL);
            INSERT INTO backup_local_consent SELECT f.root,f.state,coalesce((SELECT min(max(max(updated_at),0),9223372036854775)*1000 FROM contact_request_projection WHERE contact_identity_commitment=f.root),0) FROM contact_request_fence f WHERE NOT EXISTS(SELECT 1 FROM backup_local_consent l WHERE l.root=f.root);
            INSERT INTO backup_local_consent SELECT p.contact_identity_commitment,'lifted',min(max(max(p.updated_at),0),9223372036854775)*1000 FROM contact_request_projection p WHERE p.state='accepted' AND NOT EXISTS(SELECT 1 FROM backup_local_consent l WHERE l.root=p.contact_identity_commitment) GROUP BY p.contact_identity_commitment;
            INSERT OR IGNORE INTO contact_request_decision SELECT * FROM backup_local_consent;")?;
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
    pub(super) fn apply_merged_link_consent(&self) -> Result<(), StorageError> {
        // Projection timestamps come from callers and may disagree with decision order.
        // Reapply final denials only to links represented by this archive. A surviving lift
        // never revives a removal, and a denial never rewrites the removed lifecycle state.
        self.db.execute_batch("UPDATE friend_link_projection AS p
            SET state=CASE WHEN p.state='removed' THEN p.state ELSE (SELECT CASE d.state WHEN 'blocked' THEN 'blocked' ELSE 'rejected' END FROM contact_link_decision d WHERE d.link_id=p.link_id) END,
                blocked=CASE WHEN p.state='removed' THEN 1 ELSE (SELECT d.state='blocked' FROM contact_link_decision d WHERE d.link_id=p.link_id) END,
                capability_revoked_at=CASE WHEN EXISTS(SELECT 1 FROM contact_link_decision d WHERE d.link_id=p.link_id AND d.state='blocked')
                    THEN coalesce(p.capability_revoked_at,(SELECT max(d.decided_at,0)/1000 FROM contact_link_decision d WHERE d.link_id=p.link_id)) ELSE p.capability_revoked_at END
            WHERE (EXISTS(SELECT 1 FROM incoming.friend_link_projection source WHERE source.link_id=p.link_id)
                OR EXISTS(SELECT 1 FROM backup_source_link_consent source WHERE source.link_id=p.link_id))
              AND (p.state IN ('accepted','pending') OR (p.blocked=0 AND EXISTS(SELECT 1 FROM contact_link_decision d WHERE d.link_id=p.link_id AND d.state='blocked')))
              AND EXISTS(SELECT 1 FROM contact_link_decision d WHERE d.link_id=p.link_id AND d.state IN ('blocked','declined'));")?;
        Ok(())
    }
    fn merge_link_consent_decisions(&self) -> Result<(), StorageError> {
        self.db.execute_batch("CREATE TABLE backup_local_link_consent AS SELECT * FROM contact_link_decision; CREATE TABLE backup_source_link_consent(link_id TEXT PRIMARY KEY,state TEXT NOT NULL,decided_at INTEGER NOT NULL);
            INSERT INTO backup_local_link_consent SELECT p.link_id,CASE WHEN p.blocked=1 THEN 'blocked' WHEN p.state='rejected' THEN 'declined' ELSE 'lifted' END,min(max(p.updated_at,0),9223372036854775)*1000 FROM friend_link_projection p WHERE p.state IN ('accepted','blocked','rejected') AND NOT EXISTS(SELECT 1 FROM backup_local_link_consent l WHERE l.link_id=p.link_id);
            INSERT OR IGNORE INTO contact_link_decision SELECT * FROM backup_local_link_consent;")?;
        let modern: bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='contact_link_decision')", [], |r|r.get(0))?;
        if modern {
            self.db.execute_batch("INSERT INTO backup_source_link_consent SELECT * FROM incoming.contact_link_decision;")?;
        }
        self.db.execute_batch(&format!("INSERT OR IGNORE INTO backup_source_link_consent SELECT link_id,CASE WHEN blocked=1 THEN 'blocked' WHEN state='rejected' THEN 'declined' ELSE 'lifted' END,min(max(updated_at,0),9223372036854775)*1000 FROM incoming.friend_link_projection WHERE state IN ('accepted','blocked','rejected');
            INSERT INTO contact_link_decision SELECT * FROM backup_source_link_consent WHERE 1 ON CONFLICT(link_id) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at WHERE {};", consent_supersedes("excluded", "contact_link_decision")))?;
        Ok(())
    }
}
