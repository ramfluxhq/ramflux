// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable, ordered consent decisions, including explicit lifts of old denials.
use super::AccountDb;
use crate::{ContactLinkDecision, StorageError};
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    pub(super) fn persist_contact_consent(
        &self,
        root: &str,
        denial: Option<(&str, i64)>,
        only: Option<&str>,
    ) -> Result<(), StorageError> {
        let root = root.to_owned();
        let denial = denial.map(|(state, until)| (state.to_owned(), until));
        let only = only.map(str::to_owned);
        self.write_transaction(|| {
            self.connection.call(move |db| {
                let old: Option<String> = db.query_row("SELECT state FROM contact_request_fence WHERE root=?1", [&root], |r|r.get(0)).optional()?;
            // A re-add/accept clears a decline, never an operator block.
            if denial.as_ref().is_some_and(|(state,_)| state=="declined" && old.as_deref()==Some("blocked"))
                || denial.is_none() && only.as_deref().is_some_and(|state|old.as_deref().is_some_and(|old|old!=state)) {
                return Ok(());
            }
            let previous: i64 = db.query_row("SELECT decided_at FROM contact_request_decision WHERE root=?1", [&root], |r|r.get(0)).optional()?.unwrap_or(0);
            // Wall milliseconds plus a per-root logical floor order same-tick decisions.
            let decided_at = next_stamp(previous)?;
            let state = if let Some((state,until)) = denial.as_ref() {
                db.execute("INSERT INTO contact_request_fence VALUES(?1,?2,?3) ON CONFLICT(root) DO UPDATE SET state=excluded.state,until=excluded.until", params![root,state,until])?;
                state.as_str()
            } else {
                db.execute("DELETE FROM contact_request_fence WHERE root=?1", [&root])?;
                "lifted"
            };
            db.execute("INSERT INTO contact_request_decision VALUES(?1,?2,?3) ON CONFLICT(root) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at",params![root,state,decided_at])?;
                Ok(())
            }).map_err(StorageError::from)
        })?;
        Ok(())
    }
}

pub(super) enum LinkConsentChange {
    Establish { requester: String, target: String, at: i64 },
    Block(i64),
    Remove { scope: String, at: i64 },
    Unblock(i64),
    Decline(i64),
}
fn next_stamp(previous: i64) -> rusqlite::Result<i64> {
    let wall = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(wall.max(previous.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)?))
}
impl AccountDb {
    /// Reads the latest ordered local decision for one contact link.
    ///
    /// # Errors
    /// Returns storage errors while reading the decision row.
    pub fn contact_link_decision(
        &self,
        link_id: &str,
    ) -> Result<Option<ContactLinkDecision>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT state, decided_at FROM contact_link_decision WHERE link_id=?1",
                params![link_id],
                |row| Ok(ContactLinkDecision { state: row.get(0)?, decided_at: row.get(1)? }),
            )
            .optional()?)
    }

    /// Returns the projection update time as the legacy millisecond decision floor.
    ///
    /// # Errors
    /// Returns storage errors or `QueryReturnedNoRows` when the link is absent.
    pub fn friend_link_updated_at_millis(&self, link_id: &str) -> Result<i64, StorageError> {
        let seconds: i64 = self.connection.query_row(
            "SELECT updated_at FROM friend_link_projection WHERE link_id=?1",
            params![link_id],
            |row| row.get(0),
        )?;
        Ok(seconds.saturating_mul(1_000))
    }

    pub(super) fn persist_link_consent(
        &self,
        id: &str,
        change: LinkConsentChange,
    ) -> Result<bool, StorageError> {
        let id = id.to_owned();
        self.write_transaction(|| self.connection.call(move |db| {
            let (state,changed)=match change {
                LinkConsentChange::Establish {requester,target,at} => ("lifted",db.execute("INSERT OR REPLACE INTO friend_link_projection(link_id,requester_id,target_id,state,remove_scope,blocked,capability_revoked_at,updated_at) VALUES(?1,?2,?3,'accepted',NULL,0,NULL,?4)",params![id,requester,target,at])?),
                LinkConsentChange::Block(at) => ("blocked",db.execute("UPDATE friend_link_projection SET state='blocked',blocked=1,capability_revoked_at=coalesce(capability_revoked_at,?2),updated_at=?2 WHERE link_id=?1",params![id,at])?),
                LinkConsentChange::Remove {scope,at} => ("blocked",db.execute("UPDATE friend_link_projection SET state='removed',remove_scope=?2,capability_revoked_at=coalesce(capability_revoked_at,?3),updated_at=?3 WHERE link_id=?1",params![id,scope,at])?),
                LinkConsentChange::Unblock(at) => ("lifted",db.execute("UPDATE friend_link_projection SET state='accepted',blocked=0,capability_revoked_at=NULL,updated_at=?2 WHERE link_id=?1",params![id,at])?),
                LinkConsentChange::Decline(at) => ("declined",db.execute("UPDATE friend_link_projection SET state='rejected',updated_at=?2 WHERE link_id=?1 AND state='pending'",params![id,at])?),
            };
            if changed==0 {return Ok(false)}
            let previous=db.query_row("SELECT decided_at FROM contact_link_decision WHERE link_id=?1",[&id],|r|r.get(0)).optional()?.unwrap_or(0);
            db.execute("INSERT INTO contact_link_decision VALUES(?1,?2,?3) ON CONFLICT(link_id) DO UPDATE SET state=excluded.state,decided_at=excluded.decided_at",params![id,state,next_stamp(previous)?])?;
            Ok(true)
        }).map_err(StorageError::from))
    }
}
