// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persistent reset budgets and a hard recovery lifetime, independent of confirmation cleanup.
use super::session::pair_key;
use super::{RamfluxClient, SdkError};
use serde_json::json;
pub(super) const MAX_RESET_LIFETIME: i64 = 7 * 24 * 60 * 60;
const DAY: i64 = 24 * 60 * 60;
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ResetWork {
    pub local: String,
    pub remote: String,
    pub attempts: u32,
    pub next_at: i64,
    #[serde(default)]
    pub first_at: Option<i64>,
}
pub(super) fn work_key(local: &str, remote: &str) -> Result<String, SdkError> {
    Ok(format!("dm-pair/reset-work/{}", pair_key(local, remote)?))
}
impl RamfluxClient {
    pub(super) fn normalize_reset_work(&self, work: &mut ResetWork) -> Result<i64, SdkError> {
        if let Some(first) = work.first_at {
            return Ok(first);
        }
        // Legacy work predates first_at. Never mistake a recent retry for its creation time.
        // If retention removed the original attempt, fail closed to manual recovery.
        let first = self
            .account_db()?
            .legacy_pair_reset_first_at(&pair_key(&work.local, &work.remote)?)?
            .unwrap_or(0);
        work.first_at = Some(first);
        self.account_db()?.persist_actor_state(&work_key(&work.local, &work.remote)?, work)?;
        Ok(first)
    }

    pub(super) fn begin_pair_recovery(
        &self,
        local: &str,
        remote: &str,
        at: i64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let pair = pair_key(local, remote)?;
        if db.actor_state_exists(&format!("{pair}/manual"))? {
            return Ok(false);
        }
        let key = work_key(local, remote)?;
        let mut existing = db.load_actor_state::<ResetWork>(&key)?;
        if let Some(work) = &mut existing
            && at >= self.normalize_reset_work(work)?.saturating_add(MAX_RESET_LIFETIME)
        {
            self.mark_pair_manual(local, remote, at)?;
            return Ok(false);
        }
        let mut attempts =
            db.load_actor_state::<Vec<i64>>(&format!("{pair}/reset-times"))?.unwrap_or_default();
        attempts.retain(|last| at < last.saturating_add(DAY));
        let minute = db
            .load_actor_state::<i64>(&format!("{pair}/reset-at"))?
            .filter(|last| at < last.saturating_add(60))
            .map(|last| last.saturating_add(60));
        let daily = (attempts.len() >= 10)
            .then(|| attempts.first().copied().unwrap_or(at).saturating_add(DAY));
        if let Some(next) = minute.or(daily) {
            if let Some(mut work) = existing {
                work.next_at = work.next_at.max(next);
                db.persist_actor_state(&key, &work)?;
            }
            db.append_journal(&format!("pair-reset-refused:{pair}:{next}"),"session.reset",&json!({"device_id":remote,"state":"rate_limited","reason":if minute.is_some(){"minimum_interval"}else{"daily_budget"},"retry_at":next}),at,None)?;
            return Ok(false);
        }
        if existing.as_ref().is_some_and(|work| at < work.next_at) {
            return Ok(false);
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            let replace = existing.is_none()
                || self.active_pair(local, remote)?.is_some_and(|(state, _)| {
                    state.send_counter > u64::try_from(state.max_skip).unwrap_or(u64::MAX)
                });
            if replace {
                if let Some((state, _)) = self.active_pair(local, remote)? {
                    self.archive_pair(local, remote, &state.session_id)?;
                }
                db.remove_actor_state(&pair)?;
            }
            let first = existing.as_ref().and_then(|work| work.first_at).unwrap_or(at);
            let count = existing.as_ref().map_or(1, |work| work.attempts.saturating_add(1));
            let delay = 60_i64.saturating_mul(1_i64 << count.saturating_sub(1).min(3)).min(300);
            db.persist_actor_state(
                &key,
                &ResetWork {
                    local: local.to_owned(),
                    remote: remote.to_owned(),
                    attempts: count,
                    next_at: at.saturating_add(delay),
                    first_at: Some(first),
                },
            )?;
            attempts.push(at);
            db.persist_actor_state(&format!("{pair}/reset-times"), &attempts)?;
            db.persist_actor_state(&format!("{pair}/reset-at"), &at)?;
            db.persist_actor_state(&format!("{pair}/reset-pending"), &true)?;
            db.append_journal(
                &format!("pair-reset-attempt:{pair}:{at}"),
                "session.reset",
                &json!({"device_id":remote,"reason":"receive_state_unrecoverable","attempt":count}),
                at,
                None,
            )?;
            Ok(())
        })?;
        self.finish_pair_retirement()?;
        Ok(true)
    }
}
