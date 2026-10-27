// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bad-data backoff preserves transfer fences while operational failures end the scan.
use crate::prelude::*;
use serde::{Deserialize, Serialize};

pub(crate) const BACKOFF: &str = "group-transfer/maintenance/backoff/";
const WARNING: &str = "group-transfer/maintenance/warning";
const RETRY_SECONDS: i64 = 300;
const WARNING_SECONDS: i64 = 900;
const MAX_BACKOFF_ROWS: u64 = 8192;
#[derive(Deserialize, Serialize)]
struct Retry {
    next_at: i64,
    expires_at: i64,
}

fn bad_data(error: &SdkError) -> bool {
    match error {
        SdkError::Json(error) | SdkError::Storage(StorageError::Serde(error)) => !error.is_io(),
        SdkError::Protocol(_)
        | SdkError::InboundRejected(_)
        | SdkError::Storage(
            StorageError::Protocol(_)
            | StorageError::GroupPermissionDenied
            | StorageError::AuthorizationRejected,
        )
        | SdkError::Crypto(
            CryptoError::Protocol(_)
            | CryptoError::Base64(_)
            | CryptoError::VerifyFailed
            | CryptoError::InvalidSignatureLength(_)
            | CryptoError::InvalidPublicKeyLength(_),
        ) => true,
        // In particular SQLite, filesystem, random-source and unavailable-authority
        // failures are operational. Do not retry every key or quarantine those rows.
        _ => false,
    }
}

pub(crate) fn page(
    db: &AccountDb,
    prefix: &str,
    now: i64,
    limit: u32,
) -> Result<Vec<String>, SdkError> {
    Ok(db.actor_state_ready_key_page(prefix, BACKOFF, now, limit)?)
}

pub(crate) fn scan(
    db: &AccountDb,
    prefix: &str,
    now: i64,
    limit: u32,
    mut visit: impl FnMut(&str) -> Result<(), SdkError>,
) -> Result<(), SdkError> {
    for id in page(db, prefix, now, limit)? {
        item_result(db, &id, now, visit(&id))?;
    }
    Ok(())
}

pub(crate) fn item_result<T>(
    db: &AccountDb,
    id: &str,
    now: i64,
    result: Result<T, SdkError>,
) -> Result<Option<T>, SdkError> {
    let retry_key = format!("{BACKOFF}{id}");
    match result {
        Ok(value) => {
            if db.actor_state_exists(&retry_key)? {
                db.remove_actor_state(&retry_key)?;
            }
            Ok(Some(value))
        }
        Err(error) if bad_data(&error) => {
            let warn = db.write_transaction(|| -> Result<bool, SdkError> {
                let warn =
                    db.load_actor_state::<Retry>(WARNING)?.is_none_or(|row| row.next_at <= now);
                // Sweep once per warning interval, not once per poisoned row.
                if warn {
                    db.prune_actor_state_backoff(BACKOFF, now, 128)?;
                }
                if !db.actor_state_exists(&retry_key)?
                    && db.actor_state_usage(BACKOFF)?.0 >= MAX_BACKOFF_ROWS
                {
                    db.prune_actor_state_backoff(BACKOFF, now, 128)?;
                    if db.actor_state_usage(BACKOFF)?.0 >= MAX_BACKOFF_ROWS {
                        return Err(SdkError::InboundPending(
                            "group maintenance retry capacity".into(),
                        ));
                    }
                }
                db.persist_actor_state(
                    &retry_key,
                    &Retry {
                        next_at: now.saturating_add(RETRY_SECONDS),
                        expires_at: now.saturating_add(3600),
                    },
                )?;
                if warn {
                    db.persist_actor_state(
                        WARNING,
                        &Retry {
                            next_at: now.saturating_add(WARNING_SECONDS),
                            expires_at: now.saturating_add(3600),
                        },
                    )?;
                }
                Ok(warn)
            })?;
            if warn {
                tracing::warn!(item = %id, "invalid group transfer item backed off; original row retained");
            }
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
