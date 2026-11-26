// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only operation replay before any network gate or durable reservation.

use std::collections::BTreeSet;
use std::sync::Mutex;

use crate::{LocalBusFrame, SdkError};
use ramflux_storage::{AccountDb, OperationLookup, StorageError};
use serde_json::Value;

/// Keyed operations executing in this process, as `account NUL key`. An entry exists from the
/// moment a keyed command is admitted until its result is returned, on every exit path.
static LIVE: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Holds one live entry; dropping it releases the operation for a later resume.
pub(crate) struct Live(String);

impl Drop for Live {
    fn drop(&mut self) {
        if let Ok(mut live) = LIVE.lock() {
            live.remove(&self.0);
        }
    }
}

pub(crate) struct MutationIntent<'a> {
    pub key: Option<&'a str>,
    fingerprint: Option<String>,
    method: &'a str,
}

impl<'a> MutationIntent<'a> {
    pub(crate) fn new(request: &'a LocalBusFrame) -> Result<Self, SdkError> {
        let key = request
            .operation_id
            .as_deref()
            .or_else(|| request.body.get("idempotency_key").and_then(Value::as_str));
        if key.is_some_and(|key| key.is_empty() || key.len() > 256) {
            return Err(SdkError::LocalBus("operation_id must contain 1 to 256 bytes".into()));
        }
        let key = key
            .filter(|_| !crate::search::capability::is_method(&request.method))
            .filter(|_| !matches!(request.method.as_str(), "object.fetch" | "call.media.session"));
        let fingerprint = key
            .map(|_| {
                ramflux_protocol::canonical_json_bytes(&(&request.method, &request.body)).map(
                    |intent| ramflux_crypto::blake3_256_base64url("ramflux.operation.v1", &intent),
                )
            })
            .transpose()?;
        Ok(Self { key, fingerprint, method: request.method.as_str() })
    }
    /// Claims the operation for this process. A key already live here is refused, never resumed.
    /// # Errors
    /// Returns `OperationReconciliationRequired` when the key is already executing.
    pub(crate) fn enter(&self, account_id: &str) -> Result<Option<Live>, SdkError> {
        let Some(key) = self.key else { return Ok(None) };
        let id = format!("{account_id}\u{0}{key}");
        let mut live = LIVE
            .lock()
            .map_err(|_| SdkError::LocalBus("operation registry unavailable".to_owned()))?;
        if !live.insert(id.clone()) {
            return Err(
                StorageError::OperationReconciliationRequired { key: key.to_owned() }.into()
            );
        }
        Ok(Some(Live(id)))
    }

    /// Only a send may resume a durable Pending row: its intent fingerprint has matched, and the
    /// caller already holds the live entry, so no other execution of this key exists here.
    fn resumable(&self) -> bool {
        self.method == "conversation.send"
    }

    pub(crate) fn lookup(&self, db: &AccountDb) -> Result<Option<Value>, SdkError> {
        let (Some(key), Some(fingerprint)) = (self.key, self.fingerprint.as_deref()) else {
            return Ok(None);
        };
        match db.lookup_operation(key, fingerprint)? {
            OperationLookup::Absent => Ok(None),
            OperationLookup::Completed(body)
                if body.get("object_erased").and_then(Value::as_bool) == Some(true) =>
            {
                Err(SdkError::ObjectErased)
            }
            OperationLookup::Completed(body) => Ok(Some(body)),
            OperationLookup::Pending if self.resumable() => Ok(None),
            OperationLookup::Pending => {
                Err(StorageError::OperationReconciliationRequired { key: key.to_owned() }.into())
            }
            OperationLookup::Mismatch => Err(StorageError::EventIdConflict(key.to_owned()).into()),
        }
    }
    pub(crate) fn reserve(&self, db: &AccountDb) -> Result<Option<Value>, SdkError> {
        let (Some(key), Some(fingerprint)) = (self.key, self.fingerprint.as_deref()) else {
            return Ok(None);
        };
        if self.resumable()
            && matches!(db.lookup_operation(key, fingerprint)?, OperationLookup::Pending)
        {
            return Ok(None);
        }
        db.reserve_operation(key, fingerprint, self.method).map_err(SdkError::from)
    }
}
