// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only operation replay before any network gate or durable reservation.

use crate::{LocalBusFrame, SdkError};
use ramflux_storage::{AccountDb, OperationLookup, StorageError};
use serde_json::Value;

pub(super) struct MutationIntent<'a> {
    pub key: Option<&'a str>,
    fingerprint: Option<String>,
    method: &'a str,
}

impl<'a> MutationIntent<'a> {
    pub(super) fn new(request: &'a LocalBusFrame) -> Result<Self, SdkError> {
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
    pub(super) fn lookup(&self, db: &AccountDb) -> Result<Option<Value>, SdkError> {
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
            OperationLookup::Pending => {
                Err(StorageError::OperationReconciliationRequired { key: key.to_owned() }.into())
            }
            OperationLookup::Mismatch => Err(StorageError::EventIdConflict(key.to_owned()).into()),
        }
    }
    pub(super) fn reserve(&self, db: &AccountDb) -> Result<Option<Value>, SdkError> {
        let (Some(key), Some(fingerprint)) = (self.key, self.fingerprint.as_deref()) else {
            return Ok(None);
        };
        db.reserve_operation(key, fingerprint, self.method).map_err(SdkError::from)
    }
}
