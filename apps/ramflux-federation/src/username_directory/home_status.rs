// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pending is a local durable fact; every positive current view consumes a fresh centre wrapper.
use super::{Result, directory, error, home::HomeService};
use ramflux_protocol::username_directory as w;

impl HomeService {
    pub(super) fn status(
        &self,
        root: &str,
        operation_id: Option<String>,
        master: &str,
    ) -> Result<w::NativeUsernameReply> {
        let master = ramflux_crypto::verifying_key_from_base64url(master)?;
        let pending = self.directory.intent(root)?.filter(|intent| {
            operation_id.as_ref().is_none_or(|id| id == &intent.operation.body.operation_id)
        });
        let query_id = if pending.is_some() { None } else { operation_id.clone() };
        let receipt = match self.client.exchange_blocking(
            root,
            &directory::DirectoryRequest::Status { operation_id: query_id.clone() },
        )? {
            directory::AuthorityResponse::Receipt { receipt } => {
                let center =
                    ramflux_crypto::verifying_key_from_base64url(&self.client.pin.public_key)?;
                ramflux_crypto::username_directory::verify_receipt(
                    &center,
                    &self.client.pin.id,
                    &receipt,
                )?;
                let now = crate::now_unix_seconds()?;
                if receipt.body.principal_commitment != root
                    || query_id.as_ref().is_some_and(|id| id != &receipt.body.operation_id)
                    || receipt.body.committed_at > now
                    || now >= receipt.body.expires_at
                    || receipt.body.state != w::ReceiptState::Reserved
                        && receipt.body.expires_at
                            > now.checked_add(60).ok_or_else(|| error("username clock"))?
                {
                    return Err(error("username status receipt mismatch"));
                }
                Some(*receipt)
            }
            directory::AuthorityResponse::Refused { failure }
                if failure.code == w::DirectoryCode::NotFound && query_id.is_none() =>
            {
                None
            }
            directory::AuthorityResponse::Refused { failure } => {
                return Ok(w::NativeUsernameReply::Refused { failure });
            }
            _ => return Err(error("username status response mismatch")),
        };
        let live = self.client.revalidate(&self.directory, root, None)?;
        let view = self.directory.owner_profile(root, live, &master, crate::now_unix_seconds()?)?;
        let state = receipt.as_ref().map_or(w::NativeUsernameState::Empty, |receipt| match receipt
            .body
            .state
        {
            w::ReceiptState::Reserved => w::NativeUsernameState::Pending,
            w::ReceiptState::Committed => w::NativeUsernameState::Committed,
            w::ReceiptState::Aborted => w::NativeUsernameState::Aborted,
        });
        let state = if pending.is_some() { w::NativeUsernameState::Pending } else { state };
        let operation_id = pending
            .as_ref()
            .map(|intent| intent.operation.body.operation_id.clone())
            .or(operation_id)
            .or_else(|| receipt.as_ref().map(|receipt| receipt.body.operation_id.clone()));
        let (binding, profile, current, current_operation) = if let Some(view) = view {
            (view.binding, Some(view.profile), Some(view.receipt), Some(view.operation))
        } else {
            (None, None, None, None)
        };
        Ok(w::NativeUsernameReply::Status {
            status: Box::new(w::NativeUsernameStatus {
                operation_id,
                state,
                binding,
                profile,
                receipt: current,
                operation_receipt: if pending.is_some() { None } else { receipt },
                current_operation,
            }),
        })
    }
}
