// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive commits allocate durable public message cursors before the bus drains its outbox.
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use std::collections::BTreeSet;

impl RamfluxClient {
    /// Runs only after authenticated generated projection, still inside its writer transaction.
    /// Reads the resulting target state, so an Edit/Delete never republishes the retired body.
    pub(crate) fn journal_generated_receive_updates(&self, exact: &[u8]) -> Result<(), SdkError> {
        let Ok(inner) = g::Inner::decode(exact) else { return Ok(()) };
        let Some(event) = inner.identity else { return Ok(()) };
        let mut targets = BTreeSet::from([ramflux_protocol::encode_base64url(&event.id)]);
        let references = match inner.kind {
            3 => g::Edit::decode(inner.body.as_slice())
                .ok()
                .and_then(|edit| edit.target)
                .into_iter()
                .collect(),
            4 => g::Delete::decode(inner.body.as_slice())
                .map(|delete| delete.targets)
                .unwrap_or_default(),
            5 => g::Reaction::decode(inner.body.as_slice())
                .ok()
                .and_then(|reaction| reaction.target)
                .into_iter()
                .collect(),
            6 => g::Receipt::decode(inner.body.as_slice())
                .map(|receipt| receipt.targets)
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        targets.extend(
            references
                .into_iter()
                .map(|reference| ramflux_protocol::encode_base64url(&reference.id)),
        );
        let db = self.account_db()?;
        for target in targets {
            let Some(row) = db.direct_message_by_id(&target)? else { continue };
            if !db.actor_state_exists(&format!("routed/generated-identity/{target}"))? {
                continue;
            }
            let source = format!(
                "generated/receive/{}/{}",
                ramflux_protocol::encode_base64url(&event.id),
                target
            );
            // A fresh pair envelope carrying the same logical event cannot allocate another cursor.
            if db.journal_source_exists(&source)? {
                continue;
            }
            let update = self.generated_message_update(&row, &row.conversation_id, 0)?;
            db.append_message_update(
                &source,
                "message.updated",
                &update,
                crate::time::now_unix_timestamp(),
            )?;
        }
        Ok(())
    }
}
