// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Finalize provisional attachment ownership after the gateway send outcome.
use super::*;
use crate::client::deferred_attachment::ReferenceContext;

impl RamfluxClient {
    pub(crate) fn finish_attachment_send(
        &self,
        result: Result<GatewayInboxEntry, SdkError>,
        references: &[SdkDmAttachmentRef],
        context: ReferenceContext<'_>,
        holds: Vec<ramflux_storage::PreSendObjectHold>,
        consume_erased: bool,
    ) -> Result<GatewayInboxEntry, SdkError> {
        if result.is_ok() {
            self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
                for reference in references {
                    let registration = self.persist_received_reference_prepared(
                        reference, context.owner, context.conversation, context.message, None,
                    );
                    match registration {
                        Ok(()) => {}
                        Err(SdkError::ObjectErased) if consume_erased => {
                            tracing::warn!("erased outgoing attachment registration skipped after successful send");
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            })?;
        }
        for hold in holds {
            hold.release()?;
        }
        result
    }
}
