// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Logical own-sent replay has an erasable body register and a content-free private fence.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyRegister {
    digest: [u8; 32],
}

pub(crate) struct LogicalReplay {
    fence: String,
    body: String,
    digest: [u8; 32],
    owners: Vec<String>,
}

impl RamfluxClient {
    pub(crate) fn own_sent_logical_replay(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &g::EventIdentity,
        exact_inner: &[u8],
        owners: Vec<String>,
    ) -> Result<Option<LogicalReplay>, SdkError> {
        if owners.is_empty() {
            return Err(SdkError::InboundRejected("own-sent event has no erasure owner".into()));
        }
        let db = self.account_db()?;
        let binding = serde_json::to_string(&(
            source.storage_key(),
            ramflux_protocol::encode_base64url(&identity.id),
        ))?;
        let scope = db.own_sent_index_digest("generated-event", &binding)?;
        let replay = LogicalReplay {
            fence: format!("own-device/sent-event/{scope}"),
            body: format!("own-device/sent-event-body/{scope}"),
            digest: *blake3::hash(exact_inner).as_bytes(),
            owners,
        };
        if db.load_actor_state::<bool>(&replay.fence)?.unwrap_or(false) {
            if let Some(previous) = db.load_actor_state::<BodyRegister>(&replay.body)?
                && previous.digest != replay.digest
            {
                return Err(SdkError::ReplayMismatch);
            }
            // Once its body register has been retired, the event can never acquire a
            // different target or restore content. There is no plaintext oracle to compare.
            return Ok(None);
        }
        Ok(Some(replay))
    }

    pub(crate) fn commit_own_sent_logical_replay(
        &self,
        replay: &LogicalReplay,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        // Called after effect or a durable pending record, in the enclosing receive writer.
        db.persist_actor_state(&replay.fence, &true)?;
        let erased = replay.owners.iter().try_fold(false, |erased, owner| {
            db.message_is_deleted(owner).map(|deleted| erased || deleted)
        })?;
        if !erased {
            for owner in &replay.owners {
                db.bind_message_container_reference(owner, &replay.body)?;
            }
            db.persist_bound_message_actor_state(
                &replay.body,
                &BodyRegister { digest: replay.digest },
            )?;
        }
        Ok(())
    }
}
