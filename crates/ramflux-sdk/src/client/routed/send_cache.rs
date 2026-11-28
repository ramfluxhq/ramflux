// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sealed-once retry cache (spec §3.3 S-6): the one `PrivateMessage` of a message and its one
//! report opening, kept per `(group_id, epoch, BLAKE3(plaintext))`. A retry to any target
//! re-derives its per-target fields from the same bytes and never ratchets again; the record
//! retires with the content it belongs to.
use super::{RamfluxClient, SdkError, invalid};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// What every target of one message shares.
pub(super) struct SealedShared {
    /// The `PrivateMessage` bytes.
    pub message: Vec<u8>,
    /// Epoch the message was sealed in.
    pub epoch: u64,
    /// The report opening inside the plaintext (`None` only when a test omits the report).
    pub opening: Option<Zeroizing<[u8; 32]>>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    epoch: u64,
    message: String,
    opening: Option<String>,
}

pub(super) struct Binding {
    owner: String,
    key: String,
    epoch: u64,
}

impl Binding {
    pub(super) fn new(body: &[u8], group_id: &[u8], epoch: u64) -> Result<Option<Self>, SdkError> {
        // Receive adversaries deliberately reuse transport IDs or unsupported bodies.
        // This existing fixture hook never changes the production sender contract.
        #[cfg(test)]
        if super::report::allows_invalid_header_fixture() {
            return Ok(None);
        }
        let (identity, content) = RamfluxClient::decode_generated_inner(body)?;
        // Delete contains no erased body. Its own event owns the retry record so
        // erasing the target cannot discard a peer tombstone awaiting delivery.
        let target = match content.value.as_ref() {
            Some(ramflux_protocol::message::content::Value::Edit(value)) => value.target.as_ref(),
            Some(ramflux_protocol::message::content::Value::Reaction(value)) => {
                value.target.as_ref()
            }
            Some(ramflux_protocol::message::content::Value::Receipt(value)) => {
                value.targets.first()
            }
            _ => None,
        };
        let owner =
            ramflux_protocol::encode_base64url(target.map_or(&identity.id, |target| &target.id));
        let plaintext_hash = *blake3::hash(body).as_bytes();
        let key = format!(
            "routed/sealed-send/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.message.sealed-send.key.v2",
                &ramflux_protocol::canonical_json_bytes(&(group_id, epoch, plaintext_hash))?,
            )
        );
        Ok(Some(Self { owner, key, epoch }))
    }

    pub(super) fn load(&self, client: &RamfluxClient) -> Result<Option<SealedShared>, SdkError> {
        let db = client.account_db()?;
        if db.message_is_deleted(&self.owner)? {
            return Err(invalid("cannot resend erased content"));
        }
        let Some(stored) = db.load_actor_state::<Stored>(&self.key)? else { return Ok(None) };
        if stored.epoch != self.epoch {
            return Err(invalid("sealed retry record epoch mismatch"));
        }
        let message = ramflux_protocol::decode_base64url(&stored.message)
            .map_err(|_| invalid("sealed retry record malformed"))?;
        let opening = stored
            .opening
            .map(|encoded| {
                ramflux_protocol::decode_base64url(&encoded)
                    .ok()
                    .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                    .map(Zeroizing::new)
                    .ok_or_else(|| invalid("sealed retry record malformed"))
            })
            .transpose()?;
        Ok(Some(SealedShared { message, epoch: stored.epoch, opening }))
    }

    pub(super) fn persist(
        &self,
        client: &RamfluxClient,
        shared: &SealedShared,
    ) -> Result<(), SdkError> {
        client.account_db()?.persist_message_actor_state(
            &self.owner,
            &self.key,
            &Stored {
                epoch: shared.epoch,
                message: ramflux_protocol::encode_base64url(&shared.message),
                opening: shared
                    .opening
                    .as_ref()
                    .map(|opening| ramflux_protocol::encode_base64url(opening.as_slice())),
            },
        )?;
        Ok(())
    }
}
