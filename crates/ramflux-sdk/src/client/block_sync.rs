// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Block decisions replicated between the account's own devices (BLOCK-PERSIST-01).
//!
//! After a local block or unblock, the full block set (every `blocked` and `lifted` decision
//! with its Lamport counter) is staged to the other devices of this root as one
//! `BlockDecisionSync` control, through the same authenticated own-device fan-out as AgentSync.
//! A receiver authorizes the sender (own root, current device epoch) and applies each decision by
//! the storage ordering `(counter, device_id, state rank)`. No new key and no clear text reach
//! the home.
use crate::bus::own_device_copy;
use crate::client::generated_control::control_from_payload;
use crate::client::identity_authority::HeadUse;
use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
use crate::error::GeneratedRefusalCode;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_storage::{BlockDecisionRecord, KIND_CONTACT_REQUEST, KIND_FRIEND_LINK};

/// Domain of the local message id of one block-set packet.
const SEND_DOMAIN: &str = "ramflux.sdk.block_decision_sync.v1";
/// Conversation scope prefix of the block-set packets (one per owner root).
const SCOPE_PREFIX: &str = "block-sync:";
/// Upper bound on decisions in one packet; a larger set is refused, never truncated.
pub(crate) const MAX_BLOCK_DECISIONS: usize = 65_536;

fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused { code: GeneratedRefusalCode::Content, reason: reason.into() }
}

fn to_proto(record: &BlockDecisionRecord) -> Result<g::BlockDecision, SdkError> {
    Ok(g::BlockDecision {
        root: record.root.clone(),
        state: record.state.clone(),
        counter: u64::try_from(record.counter).map_err(|_| refused("block counter range"))?,
        device_id: record.device_id.clone(),
        decided_at: record.decided_at,
        kind: record.kind.clone(),
    })
}

fn from_proto(decision: &g::BlockDecision) -> Result<BlockDecisionRecord, SdkError> {
    let kind = match decision.kind.as_str() {
        KIND_CONTACT_REQUEST | KIND_FRIEND_LINK => decision.kind.clone(),
        _ => return Err(refused("block decision kind")),
    };
    Ok(BlockDecisionRecord {
        kind,
        root: decision.root.clone(),
        state: decision.state.clone(),
        counter: i64::try_from(decision.counter).map_err(|_| refused("block counter range"))?,
        device_id: decision.device_id.clone(),
        decided_at: decision.decided_at,
    })
}

impl RamfluxClient {
    /// Stages the full block set for the other devices of this root (after a local block or
    /// unblock). An empty set stages nothing.
    /// # Errors
    /// Refuses a missing owner or device, an oversized set, or a failed stage.
    pub(crate) fn stage_block_decisions(&self, now: i64) -> Result<(), SdkError> {
        let Some((scope, body)) = self.block_set_body()? else {
            return Ok(());
        };
        let id = ramflux_protocol::hash_base64url(SEND_DOMAIN, &body);
        own_device_copy::stage(
            self,
            OwnMessageInput {
                payload_kind: OwnPayloadKind::Control,
                id: &id,
                created_at: now,
                conversation: &scope,
                group: None,
                body: &body,
            },
            None,
        )
    }

    /// Stages the full block set to one sibling only: the pairing backfill of a new device,
    /// sent after its add-device history transfer. An empty set stages nothing.
    /// # Errors
    /// As `stage_block_decisions`, and a target outside this root.
    pub(crate) fn stage_block_decisions_to(
        &self,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
        now: i64,
    ) -> Result<(), SdkError> {
        let Some((scope, body)) = self.block_set_body()? else {
            return Ok(());
        };
        let id = ramflux_protocol::hash_base64url(SEND_DOMAIN, &body);
        own_device_copy::stage_to(
            self,
            OwnMessageInput {
                payload_kind: OwnPayloadKind::Control,
                id: &id,
                created_at: now,
                conversation: &scope,
                group: None,
                body: &body,
            },
            target,
        )
    }

    /// The encoded block-set control with its conversation scope, or `None` when empty.
    fn block_set_body(&self) -> Result<Option<(String, Vec<u8>)>, SdkError> {
        let records = self.account_db()?.block_decision_records()?;
        if records.is_empty() {
            return Ok(None);
        }
        if records.len() > MAX_BLOCK_DECISIONS {
            return Err(refused("block set too large"));
        }
        let owner = self.own_account_anchor()?;
        let device = self.own_device_ref()?;
        let decisions = records.iter().map(to_proto).collect::<Result<Vec<_>, _>>()?;
        let packet = g::BlockDecisionSync {
            owner_anchor: owner.clone(),
            source: Some(g::QualifiedDevice {
                account_anchor: device.account_anchor.clone(),
                device_id: device.device_id.clone(),
                device_epoch: device.device_epoch,
            }),
            decisions,
        };
        let body = control_from_payload(g::control::Payload::BlockSync(packet))?.encode_to_vec();
        Ok(Some((format!("{SCOPE_PREFIX}{owner}"), body)))
    }

    /// Receive authorization of one `BlockDecisionSync`: the sender must be an authenticated
    /// device of this root at its current epoch, and the packet must name it as source.
    /// # Errors
    /// Refuses endpoint, root, epoch, size or kind mismatches before any effect.
    pub(crate) fn authorize_generated_block_sync(
        &self,
        entry: &GatewayInboxEntry,
        packet: &g::BlockDecisionSync,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let own_root = self.own_account_anchor()?;
        let declared = packet.source.as_ref().ok_or_else(|| refused("block sync source missing"))?;
        if packet.owner_anchor != own_root
            || source.root_commitment() != own_root
            || declared.account_anchor != source.root_commitment()
            || declared.device_id != source.device_id()
        {
            return Err(refused("block sync endpoints do not match the authenticated device"));
        }
        if self.device_epoch_of(&source)? != declared.device_epoch {
            return Err(refused("block sync device epoch is not current"));
        }
        if packet.decisions.len() > MAX_BLOCK_DECISIONS {
            return Err(refused("block set too large"));
        }
        for decision in &packet.decisions {
            from_proto(decision)?;
        }
        Ok(())
    }

    /// Applies an authorized block set. Each decision supersedes the local one only by the
    /// storage order; a restored device's pending marker is cleared (a sibling answered).
    /// # Errors
    /// Returns the authorization refusal or a storage error; no partial state is left behind
    /// because the whole set is applied in one write transaction.
    pub(crate) fn apply_generated_block_sync(
        &self,
        entry: &GatewayInboxEntry,
        packet: &g::BlockDecisionSync,
    ) -> Result<(), SdkError> {
        self.authorize_generated_block_sync(entry, packet)?;
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            for decision in &packet.decisions {
                db.apply_block_decision(&from_proto(decision)?)?;
            }
            db.clear_block_sync_pending()?;
            Ok(())
        })
    }
}
