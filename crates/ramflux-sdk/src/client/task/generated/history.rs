// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant history authentication. Same-root provenance, membership admission,
//! replay and persistence remain the import owner's responsibility.
use super::{carrier, g, invalid};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;

const MAX_EXPORT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 289;

impl RamfluxClient {
    /// Encode candidate history without changing original signatures or witnesses.
    /// # Errors
    /// Rejects invalid nested authentication, context bindings or resource bounds.
    pub fn encode_generated_task_history_export(
        &self,
        history: &g::TaskHistoryExport,
    ) -> Result<Vec<u8>, SdkError> {
        let bytes = g::Task { payload: Some(g::task::Payload::OwnHistory(history.clone())) }
            .encode_to_vec();
        self.decode_generated_task_history_export(&bytes)?;
        Ok(bytes)
    }

    /// Authenticate received history fields against existing device/root pins.
    /// Returned witnesses and kind flags remain same-root historical assertions;
    /// they never establish current membership or install keys. The caller must
    /// authenticate the same-root source and check committed prefixes before import.
    /// # Errors
    /// Rejects noncanonical bytes before hashing, malformed bindings, invalid
    /// nested signatures, missing fields and export/page/count limits.
    pub fn decode_generated_task_history_export(
        &self,
        bytes: &[u8],
    ) -> Result<g::TaskHistoryExport, SdkError> {
        if bytes.len() > MAX_EXPORT_BYTES {
            return Err(invalid("task history export byte budget exceeded"));
        }
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("Task", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task history"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task history"));
        }
        let task = g::Task::decode(bytes).map_err(|_| invalid("invalid generated task history"))?;
        let Some(g::task::Payload::OwnHistory(history)) = task.payload else {
            return Err(invalid("generated task history required"));
        };
        if history.packets.len() > 100 {
            return Err(invalid("task history export packet count exceeded"));
        }
        let metadata = history
            .metadata
            .as_ref()
            .ok_or_else(|| invalid("task history export metadata missing"))?;
        if (metadata.skipped_items > 0 || metadata.next_cursor.is_some()) && !metadata.truncated {
            return Err(invalid("task history export truncation metadata mismatch"));
        }
        if let Some(cursor) = &metadata.next_cursor {
            identifier(cursor)?;
        }
        for packet in &history.packets {
            self.check_generated_task_history_packet(packet)?;
        }
        Ok(history)
    }

    /// Check a candidate page against an authenticated context and committed prefix.
    /// This is read-only and does not admit or store any event.
    /// # Errors
    /// Rejects context, base or prefix mismatches and invalid nested content.
    pub fn check_generated_task_history_page(
        &self,
        packet: &g::TaskOwnPacket,
        context: &g::OwnContext,
        committed_prefix: &[g::TaskCarrier],
    ) -> Result<(), SdkError> {
        if packet.context.as_ref() != Some(context)
            || usize::try_from(packet.base).ok() != Some(committed_prefix.len())
            || packet.prefix_hash != prefix_hash(committed_prefix)?
        {
            return Err(invalid("task history page context or prefix mismatch"));
        }
        self.check_generated_task_history_packet(packet)
    }

    fn check_generated_task_history_packet(
        &self,
        packet: &g::TaskOwnPacket,
    ) -> Result<(), SdkError> {
        super::super::check_delivery_size(packet.encoded_len())?;
        let context =
            packet.context.as_ref().ok_or_else(|| invalid("task history context missing"))?;
        // Parse native shared-state documents canonically without importing them.
        let native_context = crate::client::surface::OwnContext::try_from(context)?;
        if let Some(group) = &native_context.group
            && let Some(snapshot) = &group.shared_state
        {
            if snapshot.group_id != group.group_id
                || snapshot.epoch != group.group_epoch
                || snapshot.genesis.conversation_id != context.conversation_id
            {
                return Err(invalid("task history native group binding mismatch"));
            }
            ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?;
        }
        let history =
            packet.history.as_ref().ok_or_else(|| invalid("task history events missing"))?;
        identifier(&context.conversation_id)?;
        identifier(&packet.prefix_hash)?;
        if history.events.is_empty()
            || history.events.len() > MAX_EVENTS
            || packet.base > MAX_EVENTS as u64
            || packet.base.saturating_add(history.events.len() as u64) > MAX_EVENTS as u64
            || packet.manifests.len() > 64
        {
            return Err(invalid("task history context or count mismatch"));
        }
        for principal in &context.participants {
            identifier(principal)?;
        }
        if packet.base == 0 && packet.prefix_hash != prefix_hash(&[])? {
            return Err(invalid("task history empty prefix mismatch"));
        }
        for manifest in &packet.manifests {
            self.check_generated_task_manifest(manifest, &manifest.principal_id)?;
        }
        for pin in &packet.pins {
            if context.group.as_ref().is_none_or(|group| group.group_id != pin.group_id) {
                return Err(invalid("task history pin group mismatch"));
            }
            identifier(&pin.device_id)?;
            if let Some(principal) = &pin.principal_id
                && self.task_signer_key(principal, &pin.device_id)? != pin.signing_public_key
            {
                return Err(invalid("task history pin key mismatch"));
            }
        }
        let mut task_id = None;
        for accepted in &history.events {
            let id = self.check_generated_task_history_event(accepted, context)?;
            if task_id.as_ref().is_some_and(|previous| previous != &id) {
                return Err(invalid("task history task binding mismatch"));
            }
            task_id = Some(id);
        }
        Ok(())
    }

    fn check_generated_task_history_event(
        &self,
        accepted: &g::TaskAcceptedEvent,
        context: &g::OwnContext,
    ) -> Result<String, SdkError> {
        let carrier =
            accepted.carrier.as_ref().ok_or_else(|| invalid("task history carrier missing"))?;
        let bytes =
            g::Task { payload: Some(g::task::Payload::Carrier(carrier.clone())) }.encode_to_vec();
        self.decode_generated_task_carrier(&bytes)?;
        if carrier.conversation_id != context.conversation_id
            || self.task_signer_key(&carrier.principal_id, &carrier.device_id)?
                != accepted.public_key
        {
            return Err(invalid("task history signer or context mismatch"));
        }
        let event = carrier.event.as_ref().ok_or_else(|| invalid("task history event missing"))?;
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        let signer = ramflux_protocol::TaskSigner {
            principal_id: &carrier.principal_id,
            actor_type: ramflux_protocol::ActorType::Human,
            signing_key_id: &event
                .signed
                .as_ref()
                .ok_or_else(|| invalid("task history signer missing"))?
                .signing_key_id,
            public_key_base64url: &public,
        };
        let native = Self::decode_generated_task_event(&event.encode_to_vec(), &signer)?;
        if let Some(certificate) = &accepted.decision_certificate {
            self.decode_generated_task_certificate(&certificate.encode_to_vec())?;
            carrier::check_resolution(carrier, certificate)?;
            if !matches!(
                certificate.phase.as_ref().and_then(|phase| phase.value.as_ref()),
                Some(g::task_certificate_phase::Value::Committed(_))
            ) || certificate.carrier_hash.as_deref()
                != Some(carrier::carrier_hash(carrier).as_str())
            {
                return Err(invalid("task history committed certificate mismatch"));
            }
        } else if matches!(native.event(), ramflux_protocol::TaskEventBody::Resolve(_)) {
            return Err(invalid("task history resolution certificate missing"));
        }
        match &accepted.membership {
            Some(witness) => {
                let group = context.group.as_ref();
                if witness.conversation != context.conversation_id
                    || witness.at != accepted.received_at
                    || witness.group.as_deref() != group.map(|group| group.group_id.as_str())
                    || witness.epoch.is_some() != group.is_some()
                    || witness
                        .epoch
                        .is_some_and(|epoch| group.is_none_or(|group| epoch > group.group_epoch))
                    || !witness.members.contains(&carrier.principal_id)
                {
                    return Err(invalid("task history membership witness mismatch"));
                }
                for member in &witness.members {
                    identifier(member)?;
                }
            }
            None if context.group.is_some() => {
                return Err(invalid("task history group witness missing"));
            }
            None => (),
        }
        if context.group.is_none() && !context.participants.contains(&carrier.principal_id) {
            return Err(invalid("task history direct participant mismatch"));
        }
        Ok(native.event().task_id().to_owned())
    }
}

fn identifier(value: &str) -> Result<(), SdkError> {
    if value.trim().is_empty()
        || value.len() > 256
        || !ramflux_protocol::text_safety::single_line_is_safe(value)
    {
        return Err(invalid("invalid task history identifier"));
    }
    Ok(())
}

pub(super) fn prefix_hash(events: &[g::TaskCarrier]) -> Result<String, SdkError> {
    let bytes = events.iter().map(prost::Message::encode_to_vec).collect::<Vec<_>>();
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.task.history_prefix.v1",
        &ramflux_protocol::canonical_json_bytes(&bytes)?,
    ))
}
