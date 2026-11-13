// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persisted inboxes require the server deadline of every pending delivery.
use super::{BTreeMap, CursorAckState, Deserialize, InboxEntry, OpaqueDeviceInbox, pending_rows};

#[derive(Deserialize)]
pub(super) struct StoredInbox {
    next_seq: BTreeMap<String, u64>,
    #[serde(default)]
    aborted_ranges: BTreeMap<String, Vec<(u64, u64)>>,
    #[serde(default)]
    incarnations: BTreeMap<String, String>,
    #[serde(with = "pending_rows")]
    pending: BTreeMap<String, BTreeMap<crate::inbox_page::SequenceKey, InboxEntry>>,
    cursors: BTreeMap<String, CursorAckState>,
    #[serde(default)]
    retain_until: BTreeMap<String, BTreeMap<u64, i64>>,
}

impl TryFrom<StoredInbox> for OpaqueDeviceInbox {
    type Error = &'static str;

    fn try_from(stored: StoredInbox) -> Result<Self, Self::Error> {
        for (target, entries) in &stored.pending {
            for entry in entries.values() {
                if stored
                    .retain_until
                    .get(target)
                    .is_none_or(|rows| !rows.contains_key(&entry.inbox_seq))
                {
                    return Err("unsupported inbox snapshot: missing server retention deadline");
                }
            }
        }
        Ok(Self {
            next_seq: stored.next_seq,
            aborted_ranges: stored.aborted_ranges,
            incarnations: stored.incarnations,
            pending: stored.pending,
            cursors: stored.cursors,
            retain_until: stored.retain_until,
            ..Self::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeCoreError;
    use crate::router_store::publication::tests::entry;

    #[test]
    fn pending_inbox_snapshot_requires_server_deadlines() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut inbox = OpaqueDeviceInbox::new();
        inbox.restore_pending_entry_until(entry(1), 1_760_000_100);
        let mut value = serde_json::to_value(&inbox)?;
        let restored: OpaqueDeviceInbox = serde_json::from_value(value.clone())?;
        assert_eq!(restored.retain_until(&entry(1)), 1_760_000_100);
        value.as_object_mut().ok_or("inbox object")?.remove("retain_until");
        assert!(serde_json::from_value::<OpaqueDeviceInbox>(value).is_err());
        Ok(())
    }

    #[test]
    fn ack_and_nack_without_sequence_are_refused_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let row = entry(1);
        let mut inbox = OpaqueDeviceInbox::new();
        inbox.restore_pending_entry_until(row.clone(), i64::MAX);
        let before = serde_json::to_value(&inbox)?;
        let ack = ramflux_protocol::Ack {
            schema: "ramflux.ack.v1".into(),
            version: 1,
            domain: "ramflux.ack.v1".into(),
            ext: ramflux_protocol::Ext::default(),
            signed: row.envelope.signed.clone(),
            ack_id: "ack".into(),
            envelope_id: row.envelope.envelope_id.clone(),
            receiver_device_id: "receiver".into(),
            received_at: 1_760_000_010,
            cursor_after: None,
        };
        let nack = ramflux_protocol::Nack {
            schema: "ramflux.nack.v1".into(),
            version: 1,
            domain: "ramflux.nack.v1".into(),
            ext: ramflux_protocol::Ext::default(),
            signed: row.envelope.signed,
            nack_id: "nack".into(),
            envelope_id: row.envelope.envelope_id,
            receiver_device_id: "receiver".into(),
            reason: ramflux_protocol::NackReason::RateLimited,
            received_at: 1_760_000_010,
            retry_after: Some(30),
            proof_hash: None,
            new_home_node_hint: None,
        };
        let errors = [
            inbox
                .apply_ack_for_target("target", &ack)
                .err()
                .ok_or("test: missing ACK selector accepted")?,
            inbox
                .apply_nack_for_target("target", &nack)
                .err()
                .ok_or("test: missing NACK selector accepted")?,
        ];
        for error in errors {
            assert!(
                matches!(&error, NodeCoreError::MissingInboxSequence { target, envelope_id } if target == "target" && envelope_id == &ack.envelope_id),
                "missing selector must carry the delivery target and envelope: {error}"
            );
            assert!(
                error.to_string().contains("inbox_seq")
                    && error.to_string().contains(&ack.envelope_id),
                "selector diagnostic must identify the field and envelope"
            );
        }
        let mut invalid_ack = ack;
        invalid_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(0));
        let error = inbox
            .apply_ack_for_target("target", &invalid_ack)
            .err()
            .ok_or("test: invalid ACK selector accepted")?;
        assert!(
            matches!(error, NodeCoreError::InvalidInboxSequence { target, envelope_id } if target == "target" && envelope_id == invalid_ack.envelope_id),
            "invalid selector must have its own typed context"
        );
        assert_eq!(
            serde_json::to_value(&inbox)?,
            before,
            "selector refusal must not mutate pending deliveries"
        );
        Ok(())
    }
}
