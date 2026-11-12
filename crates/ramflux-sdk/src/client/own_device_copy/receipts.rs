// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, identity-free commit evidence survives disposable receipt eviction.
use super::{DOMAIN, MAX_PACKET_BYTES, OwnDeviceMessage, PREFIX, RECEIPTS, Receipt, invalid};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_storage::AccountDb;
use serde::{Deserialize, Serialize};

// Ten events per second for the existing 900-second retention window, with two windows of room.
const STREAM_WINDOW_ROWS: u32 = 10 * 900;
pub(crate) const MAX_DELIVERY_ROWS: u32 = STREAM_WINDOW_ROWS * 2;
const REPLAYS: &str = "own-device/committed-packet/";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Committed {
    fingerprint: String,
    valid_until: i64,
    expires_at: i64,
    acknowledged: bool,
}

pub(super) fn replay_key(
    db: &AccountDb,
    target: &ramflux_crypto::RootQualifiedDeviceRef,
    entry: &GatewayInboxEntry,
    id: &str,
) -> Result<String, SdkError> {
    // Source wire fields bind a previously authenticated packet, not a new device authority.
    // A first copy still discovers and verifies its current source manifest below this lookup.
    let binding = ramflux_protocol::canonical_json_bytes(&(
        DOMAIN,
        target.storage_key(),
        &entry.envelope.source_principal_id,
        &entry.envelope.source_device_id,
        id,
    ))?;
    Ok(format!("{REPLAYS}{}", private_digest(db, &binding)?))
}

fn private_digest(db: &AccountDb, binding: &[u8]) -> Result<String, SdkError> {
    let key = db.routed_seen_key(binding)?;
    Ok(key.strip_prefix("routed/seen/").ok_or_else(|| invalid("own-copy replay key"))?.to_owned())
}

pub(super) fn packet_fingerprint(db: &AccountDb, fingerprint: &str) -> Result<String, SdkError> {
    private_digest(
        db,
        &ramflux_protocol::canonical_json_bytes(&("ramflux.own_copy.fingerprint.v1", fingerprint))?,
    )
}

pub(super) fn committed(
    db: &AccountDb,
    key: &str,
    fingerprint: &str,
    now: i64,
) -> Result<bool, SdkError> {
    let Some(record) = db.load_actor_state::<Committed>(key)? else { return Ok(false) };
    if record.fingerprint != fingerprint {
        return Err(invalid("own-device message id conflict"));
    }
    if record.valid_until < now {
        return Err(invalid("own-device replay scope or lifetime mismatch"));
    }
    Ok(true)
}

pub(crate) fn remember(
    db: &AccountDb,
    key: &str,
    fingerprint: &str,
    valid_until: i64,
    acknowledged: bool,
    now: i64,
) -> Result<(), SdkError> {
    db.write_transaction(|| {
        db.maintain_own_copy_delivery(now, MAX_DELIVERY_ROWS)?;
        let old = db.load_actor_state::<Committed>(key)?;
        if old.as_ref().is_some_and(|old| old.fingerprint != fingerprint) {
            return Err(invalid("own-device message id conflict"));
        }
        let acknowledged = acknowledged || old.as_ref().is_some_and(|old| old.acknowledged);
        if old.is_none() && db.own_copy_actor_usage(REPLAYS)?.0 >= u64::from(MAX_DELIVERY_ROWS) {
            return Err(SdkError::InboundPending(
                "own-device replay window full; retry later".into(),
            ));
        }
        db.persist_actor_state(
            key,
            &Committed {
                fingerprint: fingerprint.into(),
                valid_until,
                expires_at: valid_until.saturating_add(300),
                acknowledged,
            },
        )?;
        Ok(())
    })
}

pub(crate) struct Replay {
    pub key: String,
    pub fingerprint: String,
    pub committed: bool,
}

impl RamfluxClient {
    pub(super) fn own_copy_replay(
        &self,
        entry: &GatewayInboxEntry,
        packet: &OwnDeviceMessage,
        bytes: &[u8],
        now: i64,
    ) -> Result<Replay, SdkError> {
        let db = self.account_db()?;
        let target = self.owned_device_identity()?;
        let key = replay_key(db, &target, entry, &packet.id)?;
        let wire_fingerprint = ramflux_protocol::hash_base64url(DOMAIN, bytes);
        let fingerprint = packet_fingerprint(db, &wire_fingerprint)?;
        let committed = if committed(db, &key, &fingerprint, now)? {
            true
        } else if let Some(old) =
            db.load_actor_state::<Receipt>(&format!("{RECEIPTS}{}", packet.id))?
        {
            old.validate(
                db,
                &entry.envelope.source_device_id,
                target.device_id(),
                &wire_fingerprint,
                now,
            )?;
            remember(db, &key, &fingerprint, old.valid_until, old.acknowledged, now)?;
            true
        } else {
            false
        };
        Ok(Replay { key, fingerprint, committed })
    }

    /// Legacy live ACK path only (the gateway inbox ACK helper): called after the gateway confirms this
    /// exact inbox entry's ACK. The WA path never calls it; it marks through the locator's
    /// [`OwnCopyAckBinding`] inside the settlement transaction. Retired with the legacy path.
    pub(crate) fn record_own_copy_ack(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        match self.own_copy_ack_binding(entry)? {
            Some(binding) => Ok(mark_own_copy_acknowledged(self.account_db()?, &binding)?),
            None => Ok(()),
        }
    }

    /// The existing replay-marker and receipt keys an own-copy entry commits to, for the W1
    /// locator. `None` for non-own-copy or malformed controls (they still get ACKs, but there
    /// is nothing to mark).
    pub(crate) fn own_copy_ack_binding(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<OwnCopyAckBinding>, SdkError> {
        if entry.envelope.delivery_class == ramflux_protocol::DeliveryClass::Message {
            let db = self.account_db()?;
            let receipt_key = format!("{RECEIPTS}{}", entry.envelope.envelope_id);
            if db.load_actor_state::<Receipt>(&receipt_key)?.is_none() {
                return Ok(None);
            }
            let target = self.owned_device_identity()?;
            let key = replay_key(db, &target, entry, &entry.envelope.envelope_id)?;
            let fingerprint = packet_fingerprint(db, &entry.envelope.payload_hash)?;
            // Settlement marks already committed content even if its display/delivery
            // lifetime expired while the gateway ACK was in flight.
            if db
                .load_actor_state::<Committed>(&key)?
                .is_none_or(|record| record.fingerprint != fingerprint)
            {
                return Ok(None);
            }
            return Ok(Some(OwnCopyAckBinding { committed_key: key, receipt_key, fingerprint }));
        }
        if entry.envelope.delivery_class != ramflux_protocol::DeliveryClass::SelfDeviceControl {
            return Ok(None);
        }
        let Ok(bytes) = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        else {
            return Ok(None);
        };
        let Some(raw) = bytes.strip_prefix(PREFIX).filter(|_| bytes.len() <= MAX_PACKET_BYTES)
        else {
            return Ok(None);
        };
        let Ok(packet) = ramflux_protocol::parse_i_json::<OwnDeviceMessage>(raw) else {
            return Ok(None);
        };
        let db = self.account_db()?;
        let target = self.owned_device_identity()?;
        Ok(Some(OwnCopyAckBinding {
            committed_key: replay_key(db, &target, entry, &packet.id)?,
            receipt_key: format!("{RECEIPTS}{}", packet.id),
            fingerprint: packet_fingerprint(db, &ramflux_protocol::hash_base64url(DOMAIN, &bytes))?,
        }))
    }
}

/// Opaque keys of the existing own-copy replay marker and receipt, stored in the W1 locator so
/// a terminal WA result marks them without the inbox entry. No body, no content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnCopyAckBinding {
    pub committed_key: String,
    pub receipt_key: String,
    pub fingerprint: String,
}

/// Marks the existing `Committed` replay marker and `Receipt` acknowledged. A missing marker or
/// a fingerprint mismatch is left untouched (nothing committed under that key to acknowledge).
/// Runs inside the caller's transaction.
pub(crate) fn mark_own_copy_acknowledged(
    db: &AccountDb,
    binding: &OwnCopyAckBinding,
) -> Result<(), ramflux_storage::StorageError> {
    let Some(mut committed) = db.load_actor_state::<Committed>(&binding.committed_key)? else {
        return Ok(());
    };
    if committed.fingerprint != binding.fingerprint {
        return Ok(());
    }
    committed.acknowledged = true;
    db.persist_actor_state(&binding.committed_key, &committed)?;
    if let Some(mut receipt) = db.load_actor_state::<Receipt>(&binding.receipt_key)? {
        receipt.acknowledged = true;
        db.persist_bound_message_actor_state(&binding.receipt_key, &receipt)?;
    }
    Ok(())
}

/// Test support: whether the replay marker / receipt carry the acknowledged flag.
#[cfg(test)]
pub(crate) fn own_copy_acknowledged(
    db: &AccountDb,
    binding: &OwnCopyAckBinding,
) -> Result<(Option<bool>, Option<bool>), ramflux_storage::StorageError> {
    Ok((
        db.load_actor_state::<Committed>(&binding.committed_key)?.map(|row| row.acknowledged),
        db.load_actor_state::<Receipt>(&binding.receipt_key)?.map(|row| row.acknowledged),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_has_bounded_vm_work_at_the_full_18000_marker_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let index = ramflux_storage::AccountIndex::open(root.path())?;
        index.create_account("acct", "principal")?;
        let key = ramflux_storage::AccountDbKey::derive("acct", b"receipt-work-test");
        let db = AccountDb::open(&index, "acct", &key)?;
        db.write_transaction(|| {
            for i in 0..MAX_DELIVERY_ROWS {
                db.persist_actor_state(
                    &format!("{REPLAYS}{i:05}"),
                    &Committed {
                        fingerprint: "fixture".into(),
                        valid_until: 600,
                        expires_at: 900,
                        acknowledged: false,
                    },
                )?;
            }
            Ok::<_, SdkError>(())
        })?;
        // A fresh copy at capacity exercises the new-marker usage check without evicting proofs.
        let (result, steps) = db.measure_sqlite_vm_steps(|| {
            remember(&db, &format!("{REPLAYS}new"), "new", 600, false, 0)
        })?;
        println!("remember at 18,000 markers (full): vm_steps={steps}, budget=2000");
        assert!(steps < 2000, "remember exceeded VM work budget: {steps} >= 2000");
        assert!(matches!(
            result,
            Err(SdkError::InboundPending(_)
                | SdkError::SenderManifestRequired { .. }
                | SdkError::FreshHeadRequired { .. })
        ));
        assert!(!db.actor_state_exists(&format!("{REPLAYS}new"))?);
        // Leave a slot so the same measurement also covers the actual insert/trigger path.
        db.remove_actor_state(&format!("{REPLAYS}00000"))?;
        let (result, steps) = db.measure_sqlite_vm_steps(|| {
            remember(&db, &format!("{REPLAYS}new"), "new", 600, false, 0)
        })?;
        result?;
        println!("remember at 17,999 markers (insert): vm_steps={steps}, budget=2000");
        assert!(steps < 2000, "remember insert exceeded VM work budget: {steps} >= 2000");
        assert_eq!(db.own_copy_actor_usage(REPLAYS)?.0, u64::from(MAX_DELIVERY_ROWS));
        Ok(())
    }
}
