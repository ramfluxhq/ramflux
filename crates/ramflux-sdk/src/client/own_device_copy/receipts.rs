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

pub(super) fn remember(
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

pub(super) struct Replay {
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

    /// Called only after the gateway confirms this exact inbox entry's ACK.
    pub(crate) fn record_own_copy_ack(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        if entry.envelope.delivery_class != ramflux_protocol::DeliveryClass::SelfDeviceControl {
            return Ok(());
        }
        // Malformed/quarantined controls still need ACKs; only an existing commit can be marked.
        let Ok(bytes) = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        else {
            return Ok(());
        };
        let Some(raw) = bytes.strip_prefix(PREFIX).filter(|_| bytes.len() <= MAX_PACKET_BYTES)
        else {
            return Ok(());
        };
        let Ok(packet) = ramflux_protocol::parse_i_json::<OwnDeviceMessage>(raw) else {
            return Ok(());
        };
        let db = self.account_db()?;
        let target = self.owned_device_identity()?;
        let key = replay_key(db, &target, entry, &packet.id)?;
        let Some(mut committed) = db.load_actor_state::<Committed>(&key)? else {
            return Ok(());
        };
        let fingerprint =
            packet_fingerprint(db, &ramflux_protocol::hash_base64url(DOMAIN, &bytes))?;
        if committed.fingerprint != fingerprint {
            return Ok(());
        }
        committed.acknowledged = true;
        db.persist_actor_state(&key, &committed)?;
        let receipt_key = format!("{RECEIPTS}{}", packet.id);
        if let Some(mut receipt) = db.load_actor_state::<Receipt>(&receipt_key)? {
            receipt.acknowledged = true;
            db.persist_bound_message_actor_state(&receipt_key, &receipt)?;
        }
        Ok(())
    }
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
        assert!(matches!(result, Err(SdkError::InboundPending(_))));
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
