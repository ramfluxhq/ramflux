// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rekey retained replay evidence only after authenticating its original sender.
use super::{
    RamfluxClient, SdkError,
    committed::{Committed, committed_key},
    control::a2i_key,
};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_sync::A2iControlEvent;
use serde_json::Value;

impl RamfluxClient {
    pub(super) fn upgrade_replay_identity(
        &self,
        source: &RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let marker = format!("identity/replay-upgrade/v3/{}", source.storage_key());
        if db.actor_state_exists(&marker)? {
            return Ok(());
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            self.upgrade_a2i_identity(source)?;
            for prefix in ["routed/committed/", "legacy/replay/committed/"] {
                for key in db.actor_state_keys(prefix)? {
                    let Some(value) = db.load_actor_state::<Value>(&key)? else { continue };
                    let Ok(receipt) = serde_json::from_value::<Committed>(value.clone()) else {
                        if prefix == "routed/committed/" {
                            quarantine(self, &key, "committed", &value)?;
                        }
                        continue;
                    };
                    if receipt.entry.envelope.source_device_id != source.device_id() {
                        continue;
                    }
                    let Ok(verified) = self.authenticated_device_identity(&receipt.entry) else {
                        if prefix == "routed/committed/" {
                            quarantine(self, &key, "committed", &value)?;
                        }
                        continue;
                    };
                    if verified != *source {
                        continue;
                    }
                    let next = committed_key(source, &receipt.entry.envelope.envelope_id)?;
                    if key == next {
                        continue;
                    }
                    // The signed envelope, not the old name-only key, proves who owns this row.
                    if let Some(current) = db.load_actor_state::<Committed>(&next)? {
                        if current.entry.envelope.payload_hash
                            != receipt.entry.envelope.payload_hash
                        {
                            return Err(super::invalid(
                                "legacy replay conflicts with authenticated payload",
                            ));
                        }
                    } else {
                        db.persist_actor_state(&next, &value)?;
                    }
                    let original = if prefix == "routed/committed/" {
                        key.clone()
                    } else {
                        let encoded = key.trim_start_matches(prefix);
                        String::from_utf8(
                            ramflux_protocol::decode_base64url(encoded)
                                .map_err(|_| super::invalid("invalid legacy replay provenance"))?,
                        )
                        .map_err(|_| super::invalid("invalid legacy replay provenance"))?
                    };
                    self.upgrade_control_receipt(source, &original, &next, &receipt)?;
                    db.remove_actor_state(&key)?;
                }
            }
            db.persist_actor_state(&marker, &true)?;
            Ok(())
        })
    }

    fn upgrade_control_receipt(
        &self,
        source: &RootQualifiedDeviceRef,
        old: &str,
        next: &str,
        receipt: &Committed,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let old = old.replace("routed/committed/", "routed/control/");
        let Some(mut event) = db.load_actor_state::<A2iControlEvent>(&old)? else { return Ok(()) };
        if self.bind_received_a2i_event(&mut event, &receipt.entry)? != *source {
            return Err(super::invalid("legacy control sender mismatch"));
        }
        let scoped = a2i_key(source, &event.event_id)?;
        if let Some(current) = db.load_actor_state::<A2iControlEvent>(&scoped)? {
            // Preserve an already root-qualified user's acknowledgement, never a bare-name decision.
            event.acknowledged = current.acknowledged;
            if event != current {
                return Err(super::invalid("legacy control conflicts with authenticated event"));
            }
        }
        db.persist_actor_state(&scoped, &event)?;
        db.persist_actor_state(&next.replace("routed/committed/", "routed/control/"), &event)?;
        if old != next.replace("routed/committed/", "routed/control/") {
            db.remove_actor_state(&old)?;
        }
        Ok(())
    }

    fn upgrade_a2i_identity(&self, source: &RootQualifiedDeviceRef) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for prefix in ["a2i/", "legacy/replay/a2i/"] {
            for key in db.actor_state_keys(prefix)? {
                let Some(value) = db.load_actor_state::<Value>(&key)? else { continue };
                let Ok(event) = serde_json::from_value::<A2iControlEvent>(value.clone()) else {
                    continue;
                };
                if event.source_device_id != source.device_id() {
                    continue;
                }
                match self.a2i_event_identity(&event) {
                    Ok(verified) if verified == *source => {
                        let next = a2i_key(source, &event.event_id)?;
                        if key != next {
                            if !db.actor_state_exists(&next)? {
                                db.persist_actor_state(&next, &event)?;
                            }
                            db.remove_actor_state(&key)?;
                        }
                    }
                    Err(_) if prefix == "a2i/" => quarantine(self, &key, "a2i", &value)?,
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
fn quarantine(
    client: &RamfluxClient,
    old: &str,
    kind: &str,
    value: &Value,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.persist_actor_state(
        &format!("legacy/replay/{kind}/{}", ramflux_protocol::encode_base64url(old.as_bytes())),
        value,
    )?;
    db.remove_actor_state(old)?;
    Ok(())
}
