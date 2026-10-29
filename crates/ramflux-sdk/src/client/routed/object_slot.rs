// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Object keys consume the same pair ratchet; deferred fetch never restores an older snapshot.
use super::{
    GatewayDirectMessage, GatewaySessionEngine, RamfluxClient, SdkDmEncryptedEnvelope, SdkError,
    SdkObjectKeySlot, dm_device_id_hash, invalid,
};
use crate::client::object::DeferredObjectKeySlot;
impl RamfluxClient {
    pub(crate) async fn make_pair_object_slot(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
        object_id: &str,
        key: &[u8; 32],
        conversation: &str,
    ) -> Result<SdkObjectKeySlot, SdkError> {
        let remote = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("object recipient missing"))?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        let local = &engine.config.device_id;
        let aad = slot_aad(object_id, local, remote, &bundle)?;
        let ciphertext = session.encrypt(key, &aad)?;
        if header
            .as_ref()
            .is_some_and(|header| header.initiator_device_id_hash == dm_device_id_hash(local))
        {
            self.account_db()?
                .persist_actor_state(&format!("dm-pair/local/{}", session.session_id), &true)?;
        }
        self.persist_pair(
            &self.local_device_identity(local)?,
            &self.device_identity(&Self::qualified_recipient(message)?)?,
            &bundle,
            &session,
        )?;
        self.finish_pair_retirement()?;
        Ok(SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v2".to_owned(),
            version: 2,
            object_id: object_id.to_owned(),
            conversation_id: conversation.to_owned(),
            recipient_device_id: remote.to_owned(),
            source_principal_commitment: Some(self.own_account_anchor()?),
            x3dh: header,
            ciphertext,
        })
    }
    fn slot_remote(
        &self,
        slot: &SdkObjectKeySlot,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, SdkError> {
        let mut candidates = std::collections::BTreeSet::new();
        if let Some(record) = self.account_db()?.load_actor_state::<serde_json::Value>(&format!(
            "dm-pair/session/{}",
            slot.ciphertext.session_id
        ))? && let Some(remote) = record["remote"].as_str()
        {
            let remote = self.device_reference(remote)?;
            if self
                .device_identity(&remote)
                .and_then(|identity| self.require_cached_root_authority(&identity))
                .is_ok()
            {
                candidates.insert(self.device_identity(&remote)?);
            }
        }
        if candidates.is_empty() || slot.source_principal_commitment.is_some() {
            candidates.clear();
            let mut after = String::new();
            loop {
                let ids = self.account_db()?.client_directory_ids("device", &after, 128)?;
                if ids.is_empty() {
                    break;
                }
                for id in &ids {
                    let raw =
                        crate::client::identity_authority::device_namespace::wire_device_id(id)?;
                    if dm_device_id_hash(&raw) == slot.ciphertext.sender_device_id_hash
                        && self
                            .device_identity(id)
                            .and_then(|identity| self.require_cached_root_authority(&identity))
                            .is_ok()
                        && slot.source_principal_commitment.as_ref().is_none_or(|expected| {
                            self.device_root(id).is_ok_and(|root| root == *expected)
                        })
                    {
                        candidates.insert(self.device_identity(id)?);
                    }
                }
                after = ids.last().cloned().ok_or_else(|| invalid("empty device page"))?;
            }
        }
        if candidates.len() != 1 {
            return Err(invalid("object slot requires an unambiguous root-qualified sender"));
        }
        candidates.into_iter().next().ok_or_else(|| invalid("object sender absent"))
    }
    pub(crate) fn decrypt_pair_object_slot(
        &self,
        slot: &SdkObjectKeySlot,
        current: Option<&mut ramflux_crypto::DmSession>,
    ) -> Result<DeferredObjectKeySlot, SdkError> {
        if slot.version != 2 || slot.schema != "ramflux.sdk.object_key_slot.dm.v2" {
            return Err(invalid("invalid pair object slot"));
        }
        let remote = self.slot_remote(slot)?;
        let local = &slot.recipient_device_id;
        if self.device_branch.as_ref().is_none_or(|branch| branch.device_id != *local) {
            return Err(invalid("object slot recipient mismatch"));
        }
        let envelope = SdkDmEncryptedEnvelope {
            source_principal_commitment: None,
            schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
            version: 2,
            x3dh: slot.x3dh.clone(),
            ciphertext: slot.ciphertext.clone(),
        };
        let (mut session, bundle) = self.recv_pair_session(
            &self.local_device_identity(local)?,
            &remote,
            "object-slot",
            &envelope,
        )?;
        if let Some(current) = current.as_ref() {
            if current.session_id != session.session_id {
                return Err(invalid("attachment slot differs from message pair session"));
            }
            session = (**current).clone();
        }
        let active = &mut session;
        let key = zeroize::Zeroizing::new(active.decrypt(
            &slot.ciphertext,
            &slot_aad(&slot.object_id, remote.device_id(), local, &bundle)?,
        )?);
        let object_key: [u8; 32] =
            key.as_slice().try_into().map_err(|_| invalid("invalid pair object key length"))?;
        if let Some(current) = current {
            *current = active.clone();
        }
        Ok(DeferredObjectKeySlot {
            object_key,
            session: Some(ramflux_crypto::DmSession::from_snapshot(active.snapshot())?),
            conversation_id: slot.conversation_id.clone(),
            commit_label: format!("object-slot:{}", slot.object_id),
            pair_slot: Some(slot.clone()),
            legacy_slot: None,
        })
    }
    pub(crate) fn persist_pair_slot_receipt(
        &self,
        slot: &SdkObjectKeySlot,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(&slot_receipt(slot)?, &true)?;
        self.account_db()?.persist_actor_state(
            &super::object_watermark(
                &slot.object_id,
                &self.local_device_identity(&slot.recipient_device_id)?,
            )?,
            &slot_receipt(slot)?,
        )?;
        Ok(())
    }
    pub(super) fn persist_message_slot_receipt(
        &self,
        message: &str,
        slot: &SdkObjectKeySlot,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_message_actor_state(message, &slot_receipt(slot)?, &true)?;
        db.persist_message_actor_state(
            message,
            &super::object_watermark(
                &slot.object_id,
                &self.local_device_identity(&slot.recipient_device_id)?,
            )?,
            &slot_receipt(slot)?,
        )?;
        Ok(())
    }
    pub(crate) fn commit_pair_object_slot(
        &self,
        slot: &SdkObjectKeySlot,
        key: &[u8; 32],
    ) -> Result<(), SdkError> {
        self.commit_pair_key_slot(slot, key, true)
    }
    pub(crate) fn commit_inline_pair_key_slot(
        &self,
        slot: &SdkObjectKeySlot,
        key: &[u8; 32],
    ) -> Result<(), SdkError> {
        self.commit_pair_key_slot(slot, key, false)
    }
    fn commit_pair_key_slot(
        &self,
        slot: &SdkObjectKeySlot,
        key: &[u8; 32],
        persistent_receipt: bool,
    ) -> Result<(), SdkError> {
        if persistent_receipt
            && self.account_db()?.load_actor_state::<bool>(&slot_receipt(slot)?)?.unwrap_or(false)
        {
            return Ok(());
        }
        // Rebase the key-slot receive onto the current ratchet, never a cached pre-download snapshot.
        let deferred = self.decrypt_pair_object_slot(slot, None)?;
        if &deferred.object_key != key {
            return Err(invalid("prepared object key mismatch"));
        }
        let remote = self.slot_remote(slot)?;
        let envelope = SdkDmEncryptedEnvelope {
            source_principal_commitment: None,
            schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
            version: 2,
            x3dh: slot.x3dh.clone(),
            ciphertext: slot.ciphertext.clone(),
        };
        let (_, bundle) = self.recv_pair_session(
            &self.local_device_identity(&slot.recipient_device_id)?,
            &remote,
            "object-slot",
            &envelope,
        )?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.commit_bootstrap_sequence(
                &self.local_device_identity(&slot.recipient_device_id)?,
                &remote,
                slot.x3dh.as_ref(),
                &slot.ciphertext.session_id,
            )?;
            let local = self.local_device_identity(&slot.recipient_device_id)?;
            let session =
                deferred.session.as_ref().ok_or_else(|| invalid("slot session missing"))?;
            self.persist_pair(&local, &remote, &bundle, session)?;
            if !persistent_receipt {
                // An own-device copy is the whole packet, so it confirms the pair like a routed
                // message. Crossed bootstraps from two own devices then converge on one session.
                self.confirm_pair(&local, &remote, session, false, slot.x3dh.is_some())?;
            }
            if persistent_receipt { self.persist_pair_slot_receipt(slot) } else { Ok(()) }
        })
    }
}
fn slot_aad(
    object: &str,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&(
        "ramflux.sdk.object.slot.aad.v2",
        object,
        dm_device_id_hash(sender),
        dm_device_id_hash(recipient),
        bundle,
        2_u32,
    ))?)
}
fn slot_receipt(slot: &SdkObjectKeySlot) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(
        slot.object_id.as_str(),
        slot.ciphertext.session_id.as_str(),
        slot.ciphertext.ratchet_public_key,
        slot.ciphertext.counter,
        &slot.ciphertext.header_hash,
    ))?;
    Ok(format!(
        "dm-pair/object-slot/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.object.slot.receipt.v2", &bytes)
    ))
}
