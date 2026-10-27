// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Temporary opt-in DM bootstrap, without forward secrecy; ordinary E2EE replaces it.
use super::network::{CustodyConnection, fields, now};
use crate::SdkError;
use ramflux_crypto::{
    DmCiphertext, DmSession, X3dhInitiatorInput, X3dhRecipientInput, X25519KeyPair,
};
use ramflux_protocol::custody::{CustodyServerFrame, CustodySessionAction, DeviceRef, decode};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const DM_DOMAIN: &str = "ramflux.custody_dm.v1";
static DM_RECEIVE_DROPS: AtomicU64 = AtomicU64::new(0);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    schema: String,
    source: DeviceRef,
    target: DeviceRef,
    initiator_identity: [u8; 32],
    ephemeral: [u8; 32],
    initial_ratchet: [u8; 32],
    bundle_hash: [u8; 32],
    ciphertext: DmCiphertext,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxDelivery {
    inbox_seq: u64,
    target_delivery_id: String,
    envelope: ramflux_protocol::Envelope,
}
#[derive(Clone)]
struct RejectedDelivery {
    inbox_seq: u64,
    envelope_id: String,
}
enum ReceiveDmResult {
    Message(CustodyDm),
    AlreadyAcknowledged(RejectedDelivery),
}
enum ReceiveDmFailure {
    Invalid(RejectedDelivery),
    Transient(SdkError),
}
struct ValidatedDelivery {
    inbox_seq: u64,
    envelope: ramflux_protocol::Envelope,
    packet: Packet,
    rejected: RejectedDelivery,
}
impl From<SdkError> for ReceiveDmFailure {
    fn from(error: SdkError) -> Self {
        Self::Transient(error)
    }
}
fn classify_lookup_failure(error: SdkError, rejected: RejectedDelivery) -> ReceiveDmFailure {
    match error {
        error @ (SdkError::Transport(_)
        | SdkError::Io(_)
        | SdkError::CustodyNetwork(
            ramflux_protocol::custody::CustodyRefusal::AuthorityUnavailable
            | ramflux_protocol::custody::CustodyRefusal::Capacity
            | ramflux_protocol::custody::CustodyRefusal::PersistenceUnavailable
            | ramflux_protocol::custody::CustodyRefusal::SessionExpired
            | ramflux_protocol::custody::CustodyRefusal::SessionRequired,
        )) => ReceiveDmFailure::Transient(error),
        _ => ReceiveDmFailure::Invalid(rejected),
    }
}

/// Authenticated decrypted delivery. Plaintext is erased when the value drops.
pub struct CustodyDm {
    pub inbox_seq: u64,
    pub envelope_id: String,
    pub source: DeviceRef,
    pub plaintext: Zeroizing<Vec<u8>>,
    recipient: DeviceRef,
    replay_key: String,
    receipt_sender: String,
    expires_at: u64,
}
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
fn hash_ref(reference: &DeviceRef) -> Result<[u8; 32], SdkError> {
    Ok(ramflux_crypto::blake3_256(
        "ramflux.identity.custody_dm_device.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    ))
}
fn ad(source: &DeviceRef, target: &DeviceRef) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&(DM_DOMAIN, source, target))?)
}
fn bundle_hash(bundle: &ramflux_crypto::PrekeyBundle) -> Result<[u8; 32], SdkError> {
    Ok(ramflux_crypto::blake3_256(
        "ramflux.identity.custody_dm_prekeys.v1",
        &ramflux_protocol::canonical_json_bytes(bundle)?,
    ))
}
fn payload_hash(bytes: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.identity.custody_dm_payload.v1", bytes)
}
fn message_expiry(created_at: i64, ttl: u32, current: u64) -> Result<u64, SdkError> {
    let created = u64::try_from(created_at).map_err(|_| invalid())?;
    let expires_at = created.checked_add(u64::from(ttl)).ok_or_else(invalid)?;
    if ttl == 0 || ttl > 86_400 || created > current.saturating_add(300) || current > expires_at {
        return Err(invalid());
    }
    Ok(expires_at)
}
impl CustodyConnection {
    fn validate_dm_delivery(
        &self,
        entry: serde_json::Value,
        after_seq: u64,
        own_bundle_hash: &[u8; 32],
    ) -> Result<ValidatedDelivery, ReceiveDmFailure> {
        let entry: InboxDelivery = serde_json::from_value(entry).map_err(SdkError::from)?;
        let envelope = entry.envelope;
        let rejected = RejectedDelivery {
            inbox_seq: entry.inbox_seq,
            envelope_id: envelope.envelope_id.clone(),
        };
        let expected_target = ramflux_protocol::qualified_device_id(
            &self.device.account_anchor,
            &self.device.device_id,
        )
        .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        if envelope.envelope_id.len() > 256
            || entry.inbox_seq <= after_seq
            || entry.target_delivery_id != expected_target
            || envelope.target_delivery_id != expected_target
        {
            return Err(ReceiveDmFailure::Invalid(rejected));
        }
        let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
            .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        if payload_hash(&bytes) != envelope.payload_hash {
            return Err(ReceiveDmFailure::Invalid(rejected));
        }
        let packet: Packet =
            decode(&bytes, 1024 * 1024).map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        if packet.schema != DM_DOMAIN
            || packet.target != self.device
            || packet.bundle_hash != *own_bundle_hash
            || packet.source.device_id != envelope.source_device_id
            || envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
                != Some(packet.source.account_anchor.as_str())
        {
            return Err(ReceiveDmFailure::Invalid(rejected));
        }
        Ok(ValidatedDelivery { inbox_seq: entry.inbox_seq, envelope, packet, rejected })
    }

    /// Send a DM under authenticated root-qualified source/target authority.
    /// Every envelope uses a fresh ephemeral/bootstrap and a single-message ratchet;
    /// this path never restores an old ratchet or reuses its message key after reconnect.
    /// # Errors
    /// Rejects oversized plaintext, stale peer pins, prekey substitution and routing refusal.
    pub async fn send_dm(
        &mut self,
        target: &DeviceRef,
        plaintext: &[u8],
    ) -> Result<String, SdkError> {
        self.require_experimental_dm()?;
        if plaintext.len() > 256 * 1024 {
            return Err(invalid());
        }
        let peer = self.lookup(target).await?;
        let bundle: ramflux_crypto::PrekeyBundle = serde_json::from_value(peer.prekey_bundle)?;
        let ephemeral = X25519KeyPair::random()?;
        let ratchet = X25519KeyPair::random()?;
        let associated = ad(&self.device, target)?;
        let hash = bundle_hash(&bundle)?;
        let source_hash = hash_ref(&self.device)?;
        let target_hash = hash_ref(target)?;
        let bootstrap = ramflux_crypto::x3dh_initiator(&X3dhInitiatorInput {
            initiator_identity: &self.credentials.agreement,
            initiator_ephemeral: &ephemeral,
            initiator_device_id_hash: source_hash,
            recipient_device_id_hash: target_hash,
            recipient_bundle: &bundle,
            associated_data: &associated,
            prekey_bundle_hash: &hash,
            initial_ratchet_public: ratchet.public,
        })?;
        let mut session = DmSession::initiator_with_remote_ratchet(
            bootstrap.root_seed,
            source_hash,
            target_hash,
            bootstrap.bootstrap_transcript_hash,
            &ratchet,
            bundle.signed_prekey,
        )?;
        let packet = Packet {
            schema: DM_DOMAIN.into(),
            source: self.device.clone(),
            target: target.clone(),
            initiator_identity: self.credentials.agreement.public,
            ephemeral: ephemeral.public,
            initial_ratchet: ratchet.public,
            bundle_hash: hash,
            ciphertext: session.encrypt(plaintext, &associated)?,
        };
        let bytes = ramflux_protocol::canonical_json_bytes(&packet)?;
        let id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let mut envelope = ramflux_protocol::Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.into(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: fields(),
            envelope_id: id.clone(),
            source_principal_id: self.account.record().body.principal_id.clone(),
            source_device_id: self.device.device_id.clone(),
            target_delivery_id: peer.target_delivery_id,
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 300,
            created_at: i64::try_from(now()?).map_err(|_| invalid())?,
            encrypted_payload: ramflux_protocol::encode_base64url(&bytes),
            payload_hash: payload_hash(&bytes),
        };
        envelope
            .ext
            .ext
            .insert("source_root_commitment".into(), self.device.account_anchor.clone().into());
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            &self.credentials.signing,
        );
        let CustodyServerFrame::Submitted { envelope_id, .. } =
            self.request(CustodySessionAction::Submit { envelope: Box::new(envelope) }).await?
        else {
            return Err(invalid());
        };
        if envelope_id != id {
            return Err(invalid());
        }
        Ok(id)
    }
    /// Fetch actual durable inbox entries, verify their current sender authority and decrypt.
    /// # Errors
    /// Rejects spoofed source/target/bootstrap, signature or commitment failures; no synthetic ack.
    pub async fn receive_dm(&mut self, after_seq: u64) -> Result<Vec<CustodyDm>, SdkError> {
        self.require_experimental_dm()?;
        let mut messages = Vec::new();
        let bundle = self.prekey_bundle()?;
        let own_bundle_hash = bundle_hash(&bundle)?;
        let mut scan_after = after_seq;
        // Continue beyond one full rejected page so a hundred hostile entries cannot hide the
        // first valid delivery. The four-page work cap keeps one poll bounded.
        for _ in 0..4 {
            let CustodyServerFrame::Inbox { entries } = self
                .request(CustodySessionAction::Inbox { after_seq: scan_after, limit: 100 })
                .await?
            else {
                return Err(invalid());
            };
            let page_len = entries.len();
            if page_len == 0 {
                break;
            }
            for entry in entries {
                match self.receive_one_dm(entry, scan_after, &bundle, &own_bundle_hash).await {
                    Ok(ReceiveDmResult::Message(message)) => {
                        scan_after = scan_after.max(message.inbox_seq);
                        messages.push(message);
                    }
                    Ok(ReceiveDmResult::AlreadyAcknowledged(delivery)) => {
                        self.ack_delivery(&delivery).await?;
                        scan_after = scan_after.max(delivery.inbox_seq);
                    }
                    Err(ReceiveDmFailure::Invalid(delivery)) => {
                        self.ack_delivery(&delivery).await?;
                        scan_after = scan_after.max(delivery.inbox_seq);
                        let total =
                            DM_RECEIVE_DROPS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                        tracing::warn!(
                            reason = "invalid_or_expired",
                            total,
                            "settled one rejected custody DM while continuing the inbox batch"
                        );
                    }
                    Err(ReceiveDmFailure::Transient(error)) => return Err(error),
                }
            }
            if page_len < 100 {
                break;
            }
        }
        Ok(messages)
    }

    async fn receive_one_dm(
        &mut self,
        entry: serde_json::Value,
        after_seq: u64,
        bundle: &ramflux_crypto::PrekeyBundle,
        own_bundle_hash: &[u8; 32],
    ) -> Result<ReceiveDmResult, ReceiveDmFailure> {
        let ValidatedDelivery { inbox_seq, envelope, packet, rejected } =
            self.validate_dm_delivery(entry, after_seq, own_bundle_hash)?;
        let peer = self
            .lookup(&packet.source)
            .await
            .map_err(|error| classify_lookup_failure(error, rejected.clone()))?;
        if envelope.source_principal_id != peer.publication.record.body.principal_id {
            return Err(ReceiveDmFailure::Invalid(rejected));
        }
        let authority = super::node_pins::verify_authority(
            &peer.publication,
            peer.custodian_publication.as_ref(),
            now()?,
        )
        .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        let cert = authority
            .authorize(&packet.source, "message", now()?)
            .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        if ramflux_protocol::encode_base64url(packet.initiator_identity)
            != cert.agreement_identity_public_key
        {
            return Err(ReceiveDmFailure::Invalid(rejected));
        }
        let signed_bytes = ramflux_protocol::envelope_sender_signed_bytes(&envelope)
            .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        ramflux_crypto::verify_canonical_signature(
            &signed_bytes,
            &envelope.signed.signature,
            &cert.branch_signing_public_key,
        )
        .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        let current = now()?;
        let expires_at = message_expiry(envelope.created_at, envelope.ttl, current)
            .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        let replay_key = ramflux_protocol::hash_base64url(
            "ramflux.identity.custody_dm_receipt.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &self.device,
                &packet.source,
                &envelope.envelope_id,
            ))
            .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?,
        );
        let receipt_sender = ramflux_protocol::qualified_device_id(
            &packet.source.account_anchor,
            &packet.source.device_id,
        )
        .map_err(|_| ReceiveDmFailure::Invalid(rejected.clone()))?;
        let pins = self.pins.clone();
        let lookup_key = replay_key.clone();
        let lookup_sender = receipt_sender.clone();
        if tokio::task::spawn_blocking(move || {
            pins.dm_was_acknowledged(&lookup_sender, &lookup_key, current)
        })
        .await
        .map_err(|_| invalid())??
        {
            return Ok(ReceiveDmResult::AlreadyAcknowledged(rejected));
        }
        let plaintext = self
            .decrypt_packet(&packet, bundle, own_bundle_hash)
            .map_err(|_| ReceiveDmFailure::Invalid(rejected))?;
        Ok(ReceiveDmResult::Message(CustodyDm {
            inbox_seq,
            envelope_id: envelope.envelope_id,
            source: packet.source,
            plaintext,
            recipient: self.device.clone(),
            replay_key,
            receipt_sender,
            expires_at,
        }))
    }
}
impl CustodyConnection {
    async fn ack_delivery(&mut self, delivery: &RejectedDelivery) -> Result<(), SdkError> {
        let mut ack = ramflux_protocol::Ack {
            schema: ramflux_protocol::domain::ACK.into(),
            version: 1,
            domain: ramflux_protocol::domain::ACK.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: fields(),
            ack_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            envelope_id: delivery.envelope_id.clone(),
            receiver_device_id: self.device.device_id.clone(),
            received_at: i64::try_from(now()?).map_err(|_| invalid())?,
            cursor_after: None,
        };
        ack.ext.ext.insert("inbox_seq".into(), delivery.inbox_seq.into());
        ack.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            &self.credentials.signing,
            &ack,
        )?;
        match self.request(CustodySessionAction::Ack { ack: Box::new(ack) }).await? {
            CustodyServerFrame::Acked { inbox_seq } if inbox_seq == delivery.inbox_seq => Ok(()),
            _ => Err(invalid()),
        }
    }

    fn decrypt_packet(
        &self,
        packet: &Packet,
        bundle: &ramflux_crypto::PrekeyBundle,
        own_bundle_hash: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let source_hash = hash_ref(&packet.source)?;
        let target_hash = hash_ref(&self.device)?;
        let associated = ad(&packet.source, &self.device)?;
        let signed_prekey = self.signed_prekey();
        let bootstrap = ramflux_crypto::x3dh_recipient(&X3dhRecipientInput {
            recipient_identity: &self.credentials.agreement,
            recipient_signed_prekey: &signed_prekey,
            recipient_one_time_prekey: None,
            initiator_identity_public: packet.initiator_identity,
            initiator_ephemeral_public: packet.ephemeral,
            initiator_device_id_hash: source_hash,
            recipient_device_id_hash: target_hash,
            recipient_signed_prekey_id: &bundle.signed_prekey_id,
            recipient_one_time_prekey_id: None,
            associated_data: &associated,
            prekey_bundle_hash: own_bundle_hash,
            initial_ratchet_public: packet.initial_ratchet,
        })?;
        let mut session = DmSession::recipient_with_local_ratchet(
            bootstrap.root_seed,
            target_hash,
            source_hash,
            bootstrap.bootstrap_transcript_hash,
            &signed_prekey,
        )?;
        Ok(Zeroizing::new(session.decrypt(&packet.ciphertext, &associated)?))
    }
}

impl CustodyConnection {
    /// Settle a delivery only after the caller has accepted its decrypted contents.
    /// # Errors
    /// Rejects wrong mailbox/sequence, stale authority, invalid signature or durable ACK failure.
    pub async fn ack_dm(&mut self, message: &CustodyDm) -> Result<(), SdkError> {
        self.require_experimental_dm()?;
        if message.recipient != self.device {
            return Err(invalid());
        }
        // The caller has accepted this delivery. Persist before the remote ACK so an
        // uncertain network result cannot reopen it to presentation after reconnect.
        let pins = self.pins.clone();
        let key = message.replay_key.clone();
        let expiry = message.expires_at;
        let current = now()?;
        let sender = message.receipt_sender.clone();
        tokio::task::spawn_blocking(move || {
            pins.remember_dm_acknowledgement(&sender, key, expiry, current)
        })
        .await
        .map_err(|_| invalid())??;
        self.ack_delivery(&RejectedDelivery {
            inbox_seq: message.inbox_seq,
            envelope_id: message.envelope_id.clone(),
        })
        .await
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    #[test]
    fn custody_dm_signed_ttl_cannot_be_extended_by_redelivery() -> Result<(), SdkError> {
        assert_eq!(message_expiry(100, 300, 400)?, 400);
        assert!(message_expiry(100, 300, 401).is_err());
        assert!(message_expiry(-1, 300, 100).is_err());
        assert!(message_expiry(401, 300, 100).is_err());
        assert!(message_expiry(100, 0, 100).is_err());
        assert!(message_expiry(100, 86_401, 100).is_err());
        Ok(())
    }
    #[test]
    fn rejected_delivery_retains_only_the_fields_needed_to_advance() {
        let delivery = RejectedDelivery { inbox_seq: 7, envelope_id: "message".into() };
        assert_eq!(delivery.inbox_seq, 7);
        assert_eq!(delivery.envelope_id, "message");
    }
    #[test]
    fn storage_and_lookup_failures_remain_transient() {
        let failure: ReceiveDmFailure = SdkError::Io(std::io::Error::other("retry")).into();
        assert!(matches!(failure, ReceiveDmFailure::Transient(SdkError::Io(_))));
        let rejected = RejectedDelivery { inbox_seq: 1, envelope_id: "message".into() };
        assert!(matches!(
            classify_lookup_failure(
                SdkError::CustodyNetwork(
                    ramflux_protocol::custody::CustodyRefusal::PersistenceUnavailable
                ),
                rejected.clone(),
            ),
            ReceiveDmFailure::Transient(_)
        ));
        assert!(matches!(
            classify_lookup_failure(SdkError::CustodySetupInvalid, rejected),
            ReceiveDmFailure::Invalid(_)
        ));
    }
}
