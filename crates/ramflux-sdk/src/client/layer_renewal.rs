// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary side of secondary layer renewal (SECONDARY-LAYER-01).
//!
//! A secondary device sends its own branch-signed declaration to the current primary over the
//! authenticated own-device Control. The primary authenticates it against the current roster
//! and stores one pending request for the layer-publish courier. Receipt never publishes.
use crate::SdkError;
use crate::bus::couriers::layer_publish::renewal_due;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::{DeviceRef, SignedLayerDeclaration};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

/// Pending request held per exact account/device/epoch until the courier endorses it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PendingLayerRenewal {
    pub(crate) declaration_sequence: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) signed: SignedLayerDeclaration,
}

/// Actor-state key for the one pending request of one exact device epoch.
pub(crate) fn pending_key(device: &DeviceRef) -> String {
    format!(
        "layer-renewal/pending/{}/{}/{}",
        device.account_anchor, device.device_id, device.device_epoch
    )
}

/// Minimum spacing between two endorsements of one secondary device (SECONDARY-LAYER-01).
pub(crate) const RENEWAL_SPACING_SECONDS: u64 = 3600;

/// Actor-state key of the last time the primary endorsed one exact secondary device epoch.
pub(crate) fn last_endorsed_key(device: &DeviceRef) -> String {
    format!(
        "layer-renewal/last-endorsed/{}/{}/{}",
        device.account_anchor, device.device_id, device.device_epoch
    )
}

impl super::RamfluxClient {
    /// Authenticate and store one renewal request. Siblings that are not the current primary
    /// ignore it without writes.
    /// # Errors
    /// Refuses a request whose sender, epochs, roster endorsement, lease, sequence or
    /// signature does not match the current authority.
    pub(crate) fn receive_own_layer_renewal(
        &self,
        source: &RootQualifiedDeviceRef,
        renewal: &g::OwnLayerRenewal,
    ) -> Result<(), SdkError> {
        let own_anchor = self.own_account_anchor()?;
        let born = self.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
        let record = born.record();
        let primary = &record.body.master_certificate.body.primary_device_ref;
        let primary_named = renewal.primary.as_ref().is_some_and(|reference| {
            reference.account_anchor == own_anchor
                && reference.device_id == primary.device_id
                && reference.device_epoch == primary.device_epoch
        });
        if !primary_named || born.local_device_id()? != primary.device_id {
            return Ok(());
        }
        let bytes = renewal.signed_declaration_json.as_slice();
        let signed: SignedLayerDeclaration = ramflux_protocol::parse_i_json(bytes)
            .map_err(|_| refused("own layer renewal declaration malformed"))?;
        if canonical_json_bytes(&signed)? != bytes {
            return Err(refused("own layer renewal declaration is not canonical"));
        }
        let declaration = &signed.declaration;
        let db = self.account_db()?;
        let sender_epoch =
            db.client_device_record(source)?.and_then(|record| record["device_epoch"].as_u64());
        if declaration.device.account_anchor != own_anchor
            || declaration.device.device_id != source.device_id()
            || Some(declaration.device.device_epoch) != sender_epoch
        {
            return Err(refused("own layer renewal sender mismatch"));
        }
        let now = crate::custody::network_now()?;
        if now >= declaration.expires_at {
            return Err(refused("own layer renewal declaration expired"));
        }
        let row = record
            .body
            .devices
            .iter()
            .find(|device| {
                device.device_id == declaration.device.device_id
                    && device.device_epoch == declaration.device.device_epoch
                    && device.status == DeviceSetStatus::Active
            })
            .ok_or_else(|| refused("own layer renewal device not active"))?;
        let certificate = row
            .branch_certificate
            .as_ref()
            .ok_or_else(|| refused("own layer renewal has no branch"))?;
        ramflux_crypto::custody::verify_enrollment_layer(certificate, &signed, now)
            .map_err(|_| refused("own layer renewal declaration rejected"))?;
        // The high-water is the endorsed row or the retained pin, whichever is newer: a request
        // at or below it is refused unless it is exactly the endorsed statement (idempotent).
        let endorsed = row.message_layer.as_ref();
        let retained = born.retained_layer_sequence(&declaration.device)?;
        let current =
            endorsed.map_or(0, |endorsed| endorsed.declaration.declaration_sequence).max(retained);
        if declaration.declaration_sequence < current
            || (declaration.declaration_sequence == current && endorsed != Some(&signed))
        {
            return Err(refused("own layer renewal sequence is not newer"));
        }
        if declaration.declaration_sequence == current {
            return Ok(());
        }
        let due = renewal_due(endorsed, now);
        let spaced = endorsed.is_none_or(|endorsed| {
            declaration.issued_at
                >= endorsed.declaration.issued_at.saturating_add(RENEWAL_SPACING_SECONDS)
        });
        if !due && !spaced {
            return Err(refused("own layer renewal is not due"));
        }
        let digest = *blake3::hash(bytes).as_bytes();
        let key = pending_key(&declaration.device);
        let sequence = declaration.declaration_sequence;
        db.write_transaction(|| {
            if let Some(old) = db.load_actor_state::<PendingLayerRenewal>(&key)? {
                if sequence < old.declaration_sequence
                    || (sequence == old.declaration_sequence && old.digest != digest)
                {
                    return Err(refused("own layer renewal conflicts with a pending request"));
                }
                if sequence == old.declaration_sequence {
                    return Ok(());
                }
            }
            db.persist_actor_state(
                &key,
                &PendingLayerRenewal { declaration_sequence: sequence, digest, signed },
            )?;
            Ok(())
        })
    }
}

/// Own-copy identity domain of one renewal Control (the complete body is hashed).
const RENEWAL_DOMAIN: &str = "ramflux.sdk.own_layer_renewal.v1";
/// Validity of one renewal declaration (24 h, or the integration lease).
const RENEWAL_MAX_VALIDITY: u64 = crate::bus::couriers::layer_publish::DECLARATION_VALIDITY_SECONDS;

/// Actor-state key of the latest renewal this secondary issued for one exact device epoch.
pub(crate) fn issued_key(device: &DeviceRef) -> String {
    format!(
        "layer-renewal/issued/{}/{}/{}",
        device.account_anchor, device.device_id, device.device_epoch
    )
}

impl super::RamfluxClient {
    /// Secondary send half. Signs a fresh branch declaration when the endorsed one is absent,
    /// expired, capability-stale or half elapsed, unless a newer issued one is still in flight.
    /// The issuance high-water and the own-device Control outbox row commit together.
    /// # Errors
    /// Typed refusal when the branch cannot be used or the certificate lease cannot carry a
    /// declaration. Primary devices return without work.
    pub(crate) fn stage_own_layer_renewal(&self, now: u64) -> Result<(), SdkError> {
        let born = self.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
        let record = born.record();
        let primary = &record.body.master_certificate.body.primary_device_ref;
        let local = born.local_device_id()?;
        if primary.device_id == local {
            return Ok(());
        }
        let row = record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == local && device.status == DeviceSetStatus::Active)
            .ok_or(SdkError::NetworkingPending)?;
        let certificate = row.branch_certificate.as_ref().ok_or(SdkError::NetworkingPending)?;
        let device = DeviceRef {
            account_anchor: record.body.account_anchor.clone(),
            device_id: local.to_owned(),
            device_epoch: certificate.body.device_epoch,
        };
        let db = self.account_db()?;
        let key = issued_key(&device);
        let issued = db.load_actor_state::<PendingLayerRenewal>(&key)?;
        let endorsed_sequence =
            row.message_layer.as_ref().map_or(0, |signed| signed.declaration.declaration_sequence);
        if let Some(issued) = &issued
            && issued.declaration_sequence > endorsed_sequence
            && !renewal_due(Some(&issued.signed), now)
        {
            return Ok(());
        }
        if !renewal_due(row.message_layer.as_ref(), now) {
            return Ok(());
        }
        let retained = born.retained_layer_sequence(&device)?;
        let sequence = issued
            .as_ref()
            .map_or(0, |issued| issued.declaration_sequence)
            .max(endorsed_sequence)
            .max(retained)
            .checked_add(1)
            .ok_or(SdkError::NetworkingPending)?;
        let expires_at = now.saturating_add(RENEWAL_MAX_VALIDITY).min(certificate.body.expires_at);
        if now < certificate.body.not_before || expires_at <= now {
            return Err(refused("own layer renewal has no usable certificate lease"));
        }
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let signed = crate::custody::layer_declaration::candidate(
            branch,
            device.clone(),
            ramflux_protocol::message::registry::COMPILED_LAYER,
            sequence,
            now,
            expires_at,
        )?;
        ramflux_crypto::custody::verify_enrollment_layer(certificate, &signed, now)
            .map_err(|_| refused("own layer renewal declaration rejected"))?;
        let bytes = canonical_json_bytes(&signed)?;
        let renewal = g::OwnLayerRenewal {
            primary: Some(g::QualifiedDevice {
                account_anchor: primary.account_anchor.clone(),
                device_id: primary.device_id.clone(),
                device_epoch: primary.device_epoch,
            }),
            signed_declaration_json: bytes.clone(),
        };
        let control = crate::client::generated_control::control_from_payload(
            g::control::Payload::OwnLayerRenewal(renewal),
        )?;
        let body = prost::Message::encode_to_vec(&control);
        let id = ramflux_protocol::hash_base64url(RENEWAL_DOMAIN, &body);
        let pending = PendingLayerRenewal {
            declaration_sequence: sequence,
            digest: *blake3::hash(&bytes).as_bytes(),
            signed,
        };
        db.join_write(|| {
            db.persist_actor_state(&key, &pending)?;
            crate::bus::own_device_copy::stage(
                self,
                crate::client::own_device_copy::OwnMessageInput {
                    payload_kind: crate::client::own_device_copy::OwnPayloadKind::Control,
                    id: &id,
                    created_at: i64::try_from(now).unwrap_or(i64::MAX),
                    conversation: "own-layer-renewal",
                    group: None,
                    body: &body,
                },
                None,
            )
        })
    }
}

impl super::RamfluxClient {
    /// True while this secondary has issued a renewal that the endorsed row does not yet carry.
    pub(crate) fn own_layer_renewal_in_flight(&self) -> Result<bool, SdkError> {
        let born = self.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
        let record = born.record();
        let local = born.local_device_id()?;
        let Some(row) =
            record.body.devices.iter().find(|device| {
                device.device_id == local && device.status == DeviceSetStatus::Active
            })
        else {
            return Ok(false);
        };
        let Some(certificate) = row.branch_certificate.as_ref() else { return Ok(false) };
        let device = DeviceRef {
            account_anchor: record.body.account_anchor.clone(),
            device_id: local.to_owned(),
            device_epoch: certificate.body.device_epoch,
        };
        let issued =
            self.account_db()?.load_actor_state::<PendingLayerRenewal>(&issued_key(&device))?;
        let endorsed =
            row.message_layer.as_ref().map_or(0, |signed| signed.declaration.declaration_sequence);
        Ok(issued.is_some_and(|issued| issued.declaration_sequence > endorsed))
    }
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}
