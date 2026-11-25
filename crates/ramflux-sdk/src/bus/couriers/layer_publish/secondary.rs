// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary side of secondary layer renewal (SECONDARY-LAYER-01 step 4).
//!
//! One courier pass endorses at most one pending secondary declaration into a new
//! authority-signed roster head, through the same layer head journal the primary's own
//! declaration uses. The target device and the operation are durable before Prepare, so a
//! restart resumes the same bytes; the pending request is retired only after the head is
//! acknowledged.
use super::{Plan, submit};
use crate::SdkError;
use crate::bus::state::LocalBusAccountState;
use crate::client::layer_renewal::{PendingLayerRenewal, pending_key};
use crate::custody::pairing::{HeadKind, HeadWrite};
use crate::gateway::GatewayCustodyConfig;
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::custody::{DeviceRef, SignedLayerDeclaration};
use ramflux_storage::AccountDb;
use serde::{Deserialize, Serialize};

/// Round-robin cursor: the pending key served last.
const CURSOR_KEY: &str = "layer-publish/secondary-cursor";
const TARGET_PREFIX: &str = "layer-publish/target/";
const PENDING_PREFIX: &str = "layer-renewal/pending/";

/// The endorsement in flight for one secondary device, durable before Prepare.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct SecondaryTarget {
    pub(super) device: DeviceRef,
    pub(super) operation_id: String,
    pub(super) signed: SignedLayerDeclaration,
}

fn target_key(device: &DeviceRef) -> String {
    format!("{TARGET_PREFIX}{}/{}/{}", device.account_anchor, device.device_id, device.device_epoch)
}

/// The target whose endorsement head carries `operation_id`, if this head is a secondary one.
pub(super) fn target_for(
    db: &AccountDb,
    operation_id: &str,
) -> Result<Option<SecondaryTarget>, SdkError> {
    let targets = db.list_actor_states::<SecondaryTarget>(TARGET_PREFIX)?;
    Ok(targets.into_iter().find(|target| target.operation_id == operation_id))
}

/// Retire the endorsed device's target, and its pending request when the endorsed sequence
/// covers it. Runs after the head is acknowledged and installed.
pub(super) fn complete(
    db: &AccountDb,
    device: &DeviceRef,
    endorsed_sequence: u64,
) -> Result<(), SdkError> {
    db.remove_actor_state(&target_key(device))?;
    let pending = db.load_actor_state::<PendingLayerRenewal>(&pending_key(device))?;
    if pending.is_some_and(|pending| pending.declaration_sequence <= endorsed_sequence) {
        db.remove_actor_state(&pending_key(device))?;
    }
    Ok(())
}

/// Serve the next pending secondary request in round-robin order. Stale, expired or unbindable
/// requests are dropped without a head.
pub(super) fn prepare_next(
    account: &mut LocalBusAccountState,
    config: &GatewayCustodyConfig,
    now: u64,
) -> Result<Option<Box<Plan>>, SdkError> {
    let db = account.client.account_db()?;
    let mut keyed: Vec<(String, PendingLayerRenewal)> = db
        .list_actor_states::<PendingLayerRenewal>(PENDING_PREFIX)?
        .into_iter()
        .map(|pending| (pending_key(&pending.signed.declaration.device), pending))
        .collect();
    if keyed.is_empty() {
        return Ok(None);
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let cursor = db.load_actor_state::<String>(CURSOR_KEY)?;
    let chosen = keyed
        .iter()
        .find(|(key, _)| cursor.as_ref().is_none_or(|last| key > last))
        .or_else(|| keyed.first());
    let Some((key, pending)) = chosen.cloned() else { return Ok(None) };
    db.persist_actor_state(CURSOR_KEY, &key)?;
    let device = pending.signed.declaration.device.clone();
    if !eligible(account, &pending, now)? {
        account.client.account_db()?.remove_actor_state(&key)?;
        return Ok(None);
    }
    let operation_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let db = account.client.account_db()?;
    db.persist_actor_state(
        &target_key(&device),
        &SecondaryTarget {
            device: device.clone(),
            operation_id: operation_id.clone(),
            signed: pending.signed.clone(),
        },
    )?;
    let write = endorse_write(account, config, operation_id, now, device, pending.signed)?;
    submit(account, config, write)
}

/// Resume an interrupted secondary endorsement with its durable target.
pub(super) fn resume(
    account: &mut LocalBusAccountState,
    config: &GatewayCustodyConfig,
    head: &ramflux_storage::HeadRow,
    target: SecondaryTarget,
    now: u64,
) -> Result<Option<Box<Plan>>, SdkError> {
    let expiry = target.signed.declaration.expires_at;
    if head.state == "prepared"
        && expiry <= now
        && crate::custody::pairing::publication::discard_prepared_layer(
            account.client.account_db()?,
            &config.account_root,
            &config.account_id,
            &head.operation_id,
            &head.candidate_hash,
        )?
    {
        return Ok(None);
    }
    let write = endorse_write(
        account,
        config,
        head.operation_id.clone(),
        now,
        target.device,
        target.signed,
    )?;
    if head.state == "acknowledged" {
        let hash = head.candidate_hash.clone();
        super::finish(account, config, &write, hash.clone(), hash)?;
        return Ok(None);
    }
    submit(account, config, write)
}

/// A pending request is served only while its device is still an active row, the endorsed
/// sequence is older, the declaration is unexpired and it verifies against the certificate.
fn eligible(
    account: &LocalBusAccountState,
    pending: &PendingLayerRenewal,
    now: u64,
) -> Result<bool, SdkError> {
    let born = account.client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    let declaration = &pending.signed.declaration;
    if now >= declaration.expires_at {
        return Ok(false);
    }
    let Some(row) = born.record().body.devices.iter().find(|device| {
        device.device_id == declaration.device.device_id
            && device.device_epoch == declaration.device.device_epoch
            && device.status == DeviceSetStatus::Active
    }) else {
        return Ok(false);
    };
    if row.message_layer.as_ref().is_some_and(|endorsed| {
        endorsed.declaration.declaration_sequence >= declaration.declaration_sequence
    }) {
        return Ok(false);
    }
    let Some(certificate) = row.branch_certificate.as_ref() else { return Ok(false) };
    Ok(ramflux_crypto::custody::verify_enrollment_layer(certificate, &pending.signed, now).is_ok())
}

fn endorse_write(
    account: &LocalBusAccountState,
    config: &GatewayCustodyConfig,
    operation_id: String,
    now: u64,
    device: DeviceRef,
    signed: SignedLayerDeclaration,
) -> Result<HeadWrite, SdkError> {
    let born = account.client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    let primary = born.record().body.master_certificate.body.primary_device_ref.clone();
    Ok(HeadWrite {
        account_id: config.account_id.clone(),
        operation_id,
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::SecondaryLayer,
        publisher_ref: primary.clone(),
        local_ref: primary,
        recipient_ref: Some(device),
        revoked_id: None,
        certificate: None,
        message_layer: Some(signed),
        display_name: None,
        now,
        branch_vault_ref: born.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&config.account_id),
        primary_vault_ref: Some(born.primary_vault_ref().into()),
    })
}
