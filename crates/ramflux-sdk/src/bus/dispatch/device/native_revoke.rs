// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 device revocation never reads or invokes the legacy root manifest.
use crate::{SdkError, bus::state::LocalBusAccountState, custody};
use custody::pairing::{HeadKind, HeadWrite, NodeHeadPersist, PairingNative, ProofPairingNative};
use ramflux_protocol::custody::{CustodyAuthority, DeviceRef, Publication, object_hash};
use std::sync::{Arc, Mutex};

pub(super) async fn dispatch(
    account: &mut LocalBusAccountState,
    device: &str,
) -> Result<crate::bus::daemon::LocalBusDispatchResult, SdkError> {
    let config = account.gateway_config.clone();
    let selected = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let root = selected.account_root.clone();
    let id = selected.account_id.clone();
    if account.client.account_db()?.local_account_id != id {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let pending = account.client.account_db()?.pairing_head()?;
    let authority = if pending.is_none() {
        let anchor = account
            .client
            .born_v3_account
            .as_ref()
            .ok_or(SdkError::NetworkingPending)?
            .record()
            .body
            .account_anchor
            .clone();
        let response: crate::prekey::SdkDeviceManifestResponse =
            crate::prekey::sdk_gateway_get_json(
                &config,
                &format!("/mvp1/device-manifest/{anchor}"),
            )
            .await?;
        let native = response.custody.ok_or(SdkError::CustodyModeDowngrade)?;
        Some(CustodyAuthority {
            publication: native.publication,
            custodian_publication: native.custodian_publication,
        })
    } else {
        None
    };
    let write = prepare(
        account.client.account_db()?,
        &root,
        &id,
        selected.vault.as_ref(),
        device,
        authority,
    )?;
    let publication = with_db(account, |db| {
        custody::pairing::publication::prepare_head_submission(
            db,
            &root,
            selected.vault.as_ref(),
            &write,
        )
    })?;
    let expected = object_hash(&publication.record)?;
    let connection = custody::CustodyConnection::connect_for_proof(
        crate::gateway::proof_network_config(&config)?,
        selected.vault.clone(),
    )
    .await?;
    let native = ProofPairingNative::from_connection(Arc::new(tokio::sync::Mutex::new(connection)));
    // The actual account DB stays in the frontend during every network await. Cancellation
    // leaves its exact submitted intent recoverable and never drops the unlocked DB worker.
    let acknowledged = native.publish(publication).await?;
    if acknowledged != expected {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    let receipt = NativeAck { expected, acknowledged };
    let published = with_db(account, |db| {
        custody::pairing::publish_head(db, &root, selected.vault.as_ref(), &write, &receipt)
    })?;
    account.client.born_v3_account = Some(Box::new(custody::load_account(
        account.client.account_index()?.root(),
        &account.client.account_db()?.local_account_id,
        custody::network_now()?,
    )?));
    Ok(super::local_bus_ok(
        serde_json::json!({"device_id":device,"revoked":true,"publication_state":"acknowledged","device_set_epoch":published.epoch,"record_hash":published.record_hash}),
    ))
}

// This adapter exists only after the real native proof has returned Published. It can
// acknowledge only the exact candidate that was submitted, including on a journal retry.
struct NativeAck {
    expected: String,
    acknowledged: String,
}
impl NodeHeadPersist for NativeAck {
    fn persist_head(&self, publication: &Publication, _now: u64) -> Result<String, SdkError> {
        if object_hash(&publication.record)? != self.expected || self.acknowledged != self.expected
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(self.acknowledged.clone())
    }
}

fn with_db<T>(
    account: &mut LocalBusAccountState,
    action: impl FnOnce(&Mutex<ramflux_storage::AccountDb>) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    struct Borrowed<'a> {
        original: &'a mut Option<ramflux_storage::AccountDb>,
        db: Option<Mutex<ramflux_storage::AccountDb>>,
    }
    impl Drop for Borrowed<'_> {
        fn drop(&mut self) {
            if let Some(db) = self.db.take() {
                *self.original =
                    Some(db.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner));
            }
        }
    }
    let db = account.client.active_account_db.take().ok_or(SdkError::AccountDbNotUnlocked)?;
    let borrowed =
        Borrowed { original: &mut account.client.active_account_db, db: Some(Mutex::new(db)) };
    action(borrowed.db.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?)
}

fn prepare(
    db: &ramflux_storage::AccountDb,
    root: &std::path::Path,
    id: &str,
    vault: &dyn custody::PrimaryVault,
    device: &str,
    authority: Option<CustodyAuthority>,
) -> Result<HeadWrite, SdkError> {
    let now = custody::network_now()?;
    if let Some(authority) = authority {
        custody::pairing::refresh_authority(root, db, vault, id, &authority, now)?;
    }
    let account = custody::load_account(root, id, now)?;
    let local = DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: account.local_device_id()?.into(),
        device_epoch: account.record().body.master_certificate.body.primary_device_ref.device_epoch,
    };
    account.group_primary(vault).map_err(|_| SdkError::PairingCode("PrimaryRequired"))?;
    let pending = db.pairing_head()?;
    let operation_id = if let Some(head) = pending {
        let revoked: DeviceRef = ramflux_protocol::parse_i_json(
            head.revoked_ref.as_deref().ok_or(SdkError::PairingCode("Busy"))?,
        )?;
        if head.kind != "revoke" || revoked.device_id != device {
            return Err(SdkError::PairingCode("Busy"));
        }
        head.operation_id
    } else {
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    };
    Ok(HeadWrite {
        account_id: id.into(),
        operation_id,
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::Revoke,
        publisher_ref: local.clone(),
        local_ref: local,
        recipient_ref: None,
        revoked_id: Some(device.into()),
        certificate: None,
        display_name: None,
        now,
        branch_vault_ref: account.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(id),
        primary_vault_ref: Some(account.primary_vault_ref().into()),
    })
}
