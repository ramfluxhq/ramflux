// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-approved consent intents; retry uses signed public intent, never a legacy signer.
use super::{
    Decision,
    delivery::{Intent, key},
    invalid,
};
use crate::{GatewaySessionConfig, RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_protocol::custody::{
    ContactConsentV2, ContactDecision, DeviceRef, Envelope, object_hash,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Approved {
    consent: Envelope<ContactConsentV2>,
    epoch: u64,
    signing_key: String,
    agreement_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generated_inner: Option<Vec<u8>>,
}

pub(super) struct ApprovalRequest {
    root: std::path::PathBuf,
    id: String,
    vault: std::sync::Arc<dyn crate::custody::PrimaryVault>,
    current: ramflux_crypto::custody::VerifiedRecord,
    body: ContactConsentV2,
    now: u64,
    epoch: u64,
    signing_key: String,
    agreement_key: String,
}
pub(super) enum ApprovalPlan {
    Ready(Box<Approved>),
    Sign(Box<ApprovalRequest>),
}
impl ApprovalPlan {
    pub(super) async fn execute(self) -> Result<Approved, SdkError> {
        match self {
            Self::Ready(approved) => Ok(*approved),
            Self::Sign(request) => tokio::task::spawn_blocking(move || {
                let request = *request;
                let account =
                    crate::custody::load_account(&request.root, &request.id, request.now)?;
                let consent = account.sign_contact_consent(
                    request.vault.as_ref(),
                    &request.current,
                    request.body,
                    request.now,
                )?;
                Ok(Approved {
                    consent,
                    epoch: request.epoch,
                    signing_key: request.signing_key,
                    agreement_key: request.agreement_key,
                    generated_inner: None,
                })
            })
            .await
            .map_err(|_| SdkError::CustodyVaultUnavailable)?,
        }
    }
}
pub(super) fn approval_bytes(approved: &Approved) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    Ok(Zeroizing::new(serde_json::to_vec(&approved.consent)?))
}
pub(super) fn save_approval(
    client: &RamfluxClient,
    intent: &mut Intent,
    mut approved: Approved,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let (bytes, updated) = client.account_db()?.write_transaction(|| -> Result<_, SdkError> {
        let bytes = if crate::client::target_selection::schema_v1_selected() {
            let bytes = client
                .generated_contact_inner(&approved.consent, approved.generated_inner.as_deref())?;
            approved.generated_inner = Some(bytes.to_vec());
            bytes
        } else {
            approval_bytes(&approved)?
        };
        let mut updated = intent.clone();
        updated.native_approval = Some(approved);
        client.account_db()?.persist_actor_state(&key(&updated), &updated)?;
        Ok((bytes, updated))
    })?;
    *intent = updated;
    Ok(bytes)
}
pub(super) async fn approve(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
    intent: &mut Intent,
    manifest: &SdkDeviceManifestResponse,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let approved = prepare_approval(client, config, intent, manifest)?.execute().await?;
    save_approval(client, intent, approved)
}
pub(super) fn prepare_approval(
    client: &RamfluxClient,
    config: &GatewaySessionConfig,
    intent: &Intent,
    manifest: &SdkDeviceManifestResponse,
) -> Result<ApprovalPlan, SdkError> {
    let now = crate::custody::network_now()?;
    let native =
        manifest.custody.as_deref().ok_or_else(|| invalid("native consent authority absent"))?;
    let current = client
        .current_custody_authority(&manifest.principal_commitment, now)?
        .ok_or_else(|| invalid("owned native consent authority absent"))?;
    let own = client.owned_device_identity()?;
    if current.envelope() != &native.publication.record
        || own.root_commitment() != manifest.principal_commitment
    {
        return Err(invalid("owned native consent head mismatch"));
    }
    let reference = DeviceRef {
        account_anchor: own.root_commitment().into(),
        device_id: own.device_id().into(),
        device_epoch: current
            .envelope()
            .body
            .devices
            .iter()
            .find(|d| d.device_id == own.device_id())
            .ok_or_else(|| invalid("owned native consent branch absent"))?
            .device_epoch,
    };
    let cert = current.authorize(&reference, "message", now)?;
    let master_hash = object_hash(&current.envelope().body.master_certificate)?;
    let decision = match intent.kind {
        Decision::Request => ContactDecision::Request,
        Decision::Accept => ContactDecision::Accept,
        Decision::Decline => ContactDecision::Decline,
    };
    if let Some(approved) = &intent.native_approval
        && approved.consent.body.kind == decision
        && approved.consent.body.request_id == intent.request_id
        && approved.consent.body.nonce == intent.nonce
        && approved.consent.body.requester_root == intent.requester_root
        && approved.consent.body.target_root == intent.target_root
        && approved.consent.body.note == intent.note
        && approved.consent.body.master_certificate_hash == master_hash
        && approved.consent.body.sending_device_ref == reference
        && approved.epoch <= current.envelope().body.device_set_epoch
        && approved.signing_key == cert.branch_signing_public_key
        && approved.agreement_key == cert.agreement_identity_public_key
        && approved.consent.body.expires_at > now
    {
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::custody::signing_bytes(
                ramflux_protocol::domain::CONTACT_REQUEST_V2,
                &approved.consent.body,
            )?,
            &approved.consent.signature,
            &current.envelope().body.master_certificate.body.self_signing_public_key,
        )?;
        return Ok(ApprovalPlan::Ready(Box::new(approved.clone())));
    }
    let issued_at = u64::try_from(intent.issued_at)
        .map_err(|_| invalid("invalid native intent time"))?
        .max(current.envelope().body.issued_at);
    let body = ContactConsentV2 {
        schema: ramflux_protocol::domain::CONTACT_REQUEST_V2.into(),
        version: 2,
        kind: match intent.kind {
            Decision::Request => ContactDecision::Request,
            Decision::Accept => ContactDecision::Accept,
            Decision::Decline => ContactDecision::Decline,
        },
        request_id: intent.request_id.clone(),
        nonce: intent.nonce.clone(),
        requester_root: intent.requester_root.clone(),
        target_root: intent.target_root.clone(),
        actor_root: own.root_commitment().into(),
        sending_device_ref: reference,
        issued_at,
        expires_at: issued_at
            .checked_add(ramflux_protocol::custody::CONTACT_CONSENT_TTL_SECONDS)
            .ok_or_else(|| invalid("invalid native intent expiry"))?,
        note: intent.note.clone(),
        actor_record_hash: object_hash(current.envelope())?,
        master_certificate_hash: master_hash,
    };
    let root = client.account_index()?.root().to_path_buf();
    let id = client.account_db()?.local_account_id.clone();
    let vault = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?.vault.clone();
    let signing_key = cert.branch_signing_public_key.clone();
    let agreement_key = cert.agreement_identity_public_key.clone();
    let epoch = current.envelope().body.device_set_epoch;
    // Data unlock and branch possession never manufacture primary consent.
    Ok(ApprovalPlan::Sign(Box::new(ApprovalRequest {
        root,
        id,
        vault,
        current,
        body,
        now,
        epoch,
        signing_key,
        agreement_key,
    })))
}
