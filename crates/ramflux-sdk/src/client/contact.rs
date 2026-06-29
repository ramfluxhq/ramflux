// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prekey::{SdkMvp1DeviceManifestDevice, SdkMvp1PrekeyResponse};
use crate::prelude::*;

impl RamfluxClient {
    /// # Errors
    /// Returns an error when the manifest JSON is malformed or fails fail-closed device-set
    /// verification for the expected identity commitment.
    pub fn verify_device_manifest_json(
        manifest: serde_json::Value,
        expected_identity_commitment: &str,
    ) -> Result<(), SdkError> {
        let manifest: SdkMvp1DeviceManifestResponse = serde_json::from_value(manifest)?;
        verify_device_manifest(&manifest, expected_identity_commitment)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the friend link cannot be stored.
    pub fn establish_friend_link(
        &self,
        link_id: &str,
        requester_id: &str,
        target_id: &str,
    ) -> Result<FriendLinkRecord, SdkError> {
        Ok(self.account_db()?.establish_friend_link(link_id, requester_id, target_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or friend links cannot be read.
    pub fn friend_links(&self) -> Result<Vec<FriendLinkRecord>, SdkError> {
        Ok(self.account_db()?.friend_links()?)
    }

    /// # Errors
    /// Returns an error when the contact is not linked or local verification state cannot be read.
    pub fn contact_safety_number(
        &self,
        contact_identity_commitment: &str,
    ) -> Result<SdkContactSafetyNumber, SdkError> {
        let material = self.contact_safety_material_pair(contact_identity_commitment)?;
        let fingerprint =
            ramflux_crypto::safety_fingerprint(&material.self_material, &material.contact_material);
        let safety_number =
            ramflux_crypto::safety_number(&material.self_material, &material.contact_material);
        let device_set_hash = ramflux_crypto::device_set_hash(&material.contact_material.devices);
        let status = self
            .account_db()?
            .contact_verification(contact_identity_commitment)?
            .map_or_else(|| "unverified".to_owned(), |record| record.verification_state);
        Ok(SdkContactSafetyNumber {
            contact_identity_commitment: contact_identity_commitment.to_owned(),
            self_identity_commitment: material.self_identity_commitment,
            safety_number,
            fingerprint_hex: bytes_to_hex(&fingerprint),
            safety_number_hash: ramflux_protocol::encode_base64url(fingerprint),
            self_device_count: material.self_material.devices.len(),
            contact_device_count: material.contact_material.devices.len(),
            contact_device_set_hash: ramflux_protocol::encode_base64url(device_set_hash),
            contact_lineage_head: ramflux_protocol::encode_base64url(
                &material.contact_material.lineage_head,
            ),
            verification_state: status,
        })
    }

    /// # Errors
    /// Returns an error when the contact is not linked or either published device manifest cannot
    /// be fetched and verified.
    pub(crate) async fn contact_safety_number_via_gateway(
        &self,
        gateway: &GatewaySessionConfig,
        contact_identity_commitment: &str,
    ) -> Result<SdkContactSafetyNumber, SdkError> {
        let material = self
            .contact_safety_material_pair_via_gateway(gateway, contact_identity_commitment)
            .await?;
        let fingerprint =
            ramflux_crypto::safety_fingerprint(&material.self_material, &material.contact_material);
        let safety_number =
            ramflux_crypto::safety_number(&material.self_material, &material.contact_material);
        let device_set_hash = ramflux_crypto::device_set_hash(&material.contact_material.devices);
        let status =
            self.account_db()?.contact_verification(contact_identity_commitment)?.map_or_else(
                || "unverified".to_owned(),
                |record| {
                    if record.verified_device_set_hash
                        == ramflux_protocol::encode_base64url(device_set_hash)
                    {
                        record.verification_state
                    } else if record.verification_state == "verified" {
                        "verification_stale".to_owned()
                    } else {
                        record.verification_state
                    }
                },
            );
        Ok(SdkContactSafetyNumber {
            contact_identity_commitment: contact_identity_commitment.to_owned(),
            self_identity_commitment: material.self_identity_commitment,
            safety_number,
            fingerprint_hex: bytes_to_hex(&fingerprint),
            safety_number_hash: ramflux_protocol::encode_base64url(fingerprint),
            self_device_count: material.self_material.devices.len(),
            contact_device_count: material.contact_material.devices.len(),
            contact_device_set_hash: ramflux_protocol::encode_base64url(device_set_hash),
            contact_lineage_head: ramflux_protocol::encode_base64url(
                &material.contact_material.lineage_head,
            ),
            verification_state: status,
        })
    }

    /// # Errors
    /// Returns an error when the manifest cannot be fetched, verified, or cached.
    pub(crate) async fn cache_verified_device_manifest(
        &self,
        gateway: &GatewaySessionConfig,
        principal_commitment: &str,
        source: &str,
    ) -> Result<SdkMvp1DeviceManifestResponse, SdkError> {
        let manifest = fetch_verified_device_manifest(gateway, principal_commitment).await?;
        let verified_at = now_unix_timestamp();
        for device in &manifest.devices {
            self.account_db()?.upsert_device_directory_entry(
                &device.device_id,
                &manifest.principal_commitment,
                source,
                verified_at,
            )?;
        }
        Ok(manifest)
    }

    /// # Errors
    /// Returns an error when no trusted local source can resolve the commitment, or when the
    /// resolved commitment fails device-manifest membership verification.
    pub(crate) async fn resolve_target_principal_commitment(
        &self,
        gateway: &GatewaySessionConfig,
        explicit_principal_commitment: Option<&str>,
        device_id: &str,
    ) -> Result<String, SdkError> {
        if let Some(principal_commitment) =
            explicit_principal_commitment.filter(|commitment| !commitment.is_empty())
        {
            self.assert_manifest_active_device_cached(
                gateway,
                principal_commitment,
                device_id,
                "explicit",
            )
            .await?;
            return Ok(principal_commitment.to_owned());
        }
        let Some(entry) = self.account_db()?.device_directory_entry(device_id)? else {
            return self.resolve_target_principal_commitment_from_prekey(gateway, device_id).await;
        };
        self.assert_manifest_active_device_cached(
            gateway,
            &entry.principal_commitment,
            device_id,
            "device_directory",
        )
        .await?;
        Ok(entry.principal_commitment)
    }

    async fn resolve_target_principal_commitment_from_prekey(
        &self,
        gateway: &GatewaySessionConfig,
        device_id: &str,
    ) -> Result<String, SdkError> {
        let prekey: SdkMvp1PrekeyResponse =
            sdk_gateway_get_json(gateway, &format!("/mvp1/prekey/{device_id}")).await?;
        if prekey.principal_commitment.is_empty() {
            return Err(SdkError::LocalBus(format!(
                "cannot resolve principal commitment for target device {device_id} from local trusted device directory or prekey registry"
            )));
        }
        let manifest = self
            .cache_verified_device_manifest(gateway, &prekey.principal_commitment, "prekey_resolve")
            .await?;
        if !manifest.devices.iter().any(|device| device.device_id == device_id) {
            return Err(SdkError::LocalBus(format!(
                "recipient device {device_id} is not in verified manifest for {}",
                prekey.principal_commitment
            )));
        }
        Ok(prekey.principal_commitment)
    }

    /// Resolve and verify the recipient principal commitment for a federated (cross-node) send.
    ///
    /// The recipient lives on a remote home node, so the sender's local gateway/device directory
    /// cannot serve the manifest. Instead the manifest is fetched directly from the recipient home
    /// node's federation HTTP surface (`manifest_url`, the same base the federated send already uses
    /// for the recipient prekey). Verification is identical to the local path: the manifest's root
    /// public key must commit to the expected `principal_commitment` and every device branch proof
    /// must be signed by that root, so a lying remote node can only fail closed, never forge a
    /// manifest for a commitment it does not control. The verified entries are cached into the local
    /// trusted device directory.
    ///
    /// # Errors
    /// Returns an error (fail-closed) when no explicit recipient principal commitment is supplied,
    /// when the manifest cannot be fetched or verified, or when the target device is absent from the
    /// verified manifest.
    pub(crate) fn resolve_federated_target_principal_commitment(
        &self,
        manifest_url: &str,
        explicit_principal_commitment: Option<&str>,
        device_id: &str,
    ) -> Result<String, SdkError> {
        let principal_commitment = explicit_principal_commitment
            .filter(|commitment| !commitment.is_empty())
            .ok_or_else(|| {
                SdkError::LocalBus(
                    "federated direct messages require an explicit recipient principal commitment to verify the remote device manifest"
                        .to_owned(),
                )
            })?;
        let manifest = fetch_verified_device_manifest_from_url(manifest_url, principal_commitment)?;
        let verified_at = now_unix_timestamp();
        for device in &manifest.devices {
            self.account_db()?.upsert_device_directory_entry(
                &device.device_id,
                &manifest.principal_commitment,
                "federation",
                verified_at,
            )?;
        }
        if !manifest.devices.iter().any(|device| device.device_id == device_id) {
            return Err(SdkError::LocalBus(format!(
                "recipient device {device_id} is not in verified manifest for {principal_commitment}"
            )));
        }
        Ok(principal_commitment.to_owned())
    }

    /// # Errors
    /// Returns an error when the verified manifest does not contain the active target device.
    pub(crate) async fn assert_manifest_active_device_cached(
        &self,
        gateway: &GatewaySessionConfig,
        principal_commitment: &str,
        device_id: &str,
        source: &str,
    ) -> Result<SdkMvp1DeviceManifestDevice, SdkError> {
        let manifest =
            self.cache_verified_device_manifest(gateway, principal_commitment, source).await?;
        manifest.devices.into_iter().find(|device| device.device_id == device_id).ok_or_else(|| {
            SdkError::LocalBus(format!(
                "recipient device {device_id} is not in verified manifest for {principal_commitment}"
            ))
        })
    }

    /// # Errors
    /// Returns an error when the contact cannot be verified or persisted.
    pub fn mark_contact_safety_verified(
        &self,
        contact_identity_commitment: &str,
        verified_by_device_id: &str,
    ) -> Result<ContactVerificationRecord, SdkError> {
        let safety = self.contact_safety_number(contact_identity_commitment)?;
        Ok(self.account_db()?.mark_contact_verified(ContactVerificationUpdate {
            contact_identity_commitment,
            safety_number_hash: &safety.safety_number_hash,
            device_set_hash: &safety.contact_device_set_hash,
            lineage_head: &safety.contact_lineage_head,
            verified_at: now_unix_timestamp(),
            verified_by_device_id,
        })?)
    }

    /// # Errors
    /// Returns an error when verification state cannot be read.
    pub fn contact_verification_status(
        &self,
        contact_identity_commitment: &str,
    ) -> Result<Option<ContactVerificationRecord>, SdkError> {
        Ok(self.account_db()?.contact_verification(contact_identity_commitment)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the friend link cannot be updated.
    pub fn remove_friend_link(
        &self,
        link_id: &str,
        scope: &str,
    ) -> Result<FriendLinkRecord, SdkError> {
        let link = self.account_db()?.remove_friend_link(link_id, scope, now_unix_timestamp())?;
        self.append_contact_control_event("friend.removed", &link)?;
        Ok(link)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the friend link cannot be updated.
    pub fn block_friend_link(&self, link_id: &str) -> Result<FriendLinkRecord, SdkError> {
        let link = self.account_db()?.block_friend_link(link_id, now_unix_timestamp())?;
        self.append_contact_control_event("friend.blocked", &link)?;
        Ok(link)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the friend link cannot be updated.
    pub fn unblock_friend_link(&self, link_id: &str) -> Result<FriendLinkRecord, SdkError> {
        let link = self.account_db()?.unblock_friend_link(link_id, now_unix_timestamp())?;
        self.append_contact_control_event("friend.unblocked", &link)?;
        Ok(link)
    }

    /// Records an inbound friend request as a pending friend link awaiting the
    /// recipient's accept/reject decision.
    ///
    /// # Errors
    /// Returns an error when no account DB is unlocked or the pending friend link
    /// cannot be stored.
    pub fn record_pending_friend_link(
        &self,
        link_id: &str,
        requester_id: &str,
        target_id: &str,
    ) -> Result<FriendLinkRecord, SdkError> {
        Ok(self.account_db()?.record_pending_friend_link(
            link_id,
            requester_id,
            target_id,
            now_unix_timestamp(),
        )?)
    }

    /// Declines a pending inbound friend request, transitioning it to the
    /// `rejected` state. This is distinct from remove/block of an already
    /// established contact.
    ///
    /// # Errors
    /// Returns an error when no account DB is unlocked, the link is not a pending
    /// inbound request, or the friend link cannot be updated.
    pub fn reject_friend_link(&self, link_id: &str) -> Result<FriendLinkRecord, SdkError> {
        let link = self.account_db()?.reject_friend_link(link_id, now_unix_timestamp())?;
        self.append_contact_control_event("friend.rejected", &link)?;
        Ok(link)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or rejected inbox cannot be read.
    pub fn rejected_inbox(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<ramflux_storage::RejectedInboxRecord>, SdkError> {
        Ok(self.account_db()?.rejected_inbox(conversation_id)?)
    }

    /// # Errors
    pub(crate) fn friend_rejection_reason(
        &self,
        sender_id: &str,
    ) -> Result<Option<String>, SdkError> {
        let Some(link) = self.account_db()?.friend_link_for_peer(sender_id)? else {
            return Ok(None);
        };
        if link.blocked {
            return Ok(Some("friend.blocked".to_owned()));
        }
        if link.capability_revoked_at.is_some() {
            return Ok(Some("friend.capability_revoked".to_owned()));
        }
        Ok(None)
    }

    pub(crate) fn append_contact_control_event(
        &self,
        event_type: &str,
        link: &FriendLinkRecord,
    ) -> Result<(), SdkError> {
        let event_id = format!("{event_type}:{}", link.link_id);
        let body = serde_json::to_vec(&serde_json::json!({
            "type": event_type,
            "link_id": link.link_id,
            "requester": link.requester_id,
            "target": link.target_id,
            "remove_scope": link.remove_scope,
            "blocked": link.blocked,
            "capability_revoked_at": link.capability_revoked_at,
        }))?;
        self.append_event(&event_id, event_type, &body)?;
        self.set_projection_checkpoint("friend.control", &event_id)
    }

    pub(crate) fn apply_contact_event_plaintext(&self, plaintext: &[u8]) -> Result<(), SdkError> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(plaintext) else {
            return Ok(());
        };
        let Some(event_type) = value.get("type").and_then(serde_json::Value::as_str) else {
            return Ok(());
        };
        match event_type {
            "friend.requested" => {
                let link_id =
                    value.get("link_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.requested missing link_id".to_owned())
                    })?;
                let requester_id =
                    value.get("requester").and_then(serde_json::Value::as_str).ok_or_else(
                        || SdkError::LocalBus("friend.requested missing requester".to_owned()),
                    )?;
                let target_id =
                    value.get("target").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.requested missing target".to_owned())
                    })?;
                let _link = self.record_pending_friend_link(link_id, requester_id, target_id)?;
            }
            "friend.accepted" => {
                let link_id =
                    value.get("link_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.accepted missing link_id".to_owned())
                    })?;
                let requester_id =
                    value.get("requester").and_then(serde_json::Value::as_str).ok_or_else(
                        || SdkError::LocalBus("friend.accepted missing requester".to_owned()),
                    )?;
                let target_id =
                    value.get("target").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.accepted missing target".to_owned())
                    })?;
                let _link = self.establish_friend_link(link_id, requester_id, target_id)?;
            }
            "friend.removed" => {
                let link_id =
                    value.get("link_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.removed missing link_id".to_owned())
                    })?;
                let scope = value
                    .get("scope")
                    .or_else(|| value.get("remove_scope"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("both");
                let _link = self.remove_friend_link(link_id, scope)?;
            }
            "friend.blocked" => {
                let link_id =
                    value.get("link_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.blocked missing link_id".to_owned())
                    })?;
                let _link = self.block_friend_link(link_id)?;
            }
            "friend.unblocked" => {
                let link_id =
                    value.get("link_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                        SdkError::LocalBus("friend.unblocked missing link_id".to_owned())
                    })?;
                let _link = self.unblock_friend_link(link_id)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn contact_safety_material_pair(
        &self,
        contact_identity_commitment: &str,
    ) -> Result<SdkContactSafetyMaterialPair, SdkError> {
        let link = self
            .friend_links()?
            .into_iter()
            .find(|link| {
                link.state == "accepted"
                    && (link.requester_id == contact_identity_commitment
                        || link.target_id == contact_identity_commitment)
            })
            .ok_or_else(|| {
                SdkError::LocalBus(format!("contact is not linked: {contact_identity_commitment}"))
            })?;
        let self_identity_commitment = if link.requester_id == contact_identity_commitment {
            link.target_id
        } else {
            link.requester_id
        };
        Ok(SdkContactSafetyMaterialPair {
            self_material: contact_safety_material_for(&self_identity_commitment),
            contact_material: contact_safety_material_for(contact_identity_commitment),
            self_identity_commitment,
        })
    }

    async fn contact_safety_material_pair_via_gateway(
        &self,
        gateway: &GatewaySessionConfig,
        contact_identity_commitment: &str,
    ) -> Result<SdkContactSafetyMaterialPair, SdkError> {
        let link = self
            .friend_links()?
            .into_iter()
            .find(|link| {
                link.state == "accepted"
                    && (link.requester_id == contact_identity_commitment
                        || link.target_id == contact_identity_commitment)
            })
            .ok_or_else(|| {
                SdkError::LocalBus(format!("contact is not linked: {contact_identity_commitment}"))
            })?;
        let self_identity_commitment = if link.requester_id == contact_identity_commitment {
            link.target_id
        } else {
            link.requester_id
        };
        let self_manifest = self
            .cache_verified_device_manifest(
                gateway,
                &self_identity_commitment,
                "contact.safety_number",
            )
            .await?;
        let contact_manifest = self
            .cache_verified_device_manifest(
                gateway,
                contact_identity_commitment,
                "contact.safety_number",
            )
            .await?;
        Ok(SdkContactSafetyMaterialPair {
            self_material: contact_safety_material_from_manifest(&self_manifest)?,
            contact_material: contact_safety_material_from_manifest(&contact_manifest)?,
            self_identity_commitment,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SdkContactSafetyNumber {
    pub contact_identity_commitment: String,
    pub self_identity_commitment: String,
    pub safety_number: Vec<String>,
    pub fingerprint_hex: String,
    pub safety_number_hash: String,
    pub self_device_count: usize,
    pub contact_device_count: usize,
    pub contact_device_set_hash: String,
    pub contact_lineage_head: String,
    pub verification_state: String,
}

struct SdkContactSafetyMaterialPair {
    self_material: ramflux_crypto::ContactSafetyMaterial,
    contact_material: ramflux_crypto::ContactSafetyMaterial,
    self_identity_commitment: String,
}

fn contact_safety_material_for(identity_commitment: &str) -> ramflux_crypto::ContactSafetyMaterial {
    let identity_bytes = identity_commitment.as_bytes();
    let device_epoch = 1;
    ramflux_crypto::ContactSafetyMaterial {
        identity_commitment: identity_bytes.to_vec(),
        identity_key_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.identity_key_hash.v1",
            identity_bytes,
        )
        .to_vec(),
        lineage_head: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.lineage_head.v1",
            identity_bytes,
        )
        .to_vec(),
        devices: vec![ramflux_crypto::DeviceSafetyMaterial {
            device_id_hash: ramflux_crypto::blake3_256(
                "ramflux.sdk.contact.device_id_hash.v1",
                identity_bytes,
            )
            .to_vec(),
            device_identity_key_hash: ramflux_crypto::blake3_256(
                "ramflux.sdk.contact.device_identity_key_hash.v1",
                identity_bytes,
            )
            .to_vec(),
            device_signing_key_hash: ramflux_crypto::blake3_256(
                "ramflux.sdk.contact.device_signing_key_hash.v1",
                identity_bytes,
            )
            .to_vec(),
            device_x25519_identity_key_hash: ramflux_crypto::blake3_256(
                "ramflux.sdk.contact.device_x25519_identity_key_hash.v1",
                identity_bytes,
            )
            .to_vec(),
            device_epoch,
            branch_authorized_event_id: format!(
                "device.branch_authorized:{identity_commitment}:{device_epoch}"
            )
            .into_bytes(),
        }],
    }
}

pub(crate) async fn fetch_verified_device_manifest(
    gateway: &GatewaySessionConfig,
    identity_commitment: &str,
) -> Result<SdkMvp1DeviceManifestResponse, SdkError> {
    let manifest: Option<SdkMvp1DeviceManifestResponse> =
        sdk_gateway_get_json(gateway, &format!("/mvp1/device-manifest/{identity_commitment}"))
            .await?;
    let manifest = manifest.ok_or_else(|| {
        SdkError::LocalBus(format!("missing device manifest for {identity_commitment}"))
    })?;
    verify_device_manifest(&manifest, identity_commitment)?;
    Ok(manifest)
}

/// Fetch and verify a device manifest from an absolute federation HTTP base URL (the recipient's
/// home node), rather than the sender's gateway session. Used for cross-node federated sends where
/// the recipient is not served by the local gateway. Verification is identical to the gateway path
/// (`verify_device_manifest`), so the manifest remains self-authenticating against the expected
/// commitment regardless of which node served it.
pub(crate) fn fetch_verified_device_manifest_from_url(
    manifest_url: &str,
    identity_commitment: &str,
) -> Result<SdkMvp1DeviceManifestResponse, SdkError> {
    let manifest: Option<SdkMvp1DeviceManifestResponse> =
        sdk_http_get_json(manifest_url, &format!("/mvp1/device-manifest/{identity_commitment}"))?;
    let manifest = manifest.ok_or_else(|| {
        SdkError::LocalBus(format!("missing device manifest for {identity_commitment}"))
    })?;
    verify_device_manifest(&manifest, identity_commitment)?;
    Ok(manifest)
}

/// # Errors
/// Returns an error when the device manifest is missing, fails verification, or does not contain
/// the expected active device.
pub(crate) async fn assert_manifest_active_device(
    gateway: &GatewaySessionConfig,
    principal_commitment: &str,
    device_id: &str,
) -> Result<SdkMvp1DeviceManifestDevice, SdkError> {
    let manifest = fetch_verified_device_manifest(gateway, principal_commitment).await?;
    manifest.devices.into_iter().find(|device| device.device_id == device_id).ok_or_else(|| {
        SdkError::LocalBus(format!(
            "recipient device {device_id} is not in verified manifest for {principal_commitment}"
        ))
    })
}

/// # Errors
/// Returns an error when a targeted device fanout does not carry the principal commitment needed
/// to verify manifest membership, or when the verified manifest check fails.
pub(crate) async fn assert_target_manifest_active_device(
    gateway: &GatewaySessionConfig,
    principal_commitment: Option<&str>,
    device_id: &str,
) -> Result<SdkMvp1DeviceManifestDevice, SdkError> {
    let principal_commitment =
        principal_commitment.filter(|commitment| !commitment.is_empty()).ok_or_else(|| {
            SdkError::LocalBus(
                "cannot verify manifest membership for target device without principal commitment"
                    .to_owned(),
            )
        })?;
    assert_manifest_active_device(gateway, principal_commitment, device_id).await
}

fn verify_device_manifest(
    manifest: &SdkMvp1DeviceManifestResponse,
    expected_identity_commitment: &str,
) -> Result<(), SdkError> {
    if manifest.principal_commitment != expected_identity_commitment {
        return Err(SdkError::LocalBus(format!(
            "device manifest principal commitment mismatch for {expected_identity_commitment}"
        )));
    }
    let root_commitment = identity_root_public_key_commitment(&manifest.root_public_key)?;
    if root_commitment != expected_identity_commitment {
        return Err(SdkError::LocalBus(format!(
            "device manifest root commitment mismatch for {expected_identity_commitment}"
        )));
    }
    if manifest.devices.is_empty() {
        return Err(SdkError::LocalBus(format!(
            "device manifest has no devices for {expected_identity_commitment}"
        )));
    }
    let root_public_key = ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?;
    let now = now_unix_timestamp();
    for device in &manifest.devices {
        if device.principal_id != manifest.principal_id
            || device.principal_commitment != expected_identity_commitment
            || device.branch_proof.principal_id != manifest.principal_id
            || device.branch_proof.device_id != device.device_id
            || device.branch_proof.device_epoch != device.device_epoch
            || device.prekey_bundle.device_id != device.device_id
            || device.prekey_bundle.device_epoch != device.device_epoch
        {
            return Err(SdkError::LocalBus(format!(
                "device manifest record mismatch for {}",
                device.device_id
            )));
        }
        ramflux_crypto::verify_branch_proof(
            &root_public_key,
            &device.branch_proof,
            "ramflux-node",
            "device.delivery.bind",
            now,
        )
        .map_err(|error| {
            SdkError::LocalBus(format!("branch proof invalid for {}: {error}", device.device_id))
        })?;
        let branch_public_key =
            ramflux_crypto::verifying_key_from_base64url(&device.branch_public_key)?;
        ramflux_crypto::verify_prekey_bundle(&branch_public_key, &device.prekey_bundle).map_err(
            |error| SdkError::LocalBus(format!("prekey invalid for {}: {error}", device.device_id)),
        )?;
    }
    Ok(())
}

fn contact_safety_material_from_manifest(
    manifest: &SdkMvp1DeviceManifestResponse,
) -> Result<ramflux_crypto::ContactSafetyMaterial, SdkError> {
    let identity_bytes = manifest.principal_commitment.as_bytes();
    Ok(ramflux_crypto::ContactSafetyMaterial {
        identity_commitment: identity_bytes.to_vec(),
        identity_key_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.identity_key_hash.v1",
            manifest.root_public_key.as_bytes(),
        )
        .to_vec(),
        lineage_head: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.lineage_head.v1",
            manifest.root_public_key.as_bytes(),
        )
        .to_vec(),
        devices: manifest
            .devices
            .iter()
            .map(device_safety_material)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn device_safety_material(
    device: &crate::prekey::SdkMvp1DeviceManifestDevice,
) -> Result<ramflux_crypto::DeviceSafetyMaterial, SdkError> {
    let branch_public_key_bytes = ramflux_protocol::decode_base64url(&device.branch_public_key)
        .map_err(|error| SdkError::LocalBus(format!("invalid branch public key: {error}")))?;
    Ok(ramflux_crypto::DeviceSafetyMaterial {
        device_id_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.device_id_hash.v1",
            device.device_id.as_bytes(),
        )
        .to_vec(),
        device_identity_key_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.device_identity_key_hash.v1",
            &branch_public_key_bytes,
        )
        .to_vec(),
        device_signing_key_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.device_signing_key_hash.v1",
            &branch_public_key_bytes,
        )
        .to_vec(),
        device_x25519_identity_key_hash: ramflux_crypto::blake3_256(
            "ramflux.sdk.contact.device_x25519_identity_key_hash.v1",
            &device.prekey_bundle.identity_key,
        )
        .to_vec(),
        device_epoch: device.device_epoch,
        branch_authorized_event_id: device.branch_authorized_event_id.as_bytes().to_vec(),
    })
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_fixture(
        principal_id: &str,
        device_id: &str,
        root_seed: [u8; 32],
        branch_seed: [u8; 32],
        x25519_seed: [u8; 32],
        signed_prekey_seed: [u8; 32],
    ) -> Result<SdkMvp1DeviceManifestResponse, SdkError> {
        let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
        let root_public_key =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let principal_commitment = identity_root_public_key_commitment(&root_public_key)?;
        let branch = ramflux_crypto::create_device_branch(principal_id, device_id, 1, branch_seed);
        let branch_public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
        let branch_proof = ramflux_crypto::authorize_device_branch(
            &root,
            &branch,
            "ramflux-node",
            vec!["device.delivery.bind".to_owned()],
            1_700_000_000,
            4_000_000_000,
        )?;
        let identity_key = ramflux_crypto::X25519KeyPair::from_seed(x25519_seed);
        let signed_prekey = ramflux_crypto::X25519KeyPair::from_seed(signed_prekey_seed);
        let prekey_bundle = ramflux_crypto::create_prekey_bundle(
            &branch,
            &identity_key,
            &format!("{device_id}:signed:1"),
            &signed_prekey,
            None,
            None,
        )?;
        Ok(SdkMvp1DeviceManifestResponse {
            principal_id: principal_id.to_owned(),
            principal_commitment: principal_commitment.clone(),
            root_public_key,
            devices: vec![crate::prekey::SdkMvp1DeviceManifestDevice {
                principal_id: principal_id.to_owned(),
                principal_commitment,
                device_id: device_id.to_owned(),
                device_epoch: 1,
                branch_public_key,
                target_delivery_id: format!("target_{device_id}"),
                branch_proof,
                prekey_bundle,
                branch_authorized_event_id: format!("device.branch_authorized:{device_id}:1"),
            }],
        })
    }

    #[test]
    fn device_manifest_rejects_root_commitment_mismatch() -> Result<(), SdkError> {
        let mut manifest = manifest_fixture(
            "principal_alice",
            "alice_device",
            [0x11; 32],
            [0x12; 32],
            [0x13; 32],
            [0x14; 32],
        )?;
        let expected = manifest.principal_commitment.clone();
        let attacker = ramflux_crypto::create_identity_root("principal_attacker", [0x21; 32]);
        manifest.root_public_key =
            ramflux_protocol::encode_base64url(attacker.signing_key.verifying_key().to_bytes());

        let Err(error) = verify_device_manifest(&manifest, &expected) else {
            return Err(SdkError::LocalBus("root mismatch was accepted".to_owned()));
        };
        assert!(error.to_string().contains("root commitment mismatch"));
        Ok(())
    }

    #[test]
    fn device_manifest_rejects_tampered_branch_proof() -> Result<(), SdkError> {
        let mut manifest = manifest_fixture(
            "principal_alice",
            "alice_device",
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            [0x34; 32],
        )?;
        let expected = manifest.principal_commitment.clone();
        manifest.devices[0].branch_proof.signature = "tampered".to_owned();

        assert!(verify_device_manifest(&manifest, &expected).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn targeted_fanout_requires_principal_commitment() -> Result<(), SdkError> {
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0"
                .parse()
                .map_err(|error| SdkError::LocalBus(format!("invalid bind addr: {error}")))?,
            gateway_addr: "127.0.0.1:1"
                .parse()
                .map_err(|error| SdkError::LocalBus(format!("invalid gateway addr: {error}")))?,
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_alice".to_owned(),
            device_id: "alice_device".to_owned(),
            target_delivery_id: "target_alice_device".to_owned(),
            prekey_http_url: None,
        });

        for commitment in [None, Some("")] {
            let Err(error) =
                assert_target_manifest_active_device(&gateway, commitment, "alice_device").await
            else {
                return Err(SdkError::LocalBus(
                    "targeted fanout accepted a missing principal commitment".to_owned(),
                ));
            };
            assert!(error.to_string().contains(
                "cannot verify manifest membership for target device without principal commitment"
            ));
        }
        Ok(())
    }

    #[test]
    fn manifest_material_mapping_is_byte_stable_and_symmetric() -> Result<(), SdkError> {
        let alice = manifest_fixture(
            "principal_alice",
            "alice_device",
            [0x41; 32],
            [0x42; 32],
            [0x43; 32],
            [0x44; 32],
        )?;
        let bob = manifest_fixture(
            "principal_bob",
            "bob_device",
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
        )?;
        let alice_self = contact_safety_material_from_manifest(&alice)?;
        let alice_contact = contact_safety_material_from_manifest(&alice)?;
        let bob_material = contact_safety_material_from_manifest(&bob)?;

        assert_eq!(alice_self, alice_contact);
        assert_eq!(
            ramflux_crypto::safety_fingerprint(&alice_self, &bob_material),
            ramflux_crypto::safety_fingerprint(&bob_material, &alice_contact)
        );
        Ok(())
    }

    fn unlocked_client(test_name: &str) -> Result<(RamfluxClient, PathBuf), SdkError> {
        let nanos = now_unix_timestamp();
        let root = std::env::temp_dir()
            .join(format!("ramflux-sdk-contact-{test_name}-{}-{nanos}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_contact", [0x61; 32]);
        client.create_device_branch("principal_contact", "device_contact", 1, [0x62; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", "principal_contact")?;
        client.unlock_account("acct", b"contact-reject-test")?;
        Ok((client, root))
    }

    #[test]
    fn reject_friend_link_transitions_pending_to_rejected() -> Result<(), SdkError> {
        let (client, root) = unlocked_client("reject-pending")?;

        let pending =
            client.record_pending_friend_link("link_pending", "requester", "principal_contact")?;
        assert_eq!(pending.state, "pending");

        let rejected = client.reject_friend_link("link_pending")?;
        assert_eq!(rejected.state, "rejected");
        assert_eq!(rejected.requester_id, "requester");

        // A second reject is refused: the link is no longer a pending request.
        assert!(client.reject_friend_link("link_pending").is_err());

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn reject_friend_link_refuses_established_contact() -> Result<(), SdkError> {
        let (client, root) = unlocked_client("reject-established")?;

        client.establish_friend_link("link_acc", "requester", "principal_contact")?;
        assert!(client.reject_friend_link("link_acc").is_err());
        let link = client
            .friend_links()?
            .into_iter()
            .find(|link| link.link_id == "link_acc")
            .ok_or_else(|| SdkError::LocalBus("established link present".to_owned()))?;
        assert_eq!(link.state, "accepted");

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn apply_friend_requested_event_records_pending_link() -> Result<(), SdkError> {
        let (client, root) = unlocked_client("apply-requested")?;

        let event = serde_json::to_vec(&serde_json::json!({
            "type": "friend.requested",
            "link_id": "link_inbound",
            "requester": "requester",
            "target": "principal_contact",
        }))?;
        client.apply_contact_event_plaintext(&event)?;

        let link = client
            .friend_links()?
            .into_iter()
            .find(|link| link.link_id == "link_inbound")
            .ok_or_else(|| SdkError::LocalBus("pending inbound link recorded".to_owned()))?;
        assert_eq!(link.state, "pending");

        let rejected = client.reject_friend_link("link_inbound")?;
        assert_eq!(rejected.state, "rejected");

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
