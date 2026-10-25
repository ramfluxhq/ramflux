// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-owned enrollment and explicit complete-set migration; never endorse unbound server keys.
use super::{invalid, record_key};
use crate::prelude::*;
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry, SignedDeviceSetRecord,
};
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn local_principal_kind(&self) -> Result<PrincipalKind, SdkError> {
        if let Ok(db) = self.account_db() {
            let path =
                local_bus_account_manifest_path(self.account_index()?.root(), &db.local_account_id);
            if path.exists() {
                let manifest = read_local_bus_account_manifest(&path)?;
                let kind =
                    manifest.kind.map(|k| serde_json::from_value(json!(k))).transpose()?.unwrap_or(
                        if manifest.client_mode == LocalBusClientMode::HeadlessAi {
                            PrincipalKind::HeadlessAi
                        } else {
                            PrincipalKind::Human
                        },
                    );
                if manifest.client_mode == LocalBusClientMode::HeadlessAi
                    && kind == PrincipalKind::Human
                {
                    return Err(invalid("headless account cannot claim human kind"));
                }
                return Ok(kind);
            }
        }
        Ok(PrincipalKind::Human)
    }
    pub(crate) fn bound_current_device_proof(
        &self,
        audience: &str,
        capabilities: Vec<String>,
        issued: i64,
        expires: i64,
    ) -> Result<BranchProofDocument, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let agreement = if let Some(stored) =
            self.optional_owned_private_prekey(&self.owned_device_identity()?)?
        {
            stored.bundle.identity_key
        } else {
            X25519KeyPair::from_seed(x3dh_private_seed(
                "ramflux.sdk.x3dh.identity.v1",
                &branch.signing_key.to_bytes(),
            ))
            .public
        };
        let mut proof = ramflux_crypto::authorize_device_branch_v2(
            root,
            branch,
            ramflux_crypto::BranchAuthorization {
                audience,
                capability_scope: capabilities,
                issued_at: issued,
                expires_at: expires,
                principal_kind: self.local_principal_kind()?,
                agreement_identity_public_key: agreement,
            },
        )?;
        // Registrations in the same clock second still need distinct replay identifiers.
        proof.proof_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        proof.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_crypto::branch_proof_signing_bytes(&proof)?,
            root.signing_key.to_bytes(),
        );
        Ok(proof)
    }
    /// Import independently root-signed authorizations from other legacy devices before migration.
    /// Unbound v1 directory keys are never upgraded by signing the server's claims.
    /// # Errors
    /// Rejects wrong roots, kinds, expired/unbound proofs, conflicting IDs and oversized input.
    pub fn import_legacy_device_authorizations(
        &self,
        proofs: &[BranchProofDocument],
    ) -> Result<(), SdkError> {
        if proofs.len() > 1024 || serde_json::to_vec(proofs)?.len() > 512 * 1024 {
            return Err(invalid("migration authorization budget exceeded"));
        }
        let mut retained = self
            .account_db()?
            .load_actor_state::<Vec<BranchProofDocument>>("identity/legacy_authorizations")?
            .unwrap_or_default();
        for proof in proofs {
            self.verify_owned_authorization(proof)?;
            retained.retain(|p| p.device_id != proof.device_id);
            retained.push(proof.clone());
        }
        if retained.len() > 1024 || serde_json::to_vec(&retained)?.len() > 512 * 1024 {
            return Err(invalid("migration authorization budget exceeded"));
        }
        self.account_db()?.persist_actor_state("identity/legacy_authorizations", &retained)?;
        Ok(())
    }
    fn verify_owned_authorization(&self, proof: &BranchProofDocument) -> Result<(), SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let binding = proof
            .key_binding
            .as_ref()
            .ok_or_else(|| invalid("migration needs root-bound authorizations"))?;
        if proof.principal_id != root.principal_id
            || binding.principal_kind != self.local_principal_kind()?
        {
            return Err(invalid("migration owner or kind mismatch"));
        }
        ramflux_crypto::verify_root_bound_branch_proof(
            &root.signing_key.verifying_key(),
            proof,
            binding,
            "ramflux-node",
            "device.delivery.bind",
            now_unix_timestamp(),
        )?;
        Ok(())
    }
    fn legacy_migration_entries(
        &self,
        remote: &SdkDeviceManifestResponse,
        local: &str,
    ) -> Result<Vec<SignedDeviceSetEntry>, SdkError> {
        let approvals = self
            .account_db()?
            .load_actor_state::<Vec<BranchProofDocument>>("identity/legacy_authorizations")?
            .unwrap_or_default();
        let mut devices = remote
            .devices
            .iter()
            .map(|d| d.device_id.clone())
            .chain(approvals.iter().map(|p| p.device_id.clone()))
            .collect::<std::collections::BTreeSet<_>>();
        let path = local_bus_account_manifest_path(
            self.account_index()?.root(),
            &self.account_db()?.local_account_id,
        );
        if path.exists() {
            devices.extend(
                read_local_bus_account_manifest(&path)?.devices.into_iter().map(|d| d.device_id),
            );
        }
        devices.remove(local);
        let mut entries = Vec::new();
        for device in devices {
            let proof = approvals
                .iter()
                .find(|p| p.device_id == device)
                .or_else(|| {
                    remote
                        .devices
                        .iter()
                        .find(|d| d.device_id == device)
                        .and_then(|d| d.branch_proof.key_binding.as_ref().map(|_| &d.branch_proof))
                })
                .ok_or_else(|| {
                    invalid(&format!("migration requires a root-bound authorization for {device}"))
                })?;
            self.verify_owned_authorization(proof)?;
            entries.push(entry_from_proof(proof)?);
        }
        Ok(entries)
    }
    pub(crate) fn validate_owned_registration_set(
        &self,
        record: &SignedDeviceSetRecord,
        proof: &BranchProofDocument,
    ) -> Result<(), SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), record)?;
        self.check_observed_set(record)?;
        let entry = entry_from_proof(proof)?;
        if record.principal_id != root.principal_id
            || record.principal_kind != self.local_principal_kind()?
            || !record.devices.contains(&entry)
        {
            return Err(invalid(
                "staged registration authority is stale or belongs to another device",
            ));
        }
        Ok(())
    }
    pub(crate) fn prepare_owned_authority(
        &self,
        remote: Option<&SdkDeviceManifestResponse>,
    ) -> Result<SignedDeviceSetRecord, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let mut previous = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>(&record_key(&commitment))?;
        if let Some(remote) = remote {
            if remote.principal_id != root.principal_id
                || remote.principal_commitment != commitment
                || remote.root_public_key
                    != ramflux_protocol::encode_base64url(
                        root.signing_key.verifying_key().to_bytes(),
                    )
            {
                return Err(invalid("own manifest root mismatch"));
            }
            if let Some(record) = &remote.signed_device_set {
                if record.principal_id != root.principal_id
                    || record.principal_commitment != commitment
                {
                    return Err(invalid("own signed record principal mismatch"));
                }
                ramflux_crypto::verify_signed_device_set(
                    &root.signing_key.verifying_key(),
                    record,
                )?;
                self.accept_owned_record(record)?;
                previous = Some(record.clone());
            }
        }
        let now = now_unix_timestamp();
        let proof = self.bound_current_device_proof(
            "ramflux-node",
            vec!["device.delivery.bind".into()],
            now,
            now.saturating_add(super::registration::proof_lifetime_seconds()?),
        )?;
        let local = entry_from_proof(&proof)?;
        let mut entries = previous.as_ref().map_or_else(Vec::new, |r| r.devices.clone());
        let local_kind = self.local_principal_kind()?;
        if previous.as_ref().is_some_and(|r| r.principal_kind != local_kind) {
            return Err(invalid("immutable own kind changed"));
        }
        if entries
            .iter()
            .any(|e| e.device_id == local.device_id && e.status == DeviceSetStatus::Revoked)
        {
            return Err(invalid("local device is revoked"));
        }
        if let Some(remote) = remote.filter(|m| m.signed_device_set.is_none() && previous.is_none())
        {
            entries.extend(self.legacy_migration_entries(remote, &local.device_id)?);
        }
        entries.retain(|e| e.device_id != local.device_id);
        entries.push(local);
        self.apply_owned_revocation_intents(&mut entries)?;
        entries.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let pending = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?;
        if let Some(pending) = pending {
            if previous.as_ref().is_none_or(|p| p.device_set_epoch < pending.device_set_epoch) {
                if pending.devices != entries {
                    return Err(invalid("unacknowledged root publication requires reconciliation"));
                }
                return Ok(pending);
            }
            if let Some(previous) = &previous {
                ramflux_crypto::validate_device_set_transition(&pending, previous)?;
            }
        }
        if let Some(old) = previous.as_ref().filter(|r| r.devices == entries) {
            return Ok(old.clone());
        }
        let epoch = previous
            .as_ref()
            .map_or(Some(1), |r| r.device_set_epoch.checked_add(1))
            .ok_or_else(|| invalid("device-set epoch exhausted"))?;
        let next = ramflux_crypto::sign_device_set(
            root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: self.local_principal_kind()?,
                device_set_epoch: epoch,
                devices: entries,
            },
        )?;
        if let Some(old) = &previous {
            ramflux_crypto::validate_device_set_transition(old, &next)?;
        }
        self.account_db()?.persist_actor_state("identity/owned_pending_set", &next)?;
        Ok(next)
    }
    pub(crate) fn accept_owned_record(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if record.principal_id != root.principal_id {
            return Err(invalid("own record principal mismatch"));
        }
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), record)?;
        self.account_db()?.write_transaction(|| {
            self.check_observed_set(record)?;
            self.account_db()?
                .persist_actor_state(&record_key(&record.principal_commitment), record)?;
            self.apply_record_retirements(record)?;
            self.reconcile_owned_pending(record)?;
            Ok::<_, SdkError>(())
        })?;
        self.finish_pair_retirement()
    }
    pub(crate) async fn prepare_owned_authority_via_gateway(
        &self,
        gateway: &GatewaySessionConfig,
    ) -> Result<SignedDeviceSetRecord, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let remote: Option<SdkDeviceManifestResponse> =
            sdk_gateway_get_json(gateway, &format!("/mvp1/device-manifest/{commitment}")).await?;
        self.prepare_owned_authority(remote.as_ref())
    }
}
fn entry_from_proof(proof: &BranchProofDocument) -> Result<SignedDeviceSetEntry, SdkError> {
    let binding = proof.key_binding.as_ref().ok_or_else(|| invalid("unbound migration proof"))?;
    let keys = ramflux_crypto::device_key_commitments(
        &binding.branch_signing_public_key,
        &binding.agreement_identity_public_key,
    )?;
    Ok(SignedDeviceSetEntry {
        device_id: proof.device_id.clone(),
        device_epoch: proof.device_epoch,
        signing_key_commitment: keys.0,
        agreement_key_commitment: keys.1,
        status: DeviceSetStatus::Active,
        revoked_at: None,
    })
}
