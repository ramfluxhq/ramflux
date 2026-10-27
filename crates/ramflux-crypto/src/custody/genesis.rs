// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One native primary at genesis; no migration, pairing or delegation writer.
use super::{MasterKey, SelfSigningKey};
use crate::{CryptoError, DeviceBranch, X25519KeyPair};
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind,
    custody::{
        BranchCertificate, CustodyKind, Device, DeviceRef, DeviceSet, Envelope, MASTER_SCOPES,
        MAX_BRANCH_LEASE_SECONDS, MasterCertificate, MigrationState, Profile, SectionHashes,
        encode_epoch, object_hash,
    },
    domain, encode_base64url,
};

/// Public setup choices and random certificate ids, fixed once per creation ceremony.
pub struct GenesisInput {
    pub principal_kind: PrincipalKind,
    pub display_name: String,
    pub issued_at: u64,
    pub master_cert_id: String,
    pub branch_cert_id: String,
    pub external_human_primary: Option<DeviceRef>,
}
/// Build the complete native first record without putting the master in runtime state.
/// # Errors
/// Rejects invalid metadata, reused keys, wrong native key epochs, or canonicalization failures.
pub fn create_genesis(
    master: &MasterKey,
    primary: &SelfSigningKey,
    branch: &DeviceBranch,
    agreement: &X25519KeyPair,
    input: GenesisInput,
) -> Result<Envelope<DeviceSet>, CryptoError> {
    if branch.device_epoch != 1 {
        return Err(super::validate::reject("native first device must use epoch one"));
    }
    let anchor = crate::identity_root_commitment(&super::validate::key(&master.public_key())?);
    let local = DeviceRef {
        account_anchor: anchor.clone(),
        device_id: branch.device_id.clone(),
        device_epoch: 1,
    };
    let custodian = input.external_human_primary.clone();
    let cert = master.certify(MasterCertificate {
        schema: domain::CUSTODY_MASTER_CERTIFICATE.into(),
        version: 1,
        account_anchor: anchor.clone(),
        principal_id: branch.principal_id.clone(),
        principal_kind: input.principal_kind,
        master_public_key: master.public_key(),
        self_signing_public_key: primary.public_key(),
        primary_device_ref: input.external_human_primary.unwrap_or(local),
        custody_kind: if input.principal_kind == PrincipalKind::Human {
            CustodyKind::LocalHuman
        } else {
            CustodyKind::ExternalHuman
        },
        scopes: MASTER_SCOPES.into_iter().map(str::to_owned).collect(),
        range_index: 1,
        issued_at: input.issued_at,
        cert_id: input.master_cert_id,
        legacy_binding_hash: None,
        previous_certificate_hash: None,
    })?;
    let signing = encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let agreement_public = encode_base64url(agreement.public);
    let (signing_key_commitment, agreement_key_commitment) =
        crate::device_key_commitments(&signing, &agreement_public)?;
    let branch_cert = primary.certify_branch(BranchCertificate {
        schema: domain::CUSTODY_BRANCH_CERTIFICATE.into(),
        version: 1,
        account_anchor: anchor.clone(),
        master_certificate_hash: object_hash(&cert)?,
        device_id: branch.device_id.clone(),
        device_epoch: 1,
        principal_kind: input.principal_kind,
        branch_signing_public_key: signing,
        agreement_identity_public_key: agreement_public,
        capabilities: ["call", "group", "message", "register", "sync"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        not_before: input.issued_at,
        expires_at: input
            .issued_at
            .checked_add(MAX_BRANCH_LEASE_SECONDS)
            .ok_or_else(|| super::validate::reject("branch lease arithmetic overflow"))?,
        cert_id: input.branch_cert_id,
    })?;
    primary.sign_record(DeviceSet {
        schema: domain::SIGNED_DEVICE_SET_V3.into(),
        version: 3,
        principal_id: branch.principal_id.clone(),
        account_anchor: anchor,
        principal_kind: input.principal_kind,
        origin: "new".into(),
        custody_mode: "v3".into(),
        device_set_epoch: encode_epoch(1, 1)?,
        previous_record_hash: None,
        issued_at: input.issued_at,
        master_certificate: cert,
        legacy_binding: None,
        profile: Profile {
            kind: input.principal_kind,
            display_name: ramflux_protocol::normalize_profile_display_name(&input.display_name)?,
            custodian,
        },
        devices: vec![Device {
            device_id: branch.device_id.clone(),
            device_epoch: 1,
            signing_key_commitment,
            agreement_key_commitment,
            status: DeviceSetStatus::Active,
            revoked_at: None,
            branch_certificate: Some(branch_cert),
            migration_state: MigrationState::Native,
        }],
        delegations: vec![],
        revoked_delegation_ids: vec![],
        migration: None,
        revoked_device_checkpoint: None,
        section_hashes: SectionHashes {
            profile: String::new(),
            devices: String::new(),
            delegations: String::new(),
            revoked_delegation_ids: String::new(),
            migration: String::new(),
            revoked_device_checkpoint: String::new(),
        },
    })
}
