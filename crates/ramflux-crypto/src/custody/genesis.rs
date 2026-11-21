// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One native primary at genesis; no migration, pairing or delegation writer.
//!
//! There is one genesis body. [`create_genesis`] fills a [`GenesisDraft`] with its defaults; the
//! agent creation flow fills the same draft from its approved plan and passes its own issuer for
//! the master certificate (the master stays inside the vault there).
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
use serde::Serialize;

/// Public setup choices and random certificate ids, fixed once per creation ceremony.
pub struct GenesisInput {
    pub principal_kind: PrincipalKind,
    pub display_name: String,
    pub issued_at: u64,
    pub master_cert_id: String,
    pub branch_cert_id: String,
    pub external_human_primary: Option<DeviceRef>,
}

/// Every public value of one genesis, fixed by the caller before any key signs. No secret is here.
pub struct GenesisDraft {
    pub account_anchor: String,
    pub principal_id: String,
    pub principal_kind: PrincipalKind,
    pub display_name: String,
    /// Master `primary_device_ref`.
    pub primary_device_ref: DeviceRef,
    /// Profile `custodian` (absent for a human account).
    pub custodian: Option<DeviceRef>,
    pub master_public_key: String,
    pub self_signing_public_key: String,
    pub master_cert_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub branch_signing_public_key: String,
    pub agreement_public_key: String,
    pub branch_cert_id: String,
    pub branch_capabilities: Vec<String>,
    /// Issue time of the master certificate and of the `DeviceSet`.
    pub issued_at: u64,
    pub branch_not_before: u64,
    pub branch_expires_at: u64,
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
    let branch_expires_at = input
        .issued_at
        .checked_add(MAX_BRANCH_LEASE_SECONDS)
        .ok_or_else(|| super::validate::reject("branch lease arithmetic overflow"))?;
    let draft = GenesisDraft {
        account_anchor: anchor,
        principal_id: branch.principal_id.clone(),
        principal_kind: input.principal_kind,
        display_name: input.display_name,
        primary_device_ref: input.external_human_primary.clone().unwrap_or(local),
        custodian: input.external_human_primary,
        master_public_key: master.public_key(),
        self_signing_public_key: primary.public_key(),
        master_cert_id: input.master_cert_id,
        device_id: branch.device_id.clone(),
        device_epoch: 1,
        branch_signing_public_key: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        agreement_public_key: encode_base64url(agreement.public),
        branch_cert_id: input.branch_cert_id,
        branch_capabilities: ["call", "group", "message", "register", "sync"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        issued_at: input.issued_at,
        branch_not_before: input.issued_at,
        branch_expires_at,
    };
    create_genesis_from_draft(|body| master.certify(body), primary, &draft)
}

/// The one genesis body. `issue_master` signs the master certificate: [`MasterKey::certify`] for
/// a local master, or the vault for a master that never leaves it. Its result must carry exactly
/// the body this function built (checked by hash), so a vault cannot change the approved fields.
/// The branch certificate and the `DeviceSet` are signed by `primary`.
/// # Errors
/// Everything [`create_genesis`] refuses, a lease longer than [`MAX_BRANCH_LEASE_SECONDS`], an
/// anchor that does not derive from the master key, a master certificate whose body differs from
/// the draft, and the error the issuer returns.
pub fn create_genesis_from_draft<E: From<CryptoError>>(
    issue_master: impl FnOnce(MasterCertificate) -> Result<Envelope<MasterCertificate>, E>,
    primary: &SelfSigningKey,
    draft: &GenesisDraft,
) -> Result<Envelope<DeviceSet>, E> {
    let master_body = master_certificate_body(draft).map_err(E::from)?;
    let expected_body_hash = hash_of(&master_body).map_err(E::from)?;
    let master_cert = issue_master(master_body)?;
    assemble(primary, draft, master_cert, &expected_body_hash).map_err(E::from)
}

fn master_certificate_body(draft: &GenesisDraft) -> Result<MasterCertificate, CryptoError> {
    let derived = crate::identity_root_commitment(&super::validate::key(&draft.master_public_key)?);
    if derived != draft.account_anchor {
        return Err(super::validate::reject("genesis anchor does not match the master key"));
    }
    if draft.device_epoch != 1 {
        return Err(super::validate::reject("native first device must use epoch one"));
    }
    let lease = draft
        .branch_expires_at
        .checked_sub(draft.branch_not_before)
        .filter(|lease| *lease > 0 && *lease <= MAX_BRANCH_LEASE_SECONDS);
    if lease.is_none() {
        return Err(super::validate::reject("branch lease is not a bounded positive window"));
    }
    Ok(MasterCertificate {
        schema: domain::CUSTODY_MASTER_CERTIFICATE.into(),
        version: 1,
        account_anchor: draft.account_anchor.clone(),
        principal_id: draft.principal_id.clone(),
        principal_kind: draft.principal_kind,
        master_public_key: draft.master_public_key.clone(),
        self_signing_public_key: draft.self_signing_public_key.clone(),
        primary_device_ref: draft.primary_device_ref.clone(),
        custody_kind: if draft.principal_kind == PrincipalKind::Human {
            CustodyKind::LocalHuman
        } else {
            CustodyKind::ExternalHuman
        },
        scopes: MASTER_SCOPES.into_iter().map(str::to_owned).collect(),
        range_index: 1,
        issued_at: draft.issued_at,
        cert_id: draft.master_cert_id.clone(),
        legacy_binding_hash: None,
        previous_certificate_hash: None,
    })
}

fn assemble(
    primary: &SelfSigningKey,
    draft: &GenesisDraft,
    master_cert: Envelope<MasterCertificate>,
    expected_body_hash: &str,
) -> Result<Envelope<DeviceSet>, CryptoError> {
    if hash_of(&master_cert.body)? != expected_body_hash {
        return Err(CryptoError::IdentityAuthority("master certificate differs from the genesis body"));
    }
    let (signing_key_commitment, agreement_key_commitment) = crate::device_key_commitments(
        &draft.branch_signing_public_key,
        &draft.agreement_public_key,
    )?;
    let branch_cert = primary.certify_branch(BranchCertificate {
        schema: domain::CUSTODY_BRANCH_CERTIFICATE.into(),
        version: 1,
        account_anchor: draft.account_anchor.clone(),
        master_certificate_hash: hash_of(&master_cert)?,
        device_id: draft.device_id.clone(),
        device_epoch: draft.device_epoch,
        principal_kind: draft.principal_kind,
        branch_signing_public_key: draft.branch_signing_public_key.clone(),
        agreement_identity_public_key: draft.agreement_public_key.clone(),
        capabilities: draft.branch_capabilities.clone(),
        not_before: draft.branch_not_before,
        expires_at: draft.branch_expires_at,
        cert_id: draft.branch_cert_id.clone(),
    })?;
    let device_set = DeviceSet {
        schema: domain::SIGNED_DEVICE_SET_V3.into(),
        version: 3,
        principal_id: draft.principal_id.clone(),
        account_anchor: draft.account_anchor.clone(),
        principal_kind: draft.principal_kind,
        origin: "new".into(),
        custody_mode: "v3".into(),
        device_set_epoch: encode_epoch(1, 1)?,
        previous_record_hash: None,
        issued_at: draft.issued_at,
        master_certificate: master_cert,
        legacy_binding: None,
        profile: Profile {
            kind: draft.principal_kind,
            display_name: ramflux_protocol::normalize_profile_display_name(&draft.display_name)?,
            custodian: draft.custodian.clone(),
        },
        devices: vec![Device {
            device_id: draft.device_id.clone(),
            device_epoch: draft.device_epoch,
            signing_key_commitment,
            agreement_key_commitment,
            status: DeviceSetStatus::Active,
            revoked_at: None,
            branch_certificate: Some(branch_cert),
            message_layer: None,
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
    };
    primary.sign_record(device_set)
}

fn hash_of<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    Ok(object_hash(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const ISSUED_AT: u64 = 1_700_000_000;

    fn keys() -> (MasterKey, SelfSigningKey, DeviceBranch, X25519KeyPair) {
        (
            MasterKey::generate().expect("test: random master key"),
            SelfSigningKey::from_vault_seed(&Zeroizing::new([8; 32])),
            crate::create_device_branch("genesis.example", "agent", 1, [9; 32]),
            X25519KeyPair::from_seed([10; 32]),
        )
    }

    fn human_primary() -> DeviceRef {
        DeviceRef {
            account_anchor: encode_base64url([13; 32]),
            device_id: "human-phone".into(),
            device_epoch: 1,
        }
    }

    fn default_draft(
        master: &MasterKey,
        primary: &SelfSigningKey,
        branch: &DeviceBranch,
        agreement: &X25519KeyPair,
        anchor: &str,
        branch_expires_at: u64,
    ) -> GenesisDraft {
        GenesisDraft {
            account_anchor: anchor.to_owned(),
            principal_id: branch.principal_id.clone(),
            principal_kind: PrincipalKind::HeadlessAi,
            display_name: "Genesis Agent".into(),
            primary_device_ref: human_primary(),
            custodian: Some(human_primary()),
            master_public_key: master.public_key(),
            self_signing_public_key: primary.public_key(),
            master_cert_id: encode_base64url([11; 32]),
            device_id: branch.device_id.clone(),
            device_epoch: 1,
            branch_signing_public_key: encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            agreement_public_key: encode_base64url(agreement.public),
            branch_cert_id: encode_base64url([12; 32]),
            branch_capabilities: ["call", "group", "message", "register", "sync"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            issued_at: ISSUED_AT,
            branch_not_before: ISSUED_AT,
            branch_expires_at,
        }
    }

    #[test]
    fn draft_with_default_times_equals_create_genesis_output() {
        let (master, primary, branch, agreement) = keys();
        let created = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: PrincipalKind::HeadlessAi,
                display_name: "Genesis Agent".into(),
                issued_at: ISSUED_AT,
                master_cert_id: encode_base64url([11; 32]),
                branch_cert_id: encode_base64url([12; 32]),
                external_human_primary: Some(human_primary()),
            },
        )
        .expect("test: create_genesis with default times");
        let expires = ISSUED_AT + MAX_BRANCH_LEASE_SECONDS;
        let draft = default_draft(
            &master,
            &primary,
            &branch,
            &agreement,
            &created.body.account_anchor,
            expires,
        );
        let shared = create_genesis_from_draft(|body| master.certify(body), &primary, &draft)
            .expect("test: shared genesis with default times");
        assert_eq!(
            object_hash(&created).expect("test: hash of create_genesis output"),
            object_hash(&shared).expect("test: hash of shared genesis output"),
            "the shared genesis with the default times must be byte-identical to create_genesis"
        );
    }

    #[test]
    fn draft_refuses_a_branch_lease_beyond_the_native_maximum() {
        let (master, primary, branch, agreement) = keys();
        let anchor = crate::identity_root_commitment(
            &super::super::validate::key(&master.public_key()).expect("test: master key"),
        );
        let beyond = default_draft(
            &master,
            &primary,
            &branch,
            &agreement,
            &anchor,
            ISSUED_AT + MAX_BRANCH_LEASE_SECONDS + 1,
        );
        let refused = create_genesis_from_draft::<CryptoError>(
            |body| master.certify(body),
            &primary,
            &beyond,
        );
        assert!(
            refused.is_err(),
            "a branch lease one second beyond MAX_BRANCH_LEASE_SECONDS must be refused"
        );
        let at_max = default_draft(
            &master,
            &primary,
            &branch,
            &agreement,
            &anchor,
            ISSUED_AT + MAX_BRANCH_LEASE_SECONDS,
        );
        assert!(
            create_genesis_from_draft::<CryptoError>(|body| master.certify(body), &primary, &at_max)
                .is_ok(),
            "a branch lease of exactly MAX_BRANCH_LEASE_SECONDS is the existing maximum and must pass"
        );
    }
}
