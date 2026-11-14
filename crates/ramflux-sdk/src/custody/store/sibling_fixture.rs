// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test setup for an independently stored, branch-only native sibling.
use super::*;

pub(crate) struct SiblingSetup<'a> {
    pub root: &'a Path,
    pub id: &'a str,
    pub device: &'a str,
    pub record: Envelope<DeviceSet>,
    pub branch: &'a Zeroizing<[u8; 64]>,
    pub vault: &'a dyn PrimaryVault,
    pub passphrase: &'a [u8],
    pub now: u64,
}

/// Install a primary-certified branch into its own data store and vault. No master
/// secret or primary vault reference is copied to the recipient fixture.
/// # Errors
/// Returns native authority, vault, reservation or storage failures.
pub(crate) fn install_sibling_fixture(setup: SiblingSetup<'_>) -> Result<(), SdkError> {
    let SiblingSetup { root, id, device, record, branch, vault, passphrase, now } = setup;
    let verified = verify_record(&record, now, None, None)?;
    let entry =
        record.body.devices.iter().find(|entry| entry.device_id == device).ok_or_else(invalid)?;
    let reference = ramflux_protocol::custody::DeviceRef {
        account_anchor: record.body.account_anchor.clone(),
        device_id: device.into(),
        device_epoch: entry.device_epoch,
    };
    let credentials = super::super::BranchCredentials::from_vault_seeds(
        &record.body.principal_id,
        &reference,
        branch,
    )?;
    let certified = verified.authorize(&reference, "message", now)?;
    if certified.branch_signing_public_key
        != ramflux_protocol::encode_base64url(
            credentials.signing.signing_key.verifying_key().as_bytes(),
        )
    {
        return Err(invalid());
    }
    let mut pins = AuthorityPins::default();
    pins.observe(&verified)?;
    let dir = genesis::reserve_account(root, id, &record.body.account_anchor)?;
    let branch_ref =
        format!("branch:{}", custody_vault_reference(root, id, &record.body.account_anchor)?);
    let stored = StoredAuthority {
        pairing_adoption_required: false,
        schema: "ramflux.local.custody_account.v1".into(),
        local_account_id: id.into(),
        local_device_id: device.into(),
        state: CreationState::NetworkingPending,
        networking_reason: None,
        networking_node: None,
        capacity_retry_at: None,
        pending_branch: false,
        custody_v3_observed: true,
        primary_vault_ref: String::new(),
        branch_vault_ref: branch_ref.clone(),
        vault_class: vault.vault_class().into(),
        message_layer_sequences: super::super::layer_declaration::sequence_high_water(
            &record.body.account_anchor,
            &record.body.devices,
        )?,
        record,
        compacted_ids: None,
        custodian_publication: None,
        pins,
        custodian_account_id: None,
        agent_provisioning_vault_ref: None,
    };
    vault.store_branch(&branch_ref, branch)?;
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root)?;
    client.seal_new_account_data(id, &stored.record.body.account_anchor, passphrase)?;
    genesis::require_owned_reservation(root, id, &stored.record.body.account_anchor, &dir)?;
    genesis::write_public(
        &dir.join("authority.json"),
        &ramflux_protocol::canonical_json_bytes(&stored)?,
    )?;
    Ok(())
}
