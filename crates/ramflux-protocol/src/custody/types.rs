// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact custody envelopes; nullable fields are mandatory on the wire.
use crate::{DeviceSetStatus, PrincipalKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A signature over the domain-separated canonical body, including nested signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub body: T,
    pub signature: String,
}
/// An anchor-qualified device reference, never an unqualified routing label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRef {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
}
/// Master authorization of one self-signing key and one epoch range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterCertificate {
    pub schema: String,
    pub version: u32,
    pub account_anchor: String,
    pub principal_id: String,
    pub principal_kind: PrincipalKind,
    pub master_public_key: String,
    pub self_signing_public_key: String,
    pub primary_device_ref: DeviceRef,
    pub custody_kind: CustodyKind,
    pub scopes: Vec<String>,
    pub range_index: u64,
    pub issued_at: u64,
    pub cert_id: String,
    pub legacy_binding_hash: Option<String>,
    pub previous_certificate_hash: Option<String>,
}
/// Human primary custody or custody by an independently verified human account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyKind {
    LocalHuman,
    ExternalHuman,
}
/// A leased branch capability signed by the current self-signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchCertificate {
    pub schema: String,
    pub version: u32,
    pub account_anchor: String,
    pub master_certificate_hash: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub principal_kind: PrincipalKind,
    pub branch_signing_public_key: String,
    pub agreement_identity_public_key: String,
    pub capabilities: Vec<String>,
    pub not_before: u64,
    pub expires_at: u64,
    pub cert_id: String,
}
/// Immutable genesis provenance and later revocation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    Native,
    PendingErasure,
    Erased,
    Revoked,
}
/// One complete active or recently revoked device roster entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_key_commitment: String,
    pub agreement_key_commitment: String,
    pub status: DeviceSetStatus,
    pub revoked_at: Option<u64>,
    pub branch_certificate: Option<Envelope<BranchCertificate>>,
    pub migration_state: MigrationState,
}
/// Profile authority is the enclosing v3 record, never a separate v1 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub kind: PrincipalKind,
    pub display_name: String,
    pub custodian: Option<DeviceRef>,
}
/// Signed cumulative membership commitment; the list remains required evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedCheckpoint {
    pub schema: String,
    pub version: u32,
    pub account_anchor: String,
    pub master_certificate_hash: String,
    pub device_set_epoch: u64,
    pub previous_checkpoint_hash: Option<String>,
    pub list_hash: String,
    pub count: u64,
    pub compacted_before: u64,
    pub issued_at: u64,
}
/// Hashes of the six complete signed sections, including explicit null sections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionHashes {
    pub profile: String,
    pub devices: String,
    pub delegations: String,
    pub revoked_delegation_ids: String,
    pub migration: String,
    pub revoked_device_checkpoint: String,
}
/// The complete critical v3 record. Stage 1 writers use native origin and no delegations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSet {
    pub schema: String,
    pub version: u32,
    pub principal_id: String,
    pub account_anchor: String,
    pub principal_kind: PrincipalKind,
    pub origin: String,
    pub custody_mode: String,
    pub device_set_epoch: u64,
    pub previous_record_hash: Option<String>,
    pub issued_at: u64,
    pub master_certificate: Envelope<MasterCertificate>,
    pub legacy_binding: Option<Value>,
    pub profile: Profile,
    pub devices: Vec<Device>,
    pub delegations: Vec<Value>,
    pub revoked_delegation_ids: Vec<String>,
    pub migration: Option<Value>,
    pub revoked_device_checkpoint: Option<Envelope<RevokedCheckpoint>>,
    pub section_hashes: SectionHashes,
}
