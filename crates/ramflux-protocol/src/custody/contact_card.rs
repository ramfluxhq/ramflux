// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Portable native contact identity, certified by the offline master.
use super::{Device, Envelope, MasterCertificate};
use serde::{Deserialize, Serialize};

pub const CONTACT_CARD_V3_DOMAIN: &str = "ramflux.contact.card.v3";
pub const MAX_CONTACT_CARD_V3_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactCardV3 {
    pub version: u32,
    pub reach: Option<crate::account_reach::ReachRecord>,
    pub principal_id: String,
    pub account_anchor: String,
    pub master_public_key: String,
    pub master_certificate: Envelope<MasterCertificate>,
    pub authority_head_hash: String,
    /// `device_set_epoch` of the issuing record. A required signed floor: acceptance needs a
    /// current authority at or above it, and the exact head when the epochs are equal.
    pub authority_epoch: u64,
    pub devices: Vec<Device>,
    pub node_url: String,
    pub node_key_fingerprint: String,
    pub display_name: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
