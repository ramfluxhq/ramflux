// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified group-member authority and accepted contacts inside authenticated encrypted own history.
use crate::own_device_sync::{SdkOwnDeviceGroupMemberPin, SdkOwnDeviceHistoryBundle};
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use std::collections::BTreeSet;

impl RamfluxClient {
    pub(super) fn own_history_device_manifests(
        &self,
        pins: &[SdkOwnDeviceGroupMemberPin],
    ) -> Result<Vec<SdkDeviceManifestResponse>, SdkError> {
        let roots = pins
            .iter()
            .filter_map(|pin| pin.principal_commitment.as_deref())
            .collect::<BTreeSet<_>>();
        let mut manifests = Vec::new();
        let mut bytes = 0;
        for root in roots {
            if let Some(manifest) =
                self.account_db()?.load_actor_state(&format!("identity/manifest-root/{root}"))?
            {
                let encoded = serde_json::to_vec(&manifest)?;
                if manifests.len() >= 512 || bytes + encoded.len() > 3 * 1024 * 1024 {
                    break;
                }
                bytes += encoded.len();
                manifests.push(manifest);
            }
        }
        Ok(manifests)
    }
    pub(super) fn check_own_history_authority_budget(
        manifests: &[SdkDeviceManifestResponse],
        contacts: &[String],
    ) -> Result<(), SdkError> {
        if manifests.len() > 512
            || contacts.len() > 512
            || serde_json::to_vec(&(manifests, contacts))?.len() > 8 * 1024 * 1024
        {
            return Err(SdkError::InboundRejected(
                "own history authority byte or count budget".into(),
            ));
        }
        Ok(())
    }
    /// Only called after the same-root envelope and encrypted history object authenticate.
    pub(super) fn restore_own_history_authority(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
    ) -> Result<(), SdkError> {
        Self::check_own_history_authority_budget(
            &bundle.device_manifests,
            &bundle.accepted_contacts,
        )?;
        let roots = bundle
            .group_member_pins
            .iter()
            .filter_map(|pin| pin.principal_commitment.as_deref())
            .collect::<BTreeSet<_>>();
        for manifest in &bundle.device_manifests {
            if !roots.contains(manifest.principal_commitment.as_str()) {
                return Err(SdkError::InboundRejected(
                    "own history manifest has no member pin context".into(),
                ));
            }
            super::contact::verify_device_manifest(manifest, &manifest.principal_commitment)?;
            if self
                .observed_device_set(&manifest.principal_commitment)?
                .zip(manifest.signed_device_set.as_ref())
                .is_some_and(|(current, old)| current.device_set_epoch > old.device_set_epoch)
            {
                continue;
            }
            self.persist_identity_directory(manifest)?;
        }
        for restrictions in [true, false] {
            for packet in &bundle.accepted_contacts {
                let bytes = ramflux_protocol::decode_base64url(packet).map_err(|_| {
                    SdkError::InboundRejected("invalid own contact history encoding".into())
                })?;
                if super::own_contact::is_tombstone_packet(&bytes) != restrictions {
                    continue;
                }
                if !self.receive_own_contact(&bytes)? {
                    return Err(SdkError::InboundRejected(
                        "unsupported own contact history".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}
