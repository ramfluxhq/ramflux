// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single first-contact resolution boundary for TOFU lookup and root-pinned cards.
use crate::ContactReason;
use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn lookup_failure(error: SdkError) -> SdkError {
    match error {
        SdkError::Transport(_)
        | SdkError::GatewaySessionRejected(_)
        | SdkError::Io(_)
        | SdkError::Json(_) => SdkError::ContactUnavailable(Box::new(error)),
        other => other,
    }
}

impl RamfluxClient {
    pub(crate) async fn resolve_contact(
        &self,
        gateway: &GatewaySessionConfig,
        own_gateway: &GatewaySessionConfig,
        input: ContactResolution<'_>,
    ) -> Result<Value, SdkError> {
        let ContactResolution { selector, expected_root, card, link_id, allow_commitment } = input;
        if !crate::contact_card::valid_principal(selector) {
            return Err(ContactReason::UnknownPrincipal.into());
        }
        let root_hint = expected_root.or_else(|| {
            (allow_commitment
                && ramflux_protocol::decode_base64url(selector)
                    .is_ok_and(|bytes| bytes.len() == 32))
            .then_some(selector)
        });
        let path = root_hint.map_or_else(
            || format!("/mvp1/principal-manifest/{selector}"),
            |root| format!("/mvp1/device-manifest/{root}"),
        );
        let manifest: Option<SdkDeviceManifestResponse> =
            sdk_gateway_get_json(gateway, &path).await.map_err(lookup_failure)?;
        let manifest = manifest.ok_or(ContactReason::UnknownPrincipal)?;
        let principal = &manifest.principal_id;
        if principal != selector && !(allow_commitment && manifest.principal_commitment == selector)
        {
            return Err(ContactReason::UnknownPrincipal.into());
        }
        if principal == &own_gateway.principal_id {
            return Err(ContactReason::SelfContact.into());
        }
        let pinned = self.account_db()?.client_record("identity", principal)?;
        let expected = root_hint
            .or_else(|| pinned.as_ref().and_then(|r| r["contact_identity_commitment"].as_str()))
            .unwrap_or(&manifest.principal_commitment);
        // Keep first-contact verification at one boundary; lookup is TOFU only without a pin.
        super::contact::verify_device_manifest(&manifest, expected)?;
        let own_root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let own_commitment = identity_root_public_key_commitment(
            &ramflux_protocol::encode_base64url(own_root.signing_key.verifying_key().to_bytes()),
        )?;
        let own_manifest =
            super::contact::fetch_verified_device_manifest(own_gateway, &own_commitment)
                .await
                .map_err(lookup_failure)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            self.persist_identity_directory(&own_manifest)?;
            self.persist_identity_directory(&manifest)?;
            for device in &manifest.devices {
                db.upsert_device_directory_entry(
                    &device.device_id,
                    &manifest.principal_commitment,
                    if card.is_some() { "contact_card" } else { "contact_lookup" },
                    now_unix_timestamp(),
                )?;
            }
            let mut identity =
                db.client_record("identity", principal)?.ok_or(ContactReason::UnknownPrincipal)?;
            if let Some(card) = card {
                identity["display_name"] = json!(card.display_name);
                identity["kind_asserted"] = json!(card.kind_asserted);
                identity["node"] = json!(card.node);
            }
            db.persist_client_record("identity", principal, &identity)?;
            self.establish_friend_link(&link_id, &own_commitment, &manifest.principal_commitment)?;
            let own_material =
                super::contact::contact_safety_material_from_manifest(&own_manifest)?;
            let contact_material =
                super::contact::contact_safety_material_from_manifest(&manifest)?;
            identity["safety_number"] =
                json!(ramflux_crypto::safety_number(&own_material, &contact_material));
            db.persist_client_record("identity", principal, &identity)?;
            self.contact_entry(principal)
        })
    }

    pub(crate) fn contact_entry(&self, principal: &str) -> Result<Value, SdkError> {
        let db = self.account_db()?;
        let identity = db.client_record("identity", principal)?.unwrap_or_else(|| json!({}));
        let commitment = identity["contact_identity_commitment"].as_str();
        let verification = commitment.map(|c| db.contact_verification(c)).transpose()?.flatten();
        let verified = verification.is_some_and(|v| {
            v.verification_state == "verified"
                && identity["device_set_hash"].as_str() == Some(v.verified_device_set_hash.as_str())
        });
        let linked = self.friend_link_peer_is_accepted(principal)?
            || commitment
                .map(|root| self.friend_link_peer_is_accepted(root))
                .transpose()?
                .unwrap_or(false);
        let reachable = linked
            && identity["devices"].as_array().is_some_and(|devices| {
                devices.iter().any(|d| {
                    d["device_id"].as_str().is_some() && d["target_delivery_id"].as_str().is_some()
                })
            })
            && commitment.is_some();
        Ok(
            json!({"principal_id":principal,"display_name":identity["display_name"],"reachable":reachable,"verified":verified,"kind_asserted":identity["kind_asserted"],"root_commitment":commitment,"node":identity["node"]}),
        )
    }
}

pub(crate) struct ContactResolution<'a> {
    pub selector: &'a str,
    pub expected_root: Option<&'a str>,
    pub card: Option<&'a crate::ContactCardBody>,
    pub link_id: String,
    pub allow_commitment: bool,
}
