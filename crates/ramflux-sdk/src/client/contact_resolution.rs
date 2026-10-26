// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single first-contact resolution boundary for TOFU lookup and root-pinned cards.
use crate::ContactReason;
use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn lookup_failure(error: SdkError) -> SdkError {
    match error {
        SdkError::Transport(_) | SdkError::GatewaySessionRejected(_) | SdkError::Io(_) => {
            SdkError::ContactUnavailable(Box::new(error))
        }
        SdkError::Json(_) => ContactReason::ManifestInvalid.into(),
        other => other,
    }
}

fn resolution_root<'a>(
    selector: &'a str,
    expected: Option<&'a str>,
    cached: Option<&'a Value>,
    allow_commitment: bool,
) -> Option<&'a str> {
    expected.or_else(|| cached.and_then(|row| row["contact_identity_commitment"].as_str())).or_else(
        || {
            (allow_commitment
                && ramflux_protocol::decode_base64url(selector)
                    .is_ok_and(|bytes| bytes.len() == 32))
            .then_some(selector)
        },
    )
}
fn manifest_failure(error: SdkError) -> SdkError {
    match error {
        SdkError::Transport(_)
        | SdkError::GatewaySessionRejected(_)
        | SdkError::Io(_)
        | SdkError::Json(_) => lookup_failure(error),
        _ => ContactReason::ManifestInvalid.into(),
    }
}
impl RamfluxClient {
    pub(crate) async fn resolve_contact(
        &self,
        gateway: &GatewaySessionConfig,
        own_gateway: &GatewaySessionConfig,
        input: ContactResolution<'_>,
        engine: &mut GatewaySessionEngine,
    ) -> Result<Value, SdkError> {
        let ContactResolution {
            selector,
            expected_root,
            card,
            link_id,
            allow_commitment,
            requester_is_peer,
            replace_provisional_root,
            verification,
            send_request,
            request_note,
        } = input;
        if !crate::contact_card::valid_principal(selector) {
            return Err(ContactReason::UnknownPrincipal.into());
        }
        let cached = self.account_db()?.client_record("identity", selector)?;
        let root_hint = resolution_root(selector, expected_root, cached.as_ref(), allow_commitment);
        let manifest: Option<SdkDeviceManifestResponse> = if let Some(root) = root_hint {
            sdk_gateway_get_json(gateway, &format!("/mvp1/device-manifest/{root}"))
                .await
                .map_err(lookup_failure)?
        } else {
            engine.fetch_principal_manifest(selector).await.map_err(lookup_failure)?
        };
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
        super::contact::verify_device_manifest(&manifest, expected)
            .map_err(|_| SdkError::ContactInput(ContactReason::ManifestInvalid))?;
        let old = pinned.clone().unwrap_or_else(|| json!({}));
        let own_commitment = self.contact_own_commitment()?;
        let own_manifest =
            super::contact::fetch_verified_device_manifest(own_gateway, &own_commitment)
                .await
                .map_err(manifest_failure)?;
        let db = self.account_db()?;
        // These safety observations must survive a later ownership/data transaction rejection.
        db.write_transaction(|| self.record_pinned_group_key_changes(&own_manifest))?;
        db.write_transaction(|| self.record_pinned_group_key_changes(&manifest))?;
        let replacement = self.contact_replacement(
            &old,
            principal,
            &manifest.principal_commitment,
            replace_provisional_root,
        )?;
        let contact = db.write_transaction(|| {
            if let Some(change) = &replacement {
                self.clear_provisional_contact(&old, change, &own_commitment)?;
            }
            self.persist_root_verified_directory(&own_manifest)?;
            self.persist_root_verified_directory(&manifest)?;
            self.record_contact_device_origin(&manifest, card.is_some())?;
            let mut identity =
                db.client_record("identity", principal)?.ok_or(ContactReason::UnknownPrincipal)?;
            self.decorate_contact_identity(&old, &mut identity, card, replacement.is_some())?;
            db.persist_client_record("identity", principal, &identity)?;
            let (requester, target) = if requester_is_peer {
                (&manifest.principal_commitment, &own_commitment)
            } else {
                (&own_commitment, &manifest.principal_commitment)
            };
            self.establish_friend_link(&link_id, requester, target)?;
            let own_material =
                super::contact::contact_safety_material_from_manifest(&own_manifest)?;
            let contact_material =
                super::contact::contact_safety_material_from_manifest(&manifest)?;
            identity["safety_number"] =
                json!(ramflux_crypto::safety_number(&own_material, &contact_material));
            if let Some(safety) = verification {
                self.commit_contact_safety(
                    safety,
                    &own_material,
                    &contact_material,
                    &own_gateway.device_id,
                )?;
                identity["root_source"] = json!(crate::ContactRootSource::Verified);
            }

            db.persist_client_record("identity", principal, &identity)?;
            self.stage_own_contact(&manifest, &link_id)?;
            if send_request {
                self.resolve_contact_consent(&manifest, &link_id, request_note)?;
            }
            self.contact_entry(principal)
        })?;
        self.finish_pair_retirement()?;
        Ok(contact)
    }

    fn record_contact_device_origin(
        &self,
        manifest: &SdkDeviceManifestResponse,
        card: bool,
    ) -> Result<(), SdkError> {
        for device in &manifest.devices {
            self.account_db()?.upsert_device_directory_entry(
                &device.device_id,
                &manifest.principal_commitment,
                if card { "contact_card" } else { "contact_lookup" },
                now_unix_timestamp(),
            )?;
        }
        Ok(())
    }

    fn resolve_contact_consent(
        &self,
        manifest: &SdkDeviceManifestResponse,
        link_id: &str,
        note: Option<&str>,
    ) -> Result<(), SdkError> {
        if let Some(pending) =
            self.account_db()?.contact_request(&manifest.principal_commitment, "inbound")?
            && pending.state == "pending"
        {
            self.decide_inbound_contact(&pending, "accepted")
        } else {
            self.stage_contact_request(manifest, link_id, note)
        }
    }

    pub(crate) fn contact_entry(&self, principal: &str) -> Result<Value, SdkError> {
        self.with_profile_read_scope(|| self.contact_entry_inner(principal))
    }
    fn contact_entry_inner(&self, principal: &str) -> Result<Value, SdkError> {
        let db = self.account_db()?;
        let identity = db.client_record("identity", principal)?.unwrap_or_else(|| json!({}));
        let commitment = identity["contact_identity_commitment"].as_str();
        let verified = if let Some(commitment) = commitment {
            self.contact_safety_verification_state(
                commitment,
                identity["device_set_hash"].as_str(),
            )? == "verified"
        } else {
            false
        };
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
        let outgoing_request =
            commitment.map(|root| db.contact_request(root, "outbound")).transpose()?.flatten();
        let retained_status = commitment
            .map(|root| db.client_record("contact_request_status", root))
            .transpose()?
            .flatten();
        let request_state = outgoing_request
            .as_ref()
            .map(|request| request.state.as_str())
            .or_else(|| retained_status.as_ref().and_then(|row| row["state"].as_str()));
        let request_id = outgoing_request.as_ref().map(|request| &request.request_id);
        let profile = self.read_profile_facts(principal).map(|facts| facts.profile.clone());
        let display_name = profile
            .as_ref()
            .map_or_else(|| identity["display_name"].clone(), |p| json!(p.display_name));
        let asserted = profile.as_ref().map_or_else(
            || identity["kind_asserted"].as_str().map_or(Value::Null, |kind| json!(kind)),
            |p| json!(p.kind),
        );
        let warnings = self.identity_name_warnings(principal, display_name.as_str())?;
        Ok(
            json!({"principal_id":principal,"kind_verified":profile.is_some(),"display_name_confusable_with":warnings["display_name_confusable_with"],"mixed_script":warnings["mixed_script"],"display_name":display_name,"reachable":reachable,"verified":verified,"kind_asserted":asserted,"root_commitment":commitment,"root_source":self.contact_root_source(&identity)?,"node":identity["node"],"request_state":request_state,"request_id":request_id}),
        )
    }
}

pub(crate) struct ContactResolution<'a> {
    pub send_request: bool,
    pub request_note: Option<&'a str>,
    pub selector: &'a str,
    pub expected_root: Option<&'a str>,
    pub card: Option<&'a crate::ContactCardBody>,
    pub link_id: String,
    pub allow_commitment: bool,
    pub requester_is_peer: bool,
    pub replace_provisional_root: Option<&'a str>,
    pub verification: Option<&'a SdkContactSafetyNumber>,
}
