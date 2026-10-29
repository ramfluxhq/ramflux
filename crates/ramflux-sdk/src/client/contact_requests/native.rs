// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Certified consent v2 validation and preparation before the receive transaction.
use super::{Control, Decision, conversation, invalid, wire};
use crate::{
    GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, SdkError,
    client::routed::{Kind, Routing},
    prekey::SdkDeviceManifestResponse,
};
use ramflux_protocol::custody::{
    ContactConsentV2, ContactDecision, CustodyAuthority, CustodyManifest, DeviceRef, Envelope,
    Publication, object_hash,
};

pub(super) fn decode(bytes: &[u8]) -> Result<Option<Envelope<ContactConsentV2>>, SdkError> {
    #[derive(serde::Deserialize)]
    struct Header {
        body: Schema,
    }
    #[derive(serde::Deserialize)]
    struct Schema {
        schema: String,
    }
    if !serde_json::from_slice::<Header>(bytes)
        .is_ok_and(|header| header.body.schema == ramflux_protocol::domain::CONTACT_REQUEST_V2)
    {
        return Ok(None);
    }
    Ok(Some(ramflux_protocol::custody::decode(bytes, 8192)?))
}

struct Carrier<'a> {
    client: &'a RamfluxClient,
    entry: &'a GatewayInboxEntry,
    route: &'a Routing,
    consent: &'a Envelope<ContactConsentV2>,
}
impl Carrier<'_> {
    fn verify_transport(
        &self,
        current: &ramflux_crypto::custody::VerifiedRecord,
        now: u64,
    ) -> Result<DeviceRef, SdkError> {
        let body = &self.consent.body;
        let source = DeviceRef {
            account_anchor: body.actor_root.clone(),
            device_id: self.entry.envelope.source_device_id.clone(),
            device_epoch: current
                .envelope()
                .body
                .devices
                .iter()
                .find(|device| device.device_id == self.entry.envelope.source_device_id)
                .ok_or_else(|| invalid("native consent sender is absent"))?
                .device_epoch,
        };
        let certificate = current.authorize(&source, "message", now)?;
        crate::client::routed::verify_sender_record(
            self.entry,
            &serde_json::json!({
                "principal_id":current.envelope().body.principal_id,
                "signing_public_key":certificate.branch_signing_public_key,
            }),
        )?;
        let target = if body.kind == ContactDecision::Request {
            &body.target_root
        } else {
            &body.requester_root
        };
        if body.expires_at <= now
            || body.issued_at > now.saturating_add(ramflux_protocol::custody::CLOCK_SKEW_SECONDS)
            || body.sending_device_ref != source
            || target != self.client.owned_device_identity()?.root_commitment()
            || current.envelope().body.account_anchor != body.actor_root
            || self.route.kind != Kind::Control
            || self.route.group_id.is_some()
            || self.route.attachments
            || self.route.conversation_id != conversation(&body.requester_root, &body.target_root)?
        {
            return Err(invalid("native consent endpoint, lifetime or route mismatch"));
        }
        Ok(source)
    }
}
fn current_authority(
    manifest: &SdkDeviceManifestResponse,
    now: u64,
) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
    let native =
        manifest.custody.as_deref().ok_or_else(|| invalid("native consent authority absent"))?;
    Ok(ramflux_crypto::custody::verify_publication(
        &CustodyAuthority {
            publication: native.publication.clone(),
            custodian_publication: native.custodian_publication.clone(),
        },
        now,
    )?)
}
fn validate(
    carrier: &Carrier<'_>,
    manifest: &SdkDeviceManifestResponse,
    historical: &Publication,
    now: u64,
) -> Result<(), SdkError> {
    let native =
        manifest.custody.as_deref().ok_or_else(|| invalid("native consent authority absent"))?;
    let current = current_authority(manifest, now)?;
    let source = carrier.verify_transport(&current, now)?;
    let old = ramflux_crypto::custody::verify_publication(
        &CustodyAuthority {
            publication: historical.clone(),
            custodian_publication: native.custodian_publication.clone(),
        },
        now,
    )?;
    ramflux_crypto::custody::verify_contact_consent(carrier.consent, &old, &current, &source, now)?;
    Ok(())
}

impl RamfluxClient {
    /// Resolve delayed evidence outside the receive transaction, then recheck it at commit.
    pub(crate) async fn prepare_native_contact_control(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        route: &Routing,
        bytes: &[u8],
        candidate: Option<&SdkDeviceManifestResponse>,
    ) -> Result<(), SdkError> {
        let Some(consent) = decode(bytes)? else {
            return Ok(());
        };
        ramflux_protocol::custody::validate_contact_consent(&consent.body)?;
        let now = crate::custody::network_now()?;
        let fetched;
        let manifest = if let Some(candidate) = candidate {
            candidate
        } else {
            fetched = crate::client::contact::fetch_verified_device_manifest(
                gateway,
                &consent.body.actor_root,
            )
            .await?;
            &fetched
        };
        let native = manifest
            .custody
            .as_deref()
            .ok_or_else(|| invalid("native consent authority absent"))?;
        // Authenticate the primary signature before a sender can cause a historical lookup.
        if manifest.principal_commitment != consent.body.actor_root
            || manifest.principal_id != entry.envelope.source_principal_id
        {
            return Err(invalid("native consent transport root mismatch"));
        }
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::custody::signing_bytes(
                ramflux_protocol::domain::CONTACT_REQUEST_V2,
                &consent.body,
            )?,
            &consent.signature,
            &native.publication.record.body.master_certificate.body.self_signing_public_key,
        )?;
        let carrier = Carrier { client: self, entry, route, consent: &consent };
        carrier.verify_transport(&current_authority(manifest, now)?, now)?;
        let historical =
            if object_hash(&native.publication.record)? == consent.body.actor_record_hash {
                native.publication.clone()
            } else if let Some(publication) = self.cached_contact_consent_authority(
                &consent.body.actor_root,
                &consent.body.actor_record_hash,
                now,
            )? {
                publication
            } else {
                let db = self.account_db()?;
                let at = i64::try_from(now).map_err(|_| invalid("invalid consent clock"))?;
                if !db.charge_contact_request(
                    &format!("consent-history:{}", consent.body.actor_root),
                    32,
                    3600,
                    at,
                )? || !db.charge_contact_request("consent-history-global", 256, 3600, at)?
                {
                    return Err(SdkError::ContactRequestCapacity(
                        "native consent history lookup budget exhausted".into(),
                    ));
                }
                crate::prekey::sdk_gateway_get_json::<Option<Publication>>(
                    gateway,
                    &format!(
                        "{}{}/{}",
                        ramflux_protocol::custody::CUSTODY_HISTORY_PATH_PREFIX,
                        consent.body.actor_root,
                        consent.body.actor_record_hash
                    ),
                )
                .await?
                .ok_or_else(|| {
                    SdkError::ContactUnavailable(Box::new(SdkError::InboundPending(
                        "signed consent authority is unavailable".into(),
                    )))
                })?
            };
        validate(&carrier, manifest, &historical, now)?;
        let first_seen =
            self.account_db()?.client_record("identity", &manifest.principal_id)?.is_none();
        self.remember_contact_request_cache(manifest)?;
        self.persist_fetched_identity_directory(manifest)?;
        if first_seen {
            // Verified network consent is lookup provenance, not an imported card pin.
            self.mark_lookup_root(&manifest.principal_id)?;
        }
        self.cache_contact_consent_authority(&historical, consent.body.expires_at, now)?;
        Ok(())
    }

    pub(super) fn verify_native_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
        consent: Envelope<ContactConsentV2>,
    ) -> Result<Control, SdkError> {
        let now = crate::custody::network_now()?;
        let body = &consent.body;
        let evidence = self
            .current_custody_evidence(&body.actor_root, now)?
            .ok_or_else(|| invalid("current native consent authority absent"))?;
        let historical = if object_hash(&evidence.publication.record)? == body.actor_record_hash {
            evidence.publication.clone()
        } else {
            self.cached_contact_consent_authority(&body.actor_root, &body.actor_record_hash, now)?
                .ok_or_else(|| {
                SdkError::ContactUnavailable(Box::new(SdkError::InboundPending(
                    "signed consent authority must be resolved before commit".into(),
                )))
            })?
        };
        let manifest = SdkDeviceManifestResponse::from_native(CustodyManifest {
            publication: evidence.publication,
            custodian_publication: evidence.custodian_publication,
            devices: Vec::new(),
        })?;
        validate(
            &Carrier { client: self, entry, route, consent: &consent },
            &manifest,
            &historical,
            now,
        )?;
        Ok(Control {
            signature: consent.signature,
            body: wire::Body {
                schema: body.schema.clone(),
                kind: match body.kind {
                    ContactDecision::Request => Decision::Request,
                    ContactDecision::Accept => Decision::Accept,
                    ContactDecision::Decline => Decision::Decline,
                },
                request_id: body.request_id.clone(),
                requester_root: body.requester_root.clone(),
                target_root: body.target_root.clone(),
                actor_root: body.actor_root.clone(),
                issued_at: i64::try_from(body.issued_at)
                    .map_err(|_| invalid("invalid consent time"))?,
                expires_at: i64::try_from(body.expires_at)
                    .map_err(|_| invalid("invalid consent expiry"))?,
                nonce: body.nonce.clone(),
                note: body.note.clone(),
                manifest,
            },
        })
    }
}
