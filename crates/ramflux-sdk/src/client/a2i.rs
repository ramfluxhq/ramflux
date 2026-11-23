// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

fn authority(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::error::GeneratedRefusalCode::Authority,
        reason: reason.into(),
    }
}

fn content(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::error::GeneratedRefusalCode::Content,
        reason: reason.into(),
    }
}

fn subject_value(subject_base64: &str) -> Result<serde_json::Value, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(subject_base64)
        .map_err(|_| content("a2i subject is not base64url"))?;
    if bytes.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        return Ok(value);
    }
    match String::from_utf8(bytes) {
        Ok(text) => Ok(serde_json::Value::String(text)),
        Err(_) => Err(content("a2i subject is not json")),
    }
}

fn control_domain(name: &str) -> Result<ramflux_protocol::ControlDomain, SdkError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| content("a2i control domain unknown"))
}

fn sort_a2i(events: &mut [A2iControlEvent]) {
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
            .then_with(|| left.source_device_id.cmp(&right.source_device_id))
    });
}

impl RamfluxClient {
    /// Local checks that must finish before a gateway read or an outbound capture.
    pub(crate) fn validate_a2i_sender(
        &self,
        engine_principal: &str,
        event: &A2iControlEvent,
    ) -> Result<(), SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if engine_principal != branch.principal_id {
            return Err(authority("a2i engine principal is not this account"));
        }
        if event.source_principal_id.as_ref().is_some_and(|id| id != &branch.principal_id) {
            return Err(authority("a2i source principal is not this account"));
        }
        if event.source_device_id != branch.device_id {
            return Err(authority("a2i source device is not this device"));
        }
        if event.event_type != "a2i.control" {
            return Err(content("a2i event type must be a2i.control"));
        }
        if event.event_id.is_empty() || event.action.is_empty() {
            return Err(content("a2i event id and action are required"));
        }
        if let Some(commitment) = event.source_principal_commitment.as_deref()
            && commitment != self.own_account_anchor()?
        {
            return Err(authority("a2i source commitment is not this account"));
        }
        Ok(())
    }

    fn a2i_directory_root(&self, target_device_id: &str) -> Result<String, SdkError> {
        let entry = match self.account_db()?.device_directory_entry(target_device_id) {
            Ok(entry) => entry,
            Err(StorageError::AmbiguousDeviceId(_)) => {
                return Err(authority("a2i target device is not unique"));
            }
            Err(error) => return Err(error.into()),
        };
        entry
            .map(|record| record.principal_commitment)
            .ok_or_else(|| authority("a2i target is not a verified contact device"))
    }

    fn signed_native_a2i(
        &self,
        event: &A2iControlEvent,
    ) -> Result<ramflux_protocol::A2iControlEvent, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let mut native = ramflux_protocol::A2iControlEvent {
            schema: ramflux_protocol::domain::A2I_CONTROL.into(),
            version: 1,
            domain: ramflux_protocol::domain::A2I_CONTROL.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: branch.device_id.clone(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            event_type: serde_json::from_value(serde_json::json!("a2i.control"))
                .map_err(|_| content("a2i event type missing"))?,
            control_domain: control_domain(&event.control_domain)?,
            action: event.action.clone(),
            subject: subject_value(&event.subject_base64)?,
            correlation_id: event.event_id.clone(),
            source_device_id: branch.device_id.clone(),
            target_device_id: event.target_device_id.clone(),
            grant_id: None,
            expires_at: None,
        };
        native.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &native)?;
        Ok(native)
    }

    fn a2i_delivery_id(
        manifest: &crate::prekey::SdkDeviceManifestResponse,
        device_id: &str,
        requested: Option<&str>,
    ) -> Result<String, SdkError> {
        let device = manifest
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
            .ok_or_else(|| authority("a2i target is not a verified contact device"))?;
        if requested.is_some_and(|id| id != device.target_delivery_id) {
            return Err(content("a2i target delivery id differs from the verified manifest"));
        }
        Ok(device.target_delivery_id.clone())
    }

    fn a2i_carrier(
        &self,
        config: &GatewaySessionConfig,
        root: &str,
        target_device_id: &str,
        delivery: &str,
        created_at: i64,
    ) -> Result<GatewayDirectMessage, SdkError> {
        let own = self.own_account_anchor()?;
        let conversation_id = ramflux_protocol::message::dm_scope::derive(&own, root)
            .map_err(|_| content("a2i conversation scope"))?;
        let now = crate::time::now_unix_timestamp();
        Ok(GatewayDirectMessage {
            conversation_id,
            message_id: "a2i".into(),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: config.principal_id.clone(),
            sender_id: config.device_id.clone(),
            recipient_device_id: Some(target_device_id.to_owned()),
            recipient_principal_commitment: Some(root.to_owned()),
            target_delivery_id: delivery.to_owned(),
            encrypted_body: Vec::new(),
            created_at: if created_at > 0 { created_at } else { now },
            ttl: self.content_ttl()?,
        })
    }

    pub(crate) async fn deliver_a2i(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event: &A2iControlEvent,
        target_delivery_id: Option<String>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.validate_a2i_sender(engine.config().principal_id.as_str(), event)?;
        let root = self.a2i_directory_root(&event.target_device_id)?;
        self.require_a2i_peer(&root)?;
        let native = self.signed_native_a2i(event)?;
        let bytes = self.generated_a2i_inner(&native, &root)?;
        let manifest = self.cache_verified_device_manifest(engine.config(), &root, "a2i").await?;
        let delivery = Self::a2i_delivery_id(
            &manifest,
            &event.target_device_id,
            target_delivery_id.as_deref(),
        )?;
        let message = self.a2i_carrier(
            engine.config(),
            &root,
            &event.target_device_id,
            &delivery,
            event.created_at,
        )?;
        self.send_plaintext_direct_message_without_franking(
            engine,
            message,
            &bytes,
            crate::client::routed::Route::control(),
        )
        .await
    }

    /// # Errors
    /// Returns an error when the sender, contact, or target device is not authorized, or when
    /// the control carrier cannot be sealed.
    pub async fn send_a2i_control_event_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event: &A2iControlEvent,
        target_delivery_id: Option<String>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.deliver_a2i(engine, event, target_delivery_id).await
    }

    pub(crate) fn stored_a2i_events(
        &self,
        pending: bool,
    ) -> Result<Vec<A2iControlEvent>, SdkError> {
        let mut events = self.account_db()?.list_actor_states::<A2iControlEvent>("a2i/scoped/")?;
        if pending {
            events.retain(|event| !event.acknowledged);
        }
        sort_a2i(&mut events);
        Ok(events)
    }

    pub(crate) fn a2i_events_json(&self, pending: bool) -> Result<serde_json::Value, SdkError> {
        Ok(serde_json::json!({"events": self.stored_a2i_events(pending)?}))
    }

    pub(crate) fn acknowledge_stored_a2i(
        &self,
        event_id: &str,
    ) -> Result<A2iControlEvent, SdkError> {
        if event_id.is_empty() {
            return Err(content("a2i event id is required"));
        }
        let db = self.account_db()?;
        let mut matches = Vec::new();
        for key in db.actor_state_keys("a2i/scoped/")? {
            if let Some(row) = db.load_actor_state::<A2iControlEvent>(&key)?
                && row.event_id == event_id
            {
                matches.push((key, row));
            }
        }
        let Some((key, mut row)) = matches.pop() else {
            return Err(content("a2i event not found"));
        };
        if !matches.is_empty() {
            return Err(authority("a2i event id is not unique"));
        }
        row.acknowledged = true;
        db.write_transaction(|| db.persist_actor_state(&key, &row))?;
        Ok(row)
    }

    /// # Errors
    /// Returns an error when the account is locked or legacy receive is activated.
    /// Live ingest stays on the routed control path; this reads rows already stored.
    pub fn receive_a2i_control_events(
        &mut self,
        _engine: &mut impl GatewaySessionAccess,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<A2iControlEvent>, SdkError>> {
        let result = (|| {
            self.account_db()?.refuse_legacy_receive()?;
            let mut events = self.stored_a2i_events(true)?;
            events.truncate(limit);
            Ok(events)
        })();
        std::future::ready(result)
    }
}
