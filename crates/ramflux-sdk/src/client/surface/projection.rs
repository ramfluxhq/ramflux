// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signature/author guards, atomic state transitions and durable single-use decisions.
use super::{Carrier, Outcome, Payload, Receipt, StoredSurface, invalid, key, scoped_key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn surface_state(
        &self,
        id: &str,
    ) -> Result<Option<(StoredSurface, SurfaceState)>, SdkError> {
        let record: Option<StoredSurface> =
            self.account_db()?.load_actor_state(&key("state", id))?;
        record
            .map(|record| {
                let bytes = ramflux_protocol::decode_base64url(&record.checkpoint_base64)
                    .map_err(|_| invalid("invalid surface checkpoint encoding"))?;
                let state = SurfaceState::from_checkpoint_bytes(&bytes)
                    .map_err(|_| invalid("invalid persisted surface checkpoint"))?;
                Ok((record, state))
            })
            .transpose()
    }
    pub(crate) fn project_surface_message(
        &self,
        conversation: &str,
        message: &str,
        sender: super::SurfaceSender<'_>,
        body: &[u8],
        outbound: bool,
    ) -> Result<Option<Outcome>, SdkError> {
        let super::SurfaceSender { principal, device } = sender;
        if !body.starts_with(super::carrier::PREFIX) {
            return Ok(None);
        }
        self.account_db()?.surface_transaction(||{
            let Ok(Some(carrier)) = Carrier::decode(body) else {
                let error=json!({"code":"invalid_carrier"});self.surface_error(conversation,message,None,&error)?;
                return Ok(Some(Outcome::rejected(error)));
            };
            // Transport bindings are checked even for an already committed logical message.
            if carrier.sender_principal_id != principal || carrier.sender_device_id != device || carrier.conversation_id != conversation {
                let error=json!({"code":"transport_binding_mismatch"});
                self.surface_error(conversation,message,Some(&carrier.surface_id),&error)?;
                return Ok(Some(Outcome::rejected(error)));
            }
            let fingerprint=ramflux_protocol::hash_base64url("ramflux.surface.delivery.v1",body);
            let receipt_key=scoped_key("receipt",&[principal,&carrier.message_id])?;
            if let Some(receipt)=self.account_db()?.load_actor_state::<Receipt>(&receipt_key)?{
                if receipt.fingerprint==fingerprint{
                    self.account_db()?.persist_actor_state(&key("message",message),&json!({"surface_id":carrier.surface_id,"conversation_id":conversation,"accepted":receipt.result.accepted,"fallback_text":receipt.result.fallback_text,"kind":carrier.payload_kind}))?;
                    return Ok(Some(receipt.result));
                }
                let error=json!({"code":"message_id_conflict"});self.surface_error(conversation,message,Some(&carrier.surface_id),&error)?;
                return Ok(Some(Outcome::rejected(error)));
            }
            let checked=self.verify_surface_carrier(&carrier,principal,device);
            let outcome=match checked {
                Ok(payload) if carrier.conversation_id==conversation=>self.apply_surface_payload(&carrier,payload,outbound)?,
                Ok(_)=>Outcome::rejected(json!({"code":"conversation_mismatch"})),
                Err(_)=>Outcome::rejected(json!({"code":"invalid_signature_or_wire"})),
            };
            if let Some(error)=&outcome.renderer_error{self.surface_error(conversation,message,Some(&carrier.surface_id),error)?;}
            self.account_db()?.persist_actor_state(&receipt_key,&Receipt{fingerprint,result:outcome.clone()})?;
            self.account_db()?.persist_actor_state(&key("message",message),&json!({"surface_id":carrier.surface_id,"conversation_id":conversation,"accepted":outcome.accepted,"fallback_text":outcome.fallback_text,"kind":carrier.payload_kind}))?;
            Ok(Some(outcome))
        })
    }
    pub(crate) fn surface_delivery_receipt(
        &self,
        carrier: &Carrier,
    ) -> Result<Option<Outcome>, SdkError> {
        let receipt_key =
            scoped_key("receipt", &[&carrier.sender_principal_id, &carrier.message_id])?;
        let fingerprint =
            ramflux_protocol::hash_base64url("ramflux.surface.delivery.v1", &carrier.bytes()?);
        Ok(self.account_db()?.load_actor_state::<Receipt>(&receipt_key)?.map(|receipt| {
            if receipt.fingerprint == fingerprint {
                receipt.result
            } else {
                Outcome::rejected(json!({"code":"message_id_conflict"}))
            }
        }))
    }
    pub(crate) fn preflight_surface(&self, carrier: &Carrier) -> Result<Outcome, SdkError> {
        let payload = self.verify_surface_carrier(
            carrier,
            &carrier.sender_principal_id,
            &carrier.sender_device_id,
        )?;
        self.evaluate_surface(carrier, &payload, true)
    }
    fn evaluate_surface(
        &self,
        carrier: &Carrier,
        payload: &Payload,
        outbound: bool,
    ) -> Result<Outcome, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let reject = |code: &str| Outcome::rejected(json!({"code":code}));
        // Reject unauthorized updates, stale decisions and consumed decisions before loading
        // the private stream-finality checkpoint.
        if matches!(payload, Payload::Event(_))
            && carrier.sender_principal_id != carrier.author_principal_id
        {
            return Ok(reject("non_author_update"));
        }
        if let Payload::Action(action) = payload {
            let view = self.account_db()?.client_record("surface", &carrier.surface_id)?;
            if let Some(view) = view {
                if view["conversation_id"] != carrier.conversation_id
                    || view["author_principal_id"] != carrier.author_principal_id
                {
                    return Ok(reject("surface_author_or_conversation_mismatch"));
                }
                if view["version"] != action.version()
                    || view["surface_hash"] != action.surface_hash()
                {
                    return Ok(Outcome::rejected(
                        json!({"code":"renderer_error","reject":ramflux_protocol::SurfaceReject::Stale}),
                    ));
                }
                let used = scoped_key(
                    "decision",
                    &[
                        &carrier.surface_id,
                        &action.version().to_string(),
                        action.action_id(),
                        &carrier.sender_principal_id,
                    ],
                )?;
                if self.account_db()?.load_actor_state::<Value>(&used)?.is_some() {
                    return Ok(reject("action_already_used"));
                }
            }
        }
        let saved = self.surface_state(&carrier.surface_id)?;
        if let Some((record, _)) = &saved
            && (record.conversation_id != carrier.conversation_id
                || record.author_principal_id != carrier.author_principal_id)
        {
            return Ok(reject("surface_author_or_conversation_mismatch"));
        }
        match payload {
            Payload::Event(event) => {
                if carrier.sender_principal_id != carrier.author_principal_id {
                    return Ok(reject("non_author_update"));
                }
                let state = saved.as_ref().map_or_else(SurfaceState::default, |(_, s)| s.clone());
                match state.apply(event) {
                    Ok(next) => Ok(Outcome {
                        accepted: true,
                        fallback_text: next
                            .content()
                            .ok_or_else(|| invalid("surface content absent"))?
                            .fallback_text
                            .clone(),
                        renderer_error: None,
                    }),
                    Err(error) => {
                        Ok(Outcome::rejected(json!({"code":"renderer_error","reject":error})))
                    }
                }
            }
            Payload::Action(action) => {
                let Some((record, state)) = saved else {
                    return Ok(reject("unknown_surface"));
                };
                if !outbound && local.principal_id != record.author_principal_id {
                    return Ok(reject("action_not_for_author"));
                }
                if let Err(error) = state.validate_action(action) {
                    return Ok(Outcome::rejected(json!({"code":"renderer_error","reject":error})));
                }
                let used = scoped_key(
                    "decision",
                    &[
                        &carrier.surface_id,
                        &action.version().to_string(),
                        action.action_id(),
                        &carrier.sender_principal_id,
                    ],
                )?;
                if self.account_db()?.load_actor_state::<Value>(&used)?.is_some() {
                    return Ok(reject("action_already_used"));
                }
                Ok(Outcome {
                    accepted: true,
                    fallback_text: state
                        .content()
                        .ok_or_else(|| invalid("surface content absent"))?
                        .fallback_text
                        .clone(),
                    renderer_error: None,
                })
            }
        }
    }
    fn apply_surface_payload(
        &self,
        carrier: &Carrier,
        payload: Payload,
        outbound: bool,
    ) -> Result<Outcome, SdkError> {
        let outcome = self.evaluate_surface(carrier, &payload, outbound)?;
        if !outcome.accepted {
            return Ok(outcome);
        }
        let db = self.account_db()?;
        match payload {
            Payload::Event(event) => {
                let previous = self.surface_state(&carrier.surface_id)?;
                let state = previous
                    .as_ref()
                    .map_or_else(SurfaceState::default, |(_, s)| s.clone())
                    .apply(&event)
                    .map_err(|_| invalid("surface changed during writer transaction"))?;
                let author_device = previous.map_or_else(
                    || carrier.sender_device_id.clone(),
                    |(record, _)| record.author_device_id,
                );
                let record = StoredSurface {
                    surface_id: carrier.surface_id.clone(),
                    conversation_id: carrier.conversation_id.clone(),
                    author_principal_id: carrier.author_principal_id.clone(),
                    author_device_id: author_device.clone(),
                    checkpoint_base64: ramflux_protocol::encode_base64url(
                        state
                            .checkpoint_bytes()
                            .map_err(|_| invalid("surface checkpoint failed"))?,
                    ),
                };
                db.persist_actor_state(&key("state", &carrier.surface_id), &record)?;
                let history =
                    format!("{}{:020}", key("history", &carrier.surface_id) + "/", state.version());
                db.persist_actor_state(&history,&json!({"version":state.version(),"surface_hash":state.hash(),"wire_base64":carrier.wire_base64,"carrier_base64":ramflux_protocol::encode_base64url(carrier.bytes()?),"message_id":carrier.message_id}))?;
                db.persist_client_record("surface",&carrier.surface_id,&json!({"id":carrier.surface_id,"surface_id":carrier.surface_id,"conversation_id":carrier.conversation_id,"author_principal_id":carrier.author_principal_id,"author_device_id":author_device,"version":state.version(),"surface_hash":state.hash(),"closed":state.is_closed(),"fallback_text":outcome.fallback_text,"renderer_error":null}))?;
            }
            Payload::Action(action) => {
                let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                if !outbound || local.principal_id == carrier.author_principal_id {
                    let used = scoped_key(
                        "decision",
                        &[
                            &carrier.surface_id,
                            &action.version().to_string(),
                            action.action_id(),
                            &carrier.sender_principal_id,
                        ],
                    )?;
                    db.persist_actor_state(&used, &json!({"message_id":carrier.message_id}))?;
                    let action_id = ramflux_protocol::hash_base64url(
                        "ramflux.surface.action_delivery.v1",
                        &ramflux_protocol::canonical_json_bytes(&(
                            &carrier.sender_principal_id,
                            &carrier.message_id,
                        ))?,
                    );
                    let action_key = format!("{}/{action_id}", key("actions", &carrier.surface_id));
                    db.persist_actor_state(&action_key,&json!({"id":action_id,"message_id":carrier.message_id,"sender_principal_id":carrier.sender_principal_id,"wire_base64":carrier.wire_base64,"carrier_base64":ramflux_protocol::encode_base64url(carrier.bytes()?),"version":action.version()}))?;
                    if let Some(mut view) = db.client_record("surface", &carrier.surface_id)? {
                        view["last_action_id"] = json!(action_id);
                        view["last_action_message_id"] = json!(carrier.message_id);
                        view["renderer_error"] = Value::Null;
                        db.persist_client_record("surface", &carrier.surface_id, &view)?;
                    }
                }
            }
        }
        Ok(outcome)
    }
    pub(crate) fn surface_error(
        &self,
        conversation: &str,
        message: &str,
        surface: Option<&str>,
        error: &Value,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let error_id = ramflux_protocol::hash_base64url(
            "ramflux.surface.error.v1",
            &ramflux_protocol::canonical_json_bytes(&(conversation, message, surface))?,
        );
        db.persist_client_record("surface_error",&error_id,&json!({"conversation_id":conversation,"message_id":message,"surface_id":surface,"renderer_error":error}))?;
        if let Some(id) = surface {
            let mut view=db.client_record("surface",id)?.unwrap_or_else(||json!({"id":id,"surface_id":id,"conversation_id":conversation,"version":0,"surface_hash":null,"closed":false}));
            if view["conversation_id"] == conversation {
                view["renderer_error"] = error.clone();
                db.persist_client_record("surface", id, &view)?;
            }
        }
        Ok(())
    }
}
