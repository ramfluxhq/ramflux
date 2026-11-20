// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation and rebind authorization objects: the public plan, the primary phone's signed
//! decision, the cancel message and the publication receipt. Every object is closed: unknown or
//! duplicate fields, unknown closed tokens and non-canonical bytes are refused.

use super::{
    DeviceRef, Envelope, MAX_BRANCH_LEASE_SECONDS, MAX_RANGE, MAX_RECORD_BYTES, decode,
    framed_hash, invalid, signing_bytes,
};
use crate::{
    MAX_SAFE_JSON_INTEGER, ProtocolError, canonical_json_bytes, decode_base64url, encode_base64url,
    text_safety,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::is_nfc;

/// Schema and plan-hash tag of [`RegisterPlan`].
pub const REGISTER_PLAN_SCHEMA: &str = "ramflux.agent.register_plan.v1";
/// Schema and signature tag of [`RegisterDecisionBody`].
pub const REGISTER_AUTHORIZATION_SCHEMA: &str = "ramflux.agent.register_authorization.v1";
/// Wire version of every object in this module.
pub const AGENT_REGISTER_VERSION: u32 = 1;
/// Upper bound on a plan's or decision's validity window (the 300 second ceremony lifetime).
pub const REGISTER_TTL_SECONDS: u64 = 300;
/// Native branch capabilities at genesis; agent creation never widens them.
pub const GENESIS_BRANCH_CAPABILITIES: [&str; 5] = ["call", "group", "message", "register", "sync"];
/// Upper bound on the display name, matching the `AgentProfile` responsibility bound.
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;
/// Upper bound on request identifiers and certificate identifiers.
const MAX_ID_BYTES: usize = 128;

/// Creation of a new agent anchor or a rebind after a primary transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegisterPurpose {
    /// First birth of the agent anchor; prior fields are null and the range is the genesis range.
    Create,
    /// Rebind of an existing anchor to a new custodian primary; prior fields are required.
    Rebind,
}

/// Closed profile section of the plan; the remaining `AgentProfile` fields derive natively.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegisterProfile {
    pub responsibility: String,
    pub provider: String,
    pub model: String,
    pub persona_version: u64,
    pub persona_hash: String,
    pub profile_epoch: u64,
}

/// Public plan the desktop sends to the current primary phone. It carries no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterPlan {
    pub schema: String,
    pub version: u32,
    pub request_id: String,
    pub purpose: RegisterPurpose,
    pub owner_anchor: String,
    pub human_head_hash: String,
    pub human_primary: DeviceRef,
    pub desktop: DeviceRef,
    pub agent_anchor: String,
    pub principal_id: String,
    pub agent_device: DeviceRef,
    pub master_public_key: String,
    pub self_signing_public_key: String,
    pub branch_signing_public_key: String,
    pub agreement_public_key: String,
    pub capabilities: Vec<String>,
    pub display_name: String,
    pub certificate_issued_at: u64,
    pub branch_not_before: u64,
    pub branch_expires_at: u64,
    pub master_cert_id: String,
    pub branch_cert_id: String,
    pub profile: AgentRegisterProfile,
    pub issued_at: u64,
    pub expires_at: u64,
    pub previous_agent_head_hash: Option<String>,
    pub previous_master_certificate_hash: Option<String>,
    pub next_range: u64,
}

/// Closed decision outcome; any other token refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegisterOutcome {
    Approve,
    Deny,
}

/// Signed body of a decision. The signer is the exact current human primary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDecisionBody {
    pub schema: String,
    pub version: u32,
    pub request_id: String,
    pub request_hash: String,
    pub decision: RegisterOutcome,
    pub signer: DeviceRef,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Detached primary-branch signature over [`decision_signing_bytes`].
pub type RegisterDecision = Envelope<RegisterDecisionBody>;

/// Closed cancel message from the initiating desktop; it closes pending intent only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterCancel {
    pub request_id: String,
    pub request_hash: String,
}

/// Saved result of a guarded publication, compared field by field before activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPublishReceipt {
    pub request_id: String,
    pub request_hash: String,
    pub record_hash: String,
    pub profile_hash: String,
    pub custodian_head_hash: String,
    pub custodian_primary: DeviceRef,
    pub accepted_at: u64,
}

/// Hash of a plan: framed by its schema tag over the canonical plan bytes.
/// # Errors
/// Refuses invalid plans and canonical serialization failures.
pub fn register_plan_hash(plan: &RegisterPlan) -> Result<String, ProtocolError> {
    validate_register_plan(plan)?;
    framed_hash(REGISTER_PLAN_SCHEMA, plan)
}

/// Transcript signed by the primary branch key for a decision.
/// # Errors
/// Refuses invalid decision bodies and canonical serialization failures.
pub fn decision_signing_bytes(body: &RegisterDecisionBody) -> Result<Vec<u8>, ProtocolError> {
    validate_register_decision_body(body)?;
    signing_bytes(REGISTER_AUTHORIZATION_SCHEMA, body)
}

/// Encode a validated plan as its canonical bytes.
/// # Errors
/// Refuses invalid plans and oversized output.
pub fn encode_register_plan(plan: &RegisterPlan) -> Result<Vec<u8>, ProtocolError> {
    encode_checked(plan, validate_register_plan)
}

/// Decode a plan, refusing any non-canonical or invalid bytes.
/// # Errors
/// Refuses oversized, malformed, unknown-field, non-canonical and invalid input.
pub fn decode_register_plan(bytes: &[u8]) -> Result<RegisterPlan, ProtocolError> {
    decode_checked(bytes, validate_register_plan)
}

/// Encode a validated decision envelope as its canonical bytes.
/// # Errors
/// Refuses invalid decisions and oversized output.
pub fn encode_register_decision(decision: &RegisterDecision) -> Result<Vec<u8>, ProtocolError> {
    encode_checked(decision, |value| {
        validate_register_decision_body(&value.body)?;
        binary(&value.signature, 64, "signature")
    })
}

/// Decode a decision envelope, refusing any non-canonical or invalid bytes.
/// # Errors
/// Refuses oversized, malformed, unknown-field, non-canonical and invalid input.
pub fn decode_register_decision(bytes: &[u8]) -> Result<RegisterDecision, ProtocolError> {
    decode_checked(bytes, |value: &RegisterDecision| {
        validate_register_decision_body(&value.body)?;
        binary(&value.signature, 64, "signature")
    })
}

/// Encode a validated cancel message.
/// # Errors
/// Refuses invalid cancels and oversized output.
pub fn encode_register_cancel(cancel: &RegisterCancel) -> Result<Vec<u8>, ProtocolError> {
    encode_checked(cancel, validate_register_cancel)
}

/// Decode a cancel message, refusing non-canonical or invalid bytes.
/// # Errors
/// Refuses oversized, malformed, unknown-field, non-canonical and invalid input.
pub fn decode_register_cancel(bytes: &[u8]) -> Result<RegisterCancel, ProtocolError> {
    decode_checked(bytes, validate_register_cancel)
}

/// Encode a validated publication receipt.
/// # Errors
/// Refuses invalid receipts and oversized output.
pub fn encode_agent_publish_receipt(
    receipt: &AgentPublishReceipt,
) -> Result<Vec<u8>, ProtocolError> {
    encode_checked(receipt, validate_agent_publish_receipt)
}

/// Decode a publication receipt, refusing non-canonical or invalid bytes.
/// # Errors
/// Refuses oversized, malformed, unknown-field, non-canonical and invalid input.
pub fn decode_agent_publish_receipt(bytes: &[u8]) -> Result<AgentPublishReceipt, ProtocolError> {
    decode_checked(bytes, validate_agent_publish_receipt)
}

/// Validate every field of a plan without any signature or native-state check.
/// # Errors
/// Refuses the first field that violates its closed constraint.
pub fn validate_register_plan(plan: &RegisterPlan) -> Result<(), ProtocolError> {
    if plan.schema != REGISTER_PLAN_SCHEMA || plan.version != AGENT_REGISTER_VERSION {
        return Err(invalid("register plan schema or version"));
    }
    id(&plan.request_id, "request_id")?;
    binary(&plan.owner_anchor, 32, "owner_anchor")?;
    binary(&plan.agent_anchor, 32, "agent_anchor")?;
    binary(&plan.human_head_hash, 32, "human_head_hash")?;
    device(&plan.human_primary, "human_primary")?;
    device(&plan.desktop, "desktop")?;
    device(&plan.agent_device, "agent_device")?;
    if plan.human_primary.account_anchor != plan.owner_anchor
        || plan.desktop.account_anchor != plan.owner_anchor
        || plan.agent_device.account_anchor != plan.agent_anchor
    {
        return Err(invalid("register plan device anchors"));
    }
    if plan.desktop.device_id == plan.human_primary.device_id
        && plan.desktop.device_epoch == plan.human_primary.device_epoch
    {
        return Err(invalid("register plan desktop is the primary"));
    }
    id(&plan.principal_id, "principal_id")?;
    for (value, field) in [
        (&plan.master_public_key, "master_public_key"),
        (&plan.self_signing_public_key, "self_signing_public_key"),
        (&plan.branch_signing_public_key, "branch_signing_public_key"),
        (&plan.agreement_public_key, "agreement_public_key"),
    ] {
        binary(value, 32, field)?;
    }
    if plan.capabilities.len() != GENESIS_BRANCH_CAPABILITIES.len()
        || !plan
            .capabilities
            .iter()
            .zip(GENESIS_BRANCH_CAPABILITIES)
            .all(|(actual, expected)| actual == expected)
    {
        return Err(invalid("register plan capabilities must equal genesis"));
    }
    display_name(&plan.display_name)?;
    id(&plan.master_cert_id, "master_cert_id")?;
    id(&plan.branch_cert_id, "branch_cert_id")?;
    profile(&plan.profile)?;
    for (value, field) in [
        (plan.certificate_issued_at, "certificate_issued_at"),
        (plan.branch_not_before, "branch_not_before"),
        (plan.branch_expires_at, "branch_expires_at"),
        (plan.issued_at, "issued_at"),
        (plan.expires_at, "expires_at"),
    ] {
        safe(value, field)?;
    }
    if plan.expires_at <= plan.issued_at || plan.expires_at - plan.issued_at > REGISTER_TTL_SECONDS
    {
        return Err(invalid("register plan validity window"));
    }
    if plan.branch_expires_at <= plan.branch_not_before
        || plan.branch_expires_at - plan.branch_not_before > MAX_BRANCH_LEASE_SECONDS
    {
        return Err(invalid("register plan branch lease"));
    }
    match plan.purpose {
        RegisterPurpose::Create => {
            if plan.previous_agent_head_hash.is_some()
                || plan.previous_master_certificate_hash.is_some()
                || plan.next_range != 1
            {
                return Err(invalid(
                    "create plan must use literal null prior fields and range one",
                ));
            }
        }
        RegisterPurpose::Rebind => {
            let (Some(head), Some(cert)) =
                (&plan.previous_agent_head_hash, &plan.previous_master_certificate_hash)
            else {
                return Err(invalid("rebind plan requires prior fields"));
            };
            binary(head, 32, "previous_agent_head_hash")?;
            binary(cert, 32, "previous_master_certificate_hash")?;
            if plan.next_range < 2 || plan.next_range > MAX_RANGE {
                return Err(invalid("rebind plan next range"));
            }
        }
    }
    Ok(())
}

/// Validate a decision body's own fields (closed schema, identifiers, validity window).
/// # Errors
/// Refuses schema, identifier, signer and window violations.
pub fn validate_register_decision_body(body: &RegisterDecisionBody) -> Result<(), ProtocolError> {
    if body.schema != REGISTER_AUTHORIZATION_SCHEMA || body.version != AGENT_REGISTER_VERSION {
        return Err(invalid("register decision schema or version"));
    }
    id(&body.request_id, "request_id")?;
    binary(&body.request_hash, 32, "request_hash")?;
    device(&body.signer, "signer")?;
    safe(body.issued_at, "issued_at")?;
    safe(body.expires_at, "expires_at")?;
    if body.expires_at <= body.issued_at || body.expires_at - body.issued_at > REGISTER_TTL_SECONDS
    {
        return Err(invalid("register decision validity window"));
    }
    Ok(())
}

fn validate_register_cancel(cancel: &RegisterCancel) -> Result<(), ProtocolError> {
    id(&cancel.request_id, "request_id")?;
    binary(&cancel.request_hash, 32, "request_hash")
}

fn validate_agent_publish_receipt(receipt: &AgentPublishReceipt) -> Result<(), ProtocolError> {
    id(&receipt.request_id, "request_id")?;
    for (value, field) in [
        (&receipt.request_hash, "request_hash"),
        (&receipt.record_hash, "record_hash"),
        (&receipt.profile_hash, "profile_hash"),
        (&receipt.custodian_head_hash, "custodian_head_hash"),
    ] {
        binary(value, 32, field)?;
    }
    device(&receipt.custodian_primary, "custodian_primary")?;
    safe(receipt.accepted_at, "accepted_at")
}

fn profile(value: &AgentRegisterProfile) -> Result<(), ProtocolError> {
    if value.responsibility.trim().is_empty()
        || value.responsibility.len() > MAX_DISPLAY_NAME_BYTES
        || !text_safety::single_line_is_safe(&value.responsibility)
        || !is_nfc(&value.responsibility)
    {
        return Err(invalid("profile responsibility"));
    }
    for (text, field) in [(&value.provider, "profile provider"), (&value.model, "profile model")] {
        if text.trim().is_empty()
            || text.len() > 128
            || !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(invalid(field));
        }
    }
    binary(&value.persona_hash, 32, "persona_hash")?;
    for (number, field) in
        [(value.persona_version, "persona_version"), (value.profile_epoch, "profile_epoch")]
    {
        if number == 0 {
            return Err(invalid(field));
        }
        safe(number, field)?;
    }
    Ok(())
}

fn display_name(value: &str) -> Result<(), ProtocolError> {
    if value.trim().is_empty()
        || value.len() > MAX_DISPLAY_NAME_BYTES
        || !text_safety::single_line_is_safe(value)
        || !is_nfc(value)
    {
        return Err(invalid("register plan display_name"));
    }
    Ok(())
}

fn device(value: &DeviceRef, field: &'static str) -> Result<(), ProtocolError> {
    id(&value.account_anchor, field)?;
    id(&value.device_id, field)?;
    if value.device_epoch == 0 {
        return Err(invalid(field));
    }
    safe(value.device_epoch, field)
}

/// Printable, bounded, non-empty identifier.
fn id(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(invalid(field));
    }
    Ok(())
}

fn safe(value: u64, field: &'static str) -> Result<(), ProtocolError> {
    if value > MAX_SAFE_JSON_INTEGER {
        return Err(invalid(field));
    }
    Ok(())
}

/// Exact-length, canonical base64url binary value.
fn binary(value: &str, count: usize, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != (count * 8).div_ceil(6) {
        return Err(invalid(field));
    }
    let raw = decode_base64url(value).map_err(|_| invalid(field))?;
    if raw.len() != count || encode_base64url(&raw) != value {
        return Err(invalid(field));
    }
    Ok(())
}

fn encode_checked<T: Serialize>(
    value: &T,
    validate: impl FnOnce(&T) -> Result<(), ProtocolError>,
) -> Result<Vec<u8>, ProtocolError> {
    validate(value)?;
    let bytes = canonical_json_bytes(value)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("agent register object byte budget exceeded"));
    }
    Ok(bytes)
}

fn decode_checked<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ProtocolError>,
) -> Result<T, ProtocolError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = decode(bytes, MAX_RECORD_BYTES)?;
    validate(&value)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(invalid("agent register object is not canonical"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Result = std::result::Result<(), Box<dyn std::error::Error>>;

    fn b64(byte: u8) -> String {
        encode_base64url([byte; 32])
    }

    fn device_ref(anchor: u8, id: &str, epoch: u64) -> DeviceRef {
        DeviceRef { account_anchor: b64(anchor), device_id: id.to_owned(), device_epoch: epoch }
    }

    fn plan() -> RegisterPlan {
        RegisterPlan {
            schema: REGISTER_PLAN_SCHEMA.to_owned(),
            version: AGENT_REGISTER_VERSION,
            request_id: "req-1".to_owned(),
            purpose: RegisterPurpose::Create,
            owner_anchor: b64(1),
            human_head_hash: b64(2),
            human_primary: device_ref(1, "phone", 1),
            desktop: device_ref(1, "desktop", 1),
            agent_anchor: b64(3),
            principal_id: "principal-agent".to_owned(),
            agent_device: device_ref(3, "agent-desktop", 1),
            master_public_key: b64(4),
            self_signing_public_key: b64(5),
            branch_signing_public_key: b64(6),
            agreement_public_key: b64(7),
            capabilities: GENESIS_BRANCH_CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
            display_name: "Helper".to_owned(),
            certificate_issued_at: 1_800_000_000,
            branch_not_before: 1_800_000_000,
            branch_expires_at: 1_800_000_000 + 86_400,
            master_cert_id: "master-cert-1".to_owned(),
            branch_cert_id: "branch-cert-1".to_owned(),
            profile: AgentRegisterProfile {
                responsibility: "Answers questions".to_owned(),
                provider: "provider".to_owned(),
                model: "model".to_owned(),
                persona_version: 1,
                persona_hash: b64(8),
                profile_epoch: 1,
            },
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_300,
            previous_agent_head_hash: None,
            previous_master_certificate_hash: None,
            next_range: 1,
        }
    }

    #[test]
    fn plan_round_trips_canonically_and_hash_follows_every_field() -> Result {
        let original = plan();
        let bytes = encode_register_plan(&original)?;
        assert_eq!(decode_register_plan(&bytes)?, original, "plan must round-trip exactly");
        let mut changed = original.clone();
        changed.display_name = "Other".to_owned();
        assert_ne!(
            register_plan_hash(&original)?,
            register_plan_hash(&changed)?,
            "a changed display name must change the plan hash"
        );
        Ok(())
    }

    #[test]
    fn create_plan_requires_literal_null_prior_fields_and_genesis_range() {
        let mut bad = plan();
        bad.previous_agent_head_hash = Some(b64(9));
        assert!(validate_register_plan(&bad).is_err(), "create must refuse a prior head");
        let mut bad_range = plan();
        bad_range.next_range = 2;
        assert!(validate_register_plan(&bad_range).is_err(), "create must use range one");
    }

    #[test]
    fn rebind_plan_requires_prior_fields_and_a_later_range() -> Result {
        let mut rebind = plan();
        rebind.purpose = RegisterPurpose::Rebind;
        assert!(validate_register_plan(&rebind).is_err(), "rebind without prior fields refuses");
        rebind.previous_agent_head_hash = Some(b64(9));
        rebind.previous_master_certificate_hash = Some(b64(10));
        rebind.next_range = 2;
        validate_register_plan(&rebind)?;
        rebind.next_range = 1;
        assert!(validate_register_plan(&rebind).is_err(), "rebind must use a later range");
        Ok(())
    }

    #[test]
    fn plan_refuses_widened_capabilities_long_windows_and_unknown_fields() -> Result {
        let mut widened = plan();
        widened.capabilities.push("admin".to_owned());
        assert!(validate_register_plan(&widened).is_err(), "capabilities must equal genesis");
        let mut long = plan();
        long.expires_at = long.issued_at + REGISTER_TTL_SECONDS + 1;
        assert!(validate_register_plan(&long).is_err(), "plan lifetime is capped at 300 s");
        let mut value = serde_json::to_value(plan())?;
        value
            .as_object_mut()
            .ok_or("plan must encode as an object")?
            .insert("unexpected".to_owned(), serde_json::json!(true));
        let bytes = canonical_json_bytes(&value)?;
        assert!(decode_register_plan(&bytes).is_err(), "unknown fields must refuse");
        Ok(())
    }

    #[test]
    fn decision_signing_bytes_bind_schema_and_refuse_unknown_outcomes() -> Result {
        let body = RegisterDecisionBody {
            schema: REGISTER_AUTHORIZATION_SCHEMA.to_owned(),
            version: AGENT_REGISTER_VERSION,
            request_id: "req-1".to_owned(),
            request_hash: b64(11),
            decision: RegisterOutcome::Approve,
            signer: device_ref(1, "phone", 1),
            issued_at: 1_800_000_010,
            expires_at: 1_800_000_200,
        };
        let approve = decision_signing_bytes(&body)?;
        let mut deny = body.clone();
        deny.decision = RegisterOutcome::Deny;
        assert_ne!(approve, decision_signing_bytes(&deny)?, "approve and deny must differ");
        let mut body_value = serde_json::to_value(&body)?;
        body_value["decision"] = serde_json::json!("maybe");
        let envelope = serde_json::json!({"body": body_value, "signature": b64(12)});
        let raw = canonical_json_bytes(&envelope)?;
        assert!(decode_register_decision(&raw).is_err(), "unknown outcome token must refuse");
        Ok(())
    }

    #[test]
    fn cancel_and_receipt_round_trip_and_refuse_bad_hashes() -> Result {
        let cancel = RegisterCancel { request_id: "req-1".to_owned(), request_hash: b64(11) };
        let cancel_bytes = encode_register_cancel(&cancel)?;
        assert_eq!(decode_register_cancel(&cancel_bytes)?, cancel);
        let bad =
            RegisterCancel { request_id: "req-1".to_owned(), request_hash: "short".to_owned() };
        assert!(encode_register_cancel(&bad).is_err(), "malformed hash must refuse");
        let receipt = AgentPublishReceipt {
            request_id: "req-1".to_owned(),
            request_hash: b64(11),
            record_hash: b64(13),
            profile_hash: b64(14),
            custodian_head_hash: b64(15),
            custodian_primary: device_ref(1, "phone", 1),
            accepted_at: 1_800_000_100,
        };
        let receipt_bytes = encode_agent_publish_receipt(&receipt)?;
        assert_eq!(decode_agent_publish_receipt(&receipt_bytes)?, receipt);
        Ok(())
    }

    #[test]
    fn non_canonical_plan_bytes_refuse() -> Result {
        let pretty = serde_json::to_vec_pretty(&plan())?;
        assert!(decode_register_plan(&pretty).is_err(), "pretty JSON is not canonical");
        Ok(())
    }
}
