// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Certified management, exact route binding and bounded sender-cost verification.
use crate::{
    CryptoError, DeviceBranch,
    custody::{SelfSigningKey, VerifiedRecord},
};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{
    contact_reach as wire,
    custody::{self, DeviceRef, Envelope as Signed},
};

mod groups;
mod report_receipt;
mod source;
pub use groups::{verify_group_retirement, verify_group_roster, verify_group_roster_command};
pub use report_receipt::verify_bound_node_report_receipt;
pub use source::{verify_current_source_submission, verify_original_source_submission};
mod continuity;
pub use continuity::{NodeContinuityContext, verify_node_continuity};
pub mod directory;
mod peer;
#[cfg(test)]
mod tests;
pub use peer::{
    VerifiedPeer, verify_native_prekey, verify_node_discovery, verify_notice, verify_peer_reply,
    verify_transport_snapshot,
};

fn reject(reason: &'static str) -> CryptoError {
    CryptoError::IdentityAuthority(reason)
}
fn durable_capability(traffic: wire::Traffic) -> &'static str {
    if matches!(traffic, wire::Traffic::OwnCopy | wire::Traffic::SelfSync) {
        "sync"
    } else {
        "message"
    }
}

fn manager(
    authority: &VerifiedRecord,
    actor: &DeviceRef,
    root: &str,
    head: &str,
    cert: &str,
    now: u64,
) -> Result<(), CryptoError> {
    let record = authority.envelope();
    if root != record.body.account_anchor
        || head != custody::object_hash(record)?
        || cert != custody::object_hash(&record.body.master_certificate)?
    {
        return Err(reject("reach current management authority mismatch"));
    }
    authority.authorize_primary_management(actor, "contact_consent", now)?;
    Ok(())
}

fn verify<T: serde::Serialize>(
    tag: &str,
    signed: &Signed<T>,
    key: &str,
) -> Result<(), CryptoError> {
    crate::verify_canonical_signature(
        &custody::signing_bytes(tag, &signed.body)?,
        &signed.signature,
        key,
    )
}

/// Verify a submitted policy against current recipient authority and home head.
/// # Errors
/// Refuses branch/web management, stale heads, invalid signatures and expired commands.
pub fn verify_policy(
    update: &Signed<wire::ReachPolicy>,
    authority: &VerifiedRecord,
    home_hash: &str,
    actor: &DeviceRef,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    wire::check_submission_time(b.issued_at, b.expires_at, now)?;
    original_management_time(authority, &b.actor, b.issued_at)?;
    if &b.actor != actor || b.home_head_hash != home_hash {
        return Err(reject("reach policy session or home mismatch"));
    }
    manager(
        authority,
        actor,
        &b.account_anchor,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        now,
    )?;
    if ramflux_protocol::canonical_json_bytes(update)?.len() > wire::MAX_UPDATE_BYTES {
        return Err(reject("reach policy byte budget"));
    }
    verify(
        wire::POLICY_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}

/// Verify a retained policy after its submission window has closed.
/// # Errors
/// Refuses revoked certificates/primaries and invalid original signatures.
pub fn verify_retained_policy(
    update: &Signed<wire::ReachPolicy>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    retained_manager(authority, &b.actor, &b.account_anchor, &b.master_certificate_hash, now)?;
    verify(
        wire::POLICY_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
/// Verify original recipient authority independently of a home-state manifest signature.
/// # Errors
/// Refuses stale certificates, invalid decision bodies and forged signatures.
pub fn verify_retained_admission(
    update: &Signed<wire::Admission>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    retained_manager(authority, &b.actor, &b.recipient_root, &b.master_certificate_hash, now)?;
    verify(
        wire::ADMISSION_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
fn retained_manager(
    authority: &VerifiedRecord,
    actor: &DeviceRef,
    root: &str,
    certificate: &str,
    now: u64,
) -> Result<(), CryptoError> {
    if root != authority.envelope().body.account_anchor
        || certificate != custody::object_hash(&authority.envelope().body.master_certificate)?
    {
        return Err(reject("retained reach certificate revoked or unrelated"));
    }
    authority.authorize_primary_management(actor, "contact_consent", now)?;
    Ok(())
}

/// Verify a volatile route against already adopted current source authority.
/// # Errors
/// Refuses first-seen/stale branch evidence, changed frame bytes and a renewed lifetime.
pub fn verify_ephemeral(
    frame: &wire::ReachEphemeral,
    authority: &VerifiedRecord,
    now_ms: u64,
) -> Result<(), CryptoError> {
    frame.validate(now_ms)?;
    let b = &frame.route.body;
    let envelope = &frame.frame.envelope;
    let target = ramflux_protocol::parse_qualified_device_id(&envelope.target_delivery_id)?
        .ok_or_else(|| reject("native ephemeral target required"))?;
    if !matches!(
        ramflux_protocol::message::outer::parse_live_named_delivery_mode(envelope),
        Ok(ramflux_protocol::message::outer::NamedDeliveryMode::Ephemeral)
    ) || ramflux_protocol::message::outer::refuse_live_bridge(envelope).is_err()
        || envelope.delivery_class != ramflux_protocol::DeliveryClass::Message
        || target.0 != b.recipient_root
        || envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            != Some(b.source.account_anchor.as_str())
        || b.source.account_anchor != authority.envelope().body.account_anchor
        || b.authority_head_hash != custody::object_hash(authority.envelope())?
        || b.source.device_id != envelope.source_device_id
        || authority.envelope().body.principal_id != envelope.source_principal_id
    {
        return Err(reject("ephemeral source/authority mismatch"));
    }
    let certificate = authority.authorize(&b.source, "message", now_ms / 1000)?;
    verify(wire::ROUTE_DOMAIN, &frame.route, &certificate.branch_signing_public_key)?;
    ramflux_protocol::verify_envelope_sender_signature(
        envelope,
        &certificate.branch_signing_public_key,
    )?;
    Ok(())
}

/// Verify a submitted recipient decision. Notice and peer evidence are verified by the caller.
/// # Errors
/// Refuses malformed or stale authority, forged primary intent and expired commands.
pub fn verify_admission(
    update: &Signed<wire::Admission>,
    authority: &VerifiedRecord,
    home_hash: &str,
    actor: &DeviceRef,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    wire::check_submission_time(b.issued_at, b.expires_at, now)?;
    original_management_time(authority, &b.actor, b.issued_at)?;
    if &b.actor != actor || b.home_head_hash != home_hash {
        return Err(reject("admission session or home mismatch"));
    }
    manager(
        authority,
        actor,
        &b.recipient_root,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        now,
    )?;
    if ramflux_protocol::canonical_json_bytes(update)?.len() > wire::MAX_UPDATE_BYTES {
        return Err(reject("admission byte budget"));
    }
    verify(
        wire::ADMISSION_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}

impl SelfSigningKey {
    /// Sign an explicit receiving-policy action with the certified everyday management key.
    /// # Errors
    /// Refuses unrelated keys, malformed commands or unavailable primary authority.
    pub fn sign_reach_policy(
        &self,
        body: wire::ReachPolicy,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<Signed<wire::ReachPolicy>, CryptoError> {
        body.validate()?;
        manager(
            authority,
            &body.actor,
            &body.account_anchor,
            &body.authority_head_hash,
            &body.master_certificate_hash,
            now,
        )?;
        if self.public_key()
            != authority.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(reject("reach requires certified self signing key"));
        }
        let signed = sign(wire::POLICY_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))?;
        verify_policy(&signed, authority, &signed.body.home_head_hash, &signed.body.actor, now)?;
        Ok(signed)
    }

    /// Sign explicit friendship, conversation or denial intent without synthesizing consent.
    /// # Errors
    /// Refuses unrelated keys, malformed commands or unavailable primary authority.
    pub fn sign_reach_admission(
        &self,
        body: wire::Admission,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<Signed<wire::Admission>, CryptoError> {
        body.validate()?;
        manager(
            authority,
            &body.actor,
            &body.recipient_root,
            &body.authority_head_hash,
            &body.master_certificate_hash,
            now,
        )?;
        if self.public_key()
            != authority.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(reject("admission requires certified self signing key"));
        }
        let signed =
            sign(wire::ADMISSION_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))?;
        verify_admission(&signed, authority, &signed.body.home_head_hash, &signed.body.actor, now)?;
        Ok(signed)
    }
}

fn sign<T: serde::Serialize>(
    tag: &str,
    body: T,
    key: &SigningKey,
) -> Result<Signed<T>, CryptoError> {
    let bytes = custody::signing_bytes(tag, &body)?;
    Ok(Signed { body, signature: ramflux_protocol::encode_base64url(key.sign(&bytes).to_bytes()) })
}

/// Verify exact durable route bytes against the original authority at the envelope's signing time.
/// Receiving paths use `verify_current_source_submission` to additionally require current keys.
/// # Errors
/// Refuses substituted envelopes, source/conversation authority mismatch and expired routes.
pub fn verify_submission(
    submission: &wire::Submission,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &submission.route.body;
    b.validate()?;
    wire::check_submission_time(b.issued_at, b.expires_at, now)?;
    let envelope = &submission.envelope;
    if !matches!(
        ramflux_protocol::message::outer::parse_live_named_delivery_mode(envelope),
        Ok(ramflux_protocol::message::outer::NamedDeliveryMode::Durable)
    ) || ramflux_protocol::message::outer::refuse_live_bridge(envelope).is_err()
    {
        return Err(reject("durable reach requires the named durable envelope mode"));
    }
    let target = ramflux_protocol::parse_qualified_device_id(&envelope.target_delivery_id)?
        .ok_or_else(|| reject("native route target required"))?;
    let created = u64::try_from(envelope.created_at).map_err(|_| reject("negative route time"))?;
    if b.authority_head_hash != custody::object_hash(authority.envelope())?
        || envelope.ttl > ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS_U32
        || target.0 != b.recipient_root
        || matches!(b.traffic, wire::Traffic::OwnCopy | wire::Traffic::SelfSync)
            && b.source.account_anchor != b.recipient_root
        || b.envelope_hash != custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, envelope)?
        || b.source.account_anchor != authority.envelope().body.account_anchor
        || b.source.device_id != envelope.source_device_id
        || authority.envelope().body.principal_id != envelope.source_principal_id
        || b.issued_at != created
        || created.checked_add(u64::from(envelope.ttl)) != Some(b.expires_at)
        || matches!(b.traffic, wire::Traffic::Typing)
        || ramflux_protocol::canonical_json_bytes(&submission.route)?.len() > 4096
    {
        return Err(reject("reach route envelope binding mismatch"));
    }
    let certificate = authority.authorize(&b.source, durable_capability(b.traffic), b.issued_at)?;
    verify(wire::ROUTE_DOMAIN, &submission.route, &certificate.branch_signing_public_key)?;
    ramflux_protocol::verify_envelope_sender_signature(
        envelope,
        &certificate.branch_signing_public_key,
    )?;
    Ok(())
}

/// Sign a durable route with its existing envelope's device branch.
/// # Errors
/// Refuses unrelated branches, invalid route fields and signature serialization failures.
pub fn sign_route(
    body: wire::Route,
    branch: &DeviceBranch,
) -> Result<Signed<wire::Route>, CryptoError> {
    body.validate()?;
    if body.source.device_id != branch.device_id || body.source.device_epoch != branch.device_epoch
    {
        return Err(reject("route branch ownership mismatch"));
    }
    sign(wire::ROUTE_DOMAIN, body, &branch.signing_key)
}

/// Verify challenge signature and exact work binding without consuming it.
/// Consumption and replay accounting belong to the receiving transaction.
/// # Errors
/// Refuses substituted purpose/target/envelope/issuer, invalid work and stale challenges.
pub fn verify_cost(
    cost: &wire::Cost,
    expected: &wire::ChallengeRequest,
    issuer: &str,
    key: &str,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &cost.challenge.body;
    b.validate()?;
    expected.validate()?;
    wire::check_submission_time(b.issued_at, b.expires_at, now)?;
    if cost.work_nonce > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || b.issuer != issuer
        || b.purpose != expected.purpose
        || b.source_root != expected.source_root
        || b.recipient_root != expected.recipient_root
        || b.operation_hash != expected.operation_hash
    {
        return Err(reject("sender cost context mismatch"));
    }
    verify(wire::COST_DOMAIN, &cost.challenge, key)?;
    let context = custody::framed_hash(wire::COST_CONTEXT_DOMAIN, &cost.challenge)?;
    let difficulty = u8::try_from(b.difficulty).map_err(|_| reject("cost difficulty"))?;
    if !crate::registration_pow_meets_difficulty(&context, cost.work_nonce, difficulty) {
        return Err(reject("sender work insufficient"));
    }
    Ok(())
}

/// Search at most `attempts` nonces; callers schedule bounded chunks outside async executors.
/// # Errors
/// Refuses malformed challenges and safe-integer exhaustion.
pub fn solve_cost(
    challenge: &Signed<wire::Challenge>,
    start: u64,
    attempts: u32,
) -> Result<Option<wire::Cost>, CryptoError> {
    challenge.body.validate()?;
    let context = custody::framed_hash(wire::COST_CONTEXT_DOMAIN, challenge)?;
    let difficulty =
        u8::try_from(challenge.body.difficulty).map_err(|_| reject("cost difficulty"))?;
    for offset in 0..attempts {
        let nonce = start
            .checked_add(u64::from(offset))
            .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| reject("sender work nonce exhausted"))?;
        if crate::registration_pow_meets_difficulty(&context, nonce, difficulty) {
            return Ok(Some(wire::Cost { challenge: challenge.clone(), work_nonce: nonce }));
        }
    }
    Ok(None)
}

mod provenance;
pub use provenance::{
    verify_historical_admission, verify_historical_policy, verify_historical_roster_header,
    verify_historical_state_records,
};

fn original_management_time(
    authority: &VerifiedRecord,
    actor: &DeviceRef,
    issued_at: u64,
) -> Result<(), CryptoError> {
    let recipient = &authority.envelope().body;
    let manager = authority.management_actor_authority(actor)?;
    if recipient.issued_at > issued_at
        || recipient.master_certificate.body.issued_at > issued_at
        || manager.envelope().body.issued_at > issued_at
        || manager.envelope().body.master_certificate.body.issued_at > issued_at
    {
        return Err(reject("management authority was issued after original intent"));
    }
    authority.authorize_primary_management(actor, "contact_consent", issued_at)?;
    Ok(())
}

mod staging;
pub use staging::{EncryptedProvenanceStage, ProvenanceStageBuilder};
