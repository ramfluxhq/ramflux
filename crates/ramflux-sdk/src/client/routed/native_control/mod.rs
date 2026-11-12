// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer-authored generated controls (GROUP_KEY, RECOVERY, A2I, OBJECT_REVOKE): one exact-replay
//! ledger shared by the four native executors. Each executor lives in its own module.
mod a2i;
mod group_key;
mod guardian;
mod object_revoke;
mod produce;

use crate::client::identity_authority::HeadUse;
use crate::error::GeneratedRefusalCode;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message as g;

/// Sender or ownership rule failed against durable state.
fn authority(reason: &str) -> SdkError {
    SdkError::GeneratedRefused { code: GeneratedRefusalCode::Authority, reason: reason.into() }
}

/// A known field of a known layer carries a value outside its closed set.
fn content(reason: &str) -> SdkError {
    SdkError::GeneratedRefused { code: GeneratedRefusalCode::Content, reason: reason.into() }
}

/// Typed signature fields to the native form; Ed25519 is the only admitted algorithm.
fn native_signed(
    signed: Option<&g::SignedFields>,
) -> Result<ramflux_protocol::SignedFields, SdkError> {
    let signed = signed.ok_or_else(|| content("signed fields missing"))?;
    match signed.signature_alg.as_ref().and_then(|alg| alg.value.as_ref()) {
        Some(g::signature_alg::Value::Ed25519(_)) => {}
        None => return Err(content("signature algorithm missing")),
    }
    if signed.signing_key_id.is_empty() || signed.signature.is_empty() {
        return Err(content("signature fields incomplete"));
    }
    Ok(ramflux_protocol::SignedFields {
        signing_key_id: signed.signing_key_id.clone(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: signed.signature.clone(),
    })
}

fn generated_signed(signed: &ramflux_protocol::SignedFields) -> g::SignedFields {
    g::SignedFields {
        signing_key_id: signed.signing_key_id.clone(),
        signature_alg: Some(g::SignatureAlg {
            value: Some(g::signature_alg::Value::Ed25519(g::SignatureAlgEd25519 {})),
        }),
        signature: signed.signature.clone(),
    }
}

impl RamfluxClient {
    /// Principal id and signing key pinned for the authenticated transport device. A principal
    /// or key named inside a payload is only accepted when it equals this pin.
    fn pinned_peer(&self, source: &RootQualifiedDeviceRef) -> Result<(String, String), SdkError> {
        let record = self.trusted_device(HeadUse::NewAuthorization, source)?;
        let field = |name: &str| {
            record[name]
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| authority("peer device pin is incomplete"))
        };
        Ok((field("principal_id")?, field("signing_public_key")?))
    }

    /// An accepted, unblocked contact link between the peer root and the local root.
    fn require_accepted_contact(&self, peer_root: &str) -> Result<(), SdkError> {
        if self.friend_rejection_reason(peer_root)?.is_some() {
            return Err(authority("blocked or removed peer cannot send this control"));
        }
        let own = self.own_account_anchor()?;
        let linked = self.account_db()?.friend_links()?.into_iter().any(|link| {
            link.state == "accepted"
                && !link.blocked
                && ((link.requester_id == peer_root && link.target_id == own)
                    || (link.requester_id == own && link.target_id == peer_root))
        });
        if linked { Ok(()) } else { Err(authority("control requires an accepted contact link")) }
    }

    /// Exact-replay ledger for peer controls 5/9/11/12. The effect and the ledger row commit in
    /// one transaction: an exact repeat is ignored, the same id with other bytes is refused.
    fn apply_generated_peer_control_once(
        &self,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        exact_inner: &[u8],
        operation: i32,
        effect: impl FnOnce(&RootQualifiedDeviceRef) -> Result<(), SdkError>,
    ) -> Result<bool, SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let scanned = g::validation::scan_inner(exact_inner)
            .map_err(|_| SdkError::InboundRejected("native Control Inner malformed".into()))?;
        let inner = g::Inner::decode(exact_inner)
            .map_err(|_| SdkError::InboundRejected("native Control identity malformed".into()))?;
        let control = g::Control::decode(scanned.body)
            .map_err(|_| SdkError::InboundRejected("peer Control missing".into()))?;
        if control.operation != operation || !matches!(operation, 5 | 9 | 11 | 12) {
            return Err(content("control is not a peer native control"));
        }
        let known_epoch = self
            .account_db()?
            .client_device_record(&source)?
            .and_then(|record| record["device_epoch"].as_u64());
        if scanned.kind != 8
            || scanned.outcome != g::validation::ScanOutcome::Supported
            || inner.identity.as_ref() != Some(identity)
            || g::identity::verify(identity).is_err()
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != source.root_commitment()
                    || author.device_id != source.device_id()
                    || known_epoch.is_some_and(|epoch| author.device_epoch != epoch)
            })
        {
            return Err(authority("native Control author is not the authenticated pair peer"));
        }
        let key = format!(
            "routed/native-control-applied/{}/{}",
            source.storage_key(),
            ramflux_protocol::encode_base64url(&identity.id)
        );
        let digest = *blake3::hash(exact_inner).as_bytes();
        let db = self.account_db()?;
        db.write_transaction(|| {
            if let Some(old) = db.load_actor_state::<[u8; 32]>(&key)? {
                return if old == digest { Ok(false) } else { Err(SdkError::ReplayMismatch) };
            }
            effect(&source)?;
            db.persist_actor_state(&key, &digest)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_signed_refuses_missing_algorithm_and_empty_signature() {
        assert!(native_signed(None).is_err());
        let mut signed = generated_signed(&ramflux_protocol::SignedFields {
            signing_key_id: "device".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "sig".into(),
        });
        assert!(native_signed(Some(&signed)).is_ok());
        signed.signature.clear();
        assert!(native_signed(Some(&signed)).is_err());
        signed.signature = "sig".into();
        signed.signature_alg = None;
        assert!(native_signed(Some(&signed)).is_err());
    }
}
