// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation side of the dormant attachment renewal route (P25 N6a): the capability, the
//! node-signed `attachment_authority` pin published in the server record, the in-memory
//! availability book, and the admission gate for an inbound renewal peer request.
use crate::relay::attachment::RenewalRefusal;
use crate::{FederationRedbStore, NodeCoreError};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

/// Negotiated federation capability. Advertised only when the authority is configured.
pub const ATTACHMENT_RENEWAL_CAPABILITY: &str = "attachment-renewal.v1";
/// Largest JSON integer that is exact in JCS numbers.
const MAX_GENERATION: u64 = (1 << 53) - 1;
/// Unpadded base64url length of a 32-byte Ed25519 key.
const KEY_CHARS: usize = 43;

/// The node-signed pin of A's attachment authority. Two members, no others.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationAttachmentAuthority {
    pub generation: u64,
    pub signing_public_key: String,
}

impl FederationAttachmentAuthority {
    /// # Errors
    /// `CapabilityInvalid` for a generation outside `1..=2^53-1` or a key that is not
    /// exactly 43 base64url characters decoding to 32 bytes.
    pub fn validate(&self) -> Result<[u8; 32], RenewalRefusal> {
        if self.generation == 0 || self.generation > MAX_GENERATION {
            return Err(RenewalRefusal::CapabilityInvalid);
        }
        if self.signing_public_key.len() != KEY_CHARS {
            return Err(RenewalRefusal::CapabilityInvalid);
        }
        ramflux_protocol::decode_base64url(&self.signing_public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(RenewalRefusal::CapabilityInvalid)
    }
}

/// Field decoder: an absent key stays `None` through `#[serde(default)]`; an explicit
/// `null` is refused as non-canonical because the inner type is not an `Option`.
pub(crate) fn authority_not_null<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FederationAttachmentAuthority>, D::Error> {
    let authority = FederationAttachmentAuthority::deserialize(deserializer)?;
    authority
        .validate()
        .map_err(|_| serde::de::Error::custom("non-canonical attachment_authority"))?;
    Ok(Some(authority))
}

/// What B's router learns about a peer's authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityPin {
    pub generation: u64,
    pub key: [u8; 32],
}

/// Wire answer of the `AttachmentAuthorityPin` local action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PinAnswer {
    Available {
        pin: AuthorityPin,
    },
    /// Not advertised, not negotiated, or refused by the history.
    Unavailable,
    /// The history has no room for this node.
    SourceUnknown,
}
impl PinAnswer {
    /// # Errors
    /// `CapabilityUnavailable` / `SourceUnknown` as in section 2.
    pub fn into_pin(self) -> Result<AuthorityPin, RenewalRefusal> {
        match self {
            Self::Available { pin } => Ok(pin),
            Self::Unavailable => Err(RenewalRefusal::CapabilityUnavailable),
            Self::SourceUnknown => Err(RenewalRefusal::SourceUnknown),
        }
    }
}

/// Why an adoption left the pin unavailable (history is never changed by these).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Withdrawn {
    /// The record carries no field, or the capability was not negotiated.
    Absent,
    /// Same generation, different key.
    Substitution,
    /// Lower generation than the history maximum.
    Rollback,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityAdoption {
    Available(AuthorityPin),
    Unavailable(Withdrawn),
}

#[cfg(test)]
pub(crate) type HistoryHook = std::sync::Arc<dyn Fn(&AttachmentAuthorityBook) + Send + Sync>;

/// In-memory availability, recomputed from every freshly verified record. The lock is
/// held across the durable history write *and* the publication, so a lower generation
/// can never overwrite a higher one that was published in between.
#[derive(Default)]
pub struct AttachmentAuthorityBook {
    pub(crate) available: Mutex<BTreeMap<String, AuthorityPin>>,
    #[cfg(test)]
    pub(crate) after_history_write: Mutex<Option<HistoryHook>>,
}
impl AttachmentAuthorityBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adopt one freshly signed server record. The signature and freshness are verified
    /// here, and negotiation is read from the node's actual negotiated capability set
    /// (an advertisement alone is not enough).
    /// # Errors
    /// The record's verification failure; `AttachmentAuthorityHistoryCapacity` when the
    /// node has no history slot (its pin is made unavailable first); store failures.
    pub fn adopt_record(
        &self,
        store: &FederationRedbStore,
        state: &crate::FederationTrustState,
        record: &crate::FederationServerRecord,
        now: u64,
    ) -> Result<AuthorityAdoption, NodeCoreError> {
        crate::verify_federation_server_record(record, now)?;
        let negotiated = state
            .negotiated_capabilities(&record.node_id)
            .is_some_and(|caps| caps.contains(ATTACHMENT_RENEWAL_CAPABILITY));
        self.adopt(store, &record.node_id, record.attachment_authority.as_ref(), negotiated, now)
    }

    pub(crate) fn adopt(
        &self,
        store: &FederationRedbStore,
        node_id: &str,
        authority: Option<&FederationAttachmentAuthority>,
        negotiated: bool,
        now: u64,
    ) -> Result<AuthorityAdoption, NodeCoreError> {
        let mut available = self
            .available
            .lock()
            .map_err(|_| NodeCoreError::Redb("attachment authority book poisoned".into()))?;
        let outcome = store.adopt_attachment_authority(node_id, authority, negotiated, now);
        #[cfg(test)]
        {
            let hook = self.after_history_write.lock().ok().and_then(|h| h.clone());
            if let Some(hook) = hook {
                hook(self);
            }
        }
        match &outcome {
            Ok(AuthorityAdoption::Available(pin)) => {
                available.insert(node_id.to_owned(), *pin);
            }
            _ => {
                available.remove(node_id);
            }
        }
        outcome
    }

    /// The answer for B's router, rechecked against live state at every lookup: an
    /// unadmitted node is `SourceUnknown`, a peer that did not negotiate the capability is
    /// unavailable whatever it advertised, and a node the history had no room for is
    /// `SourceUnknown` too (derived from the durable counter, not cached).
    #[must_use]
    pub fn answer(
        &self,
        store: &FederationRedbStore,
        state: &crate::FederationTrustState,
        node_id: &str,
        now: u64,
    ) -> PinAnswer {
        if !state.can_deliver_to(node_id, now) {
            return PinAnswer::SourceUnknown;
        }
        let negotiated = state
            .negotiated_capabilities(node_id)
            .is_some_and(|caps| caps.contains(ATTACHMENT_RENEWAL_CAPABILITY));
        if !negotiated {
            return PinAnswer::Unavailable;
        }
        if let Some(pin) = self.available.lock().ok().and_then(|a| a.get(node_id).copied()) {
            return PinAnswer::Available { pin };
        }
        let no_row = store.attachment_authority_history(node_id).is_ok_and(|h| h.is_none());
        let full =
            store.attachment_authority_nodes().is_ok_and(|n| n >= crate::MAX_AUTHORITY_NODES);
        if no_row && full { PinAnswer::SourceUnknown } else { PinAnswer::Unavailable }
    }
}

/// Facts about one inbound `/s9/attachments/renew/peer` request, all taken from the
/// transport or from this node's own state, never from the request body.
#[derive(Clone, Copy, Debug)]
pub struct PeerRenewalFacts<'a> {
    /// Node id from the verified TLS SPIFFE identity.
    pub tls_node: &'a str,
    /// `home_node` claimed inside the request.
    pub home_node: &'a str,
    /// The peer is admitted for delivery.
    pub admitted: bool,
    /// This node advertises the capability (the authority is configured).
    pub advertised: bool,
    /// The peer negotiated the capability.
    pub negotiated: bool,
}

/// Admission of an inbound renewal peer request. Checks run in a fixed order and each
/// refusal comes from exactly one predicate.
/// # Errors
/// `CapabilityUnavailable` (not advertised, or the peer lacks it), `SourceUnknown`
/// (unadmitted peer), `HomeMismatch` (TLS node is not the request's `home_node`).
pub fn admit_peer_renewal(facts: &PeerRenewalFacts<'_>) -> Result<(), RenewalRefusal> {
    if !facts.advertised {
        return Err(RenewalRefusal::CapabilityUnavailable);
    }
    if !facts.admitted {
        return Err(RenewalRefusal::SourceUnknown);
    }
    if !facts.negotiated {
        return Err(RenewalRefusal::CapabilityUnavailable);
    }
    if facts.tls_node != facts.home_node {
        return Err(RenewalRefusal::HomeMismatch);
    }
    Ok(())
}
