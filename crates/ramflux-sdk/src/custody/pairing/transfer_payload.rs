// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded handover metadata. Secrets serialize directly into one zeroizing allocation.

use crate::SdkError;
use ramflux_crypto::custody::pairing::{HpkeReceiver, HpkeSender, MAX_HPKE_PLAINTEXT};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::channel::{
    AttestingHead, DataKey, GroupRestriction, JournalEntry, PendingInvitation, RetainedFloor,
    RetainedFloorsRef, TransferPayload,
};
use ramflux_protocol::custody::pairing::{PairingWire, Transcript};
use serde::{Serialize, Serializer, ser::SerializeMap};
use zeroize::Zeroizing;

struct Canonical<'a, T: ?Sized>(&'a T);

macro_rules! canonical {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl Serialize for Canonical<'_, $ty> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(None)?;
                $(map.serialize_entry(stringify!($field), &self.0.$field)?;)+
                map.end()
            }
        }
    };
}

canonical!(DataKey, key, key_id, purpose);
canonical!(AttestingHead, epoch, hash);
canonical!(RetainedFloorsRef, count, object_hash, total_len);
canonical!(DeviceRef, account_anchor, device_epoch, device_id);
canonical!(PendingInvitation, expires_at, invitation_id, proposal_hash);
canonical!(JournalEntry, acknowledgement_hash, intent_hash, operation_id, state);
canonical!(
    GroupRestriction,
    control_head_hash,
    group_genesis_hash,
    group_id,
    restriction_hashes,
    revocation_hashes
);

impl<T> Serialize for Canonical<'_, [T]>
where
    for<'a> Canonical<'a, T>: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            sequence.serialize_element(&Canonical(item))?;
        }
        sequence.end()
    }
}

impl Serialize for Canonical<'_, RetainedFloor> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (root, epoch, head, device) = match self.0 {
            RetainedFloor::Root { root, epoch, attesting_head } => {
                (root, epoch, attesting_head, None)
            }
            RetainedFloor::Device { root, device, epoch, attesting_head } => {
                (root, epoch, attesting_head, Some(device))
            }
        };
        let mut map = serializer.serialize_map(Some(if device.is_some() { 5 } else { 4 }))?;
        map.serialize_entry("attesting_head", &Canonical(head))?;
        if let Some(device) = device {
            map.serialize_entry("device", device)?;
        }
        map.serialize_entry("epoch", epoch)?;
        map.serialize_entry("kind", if device.is_some() { "device_floor" } else { "root_floor" })?;
        map.serialize_entry("root", root)?;
        map.end()
    }
}

impl Serialize for Canonical<'_, TransferPayload> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut map =
            serializer.serialize_map(Some(12 + usize::from(value.retained_floors.is_some())))?;
        map.serialize_entry("current_record_hash", &value.current_record_hash)?;
        map.serialize_entry("delegation_state", &value.delegation_state)?;
        map.serialize_entry("device_set_epoch", &value.device_set_epoch)?;
        map.serialize_entry(
            "group_restriction_summary",
            &Canonical(value.group_restriction_summary.as_slice()),
        )?;
        map.serialize_entry("journal", &Canonical(value.journal.as_slice()))?;
        map.serialize_entry("optional_data_keys", &Canonical(value.optional_data_keys.as_slice()))?;
        map.serialize_entry("pending_erasure", &Canonical(value.pending_erasure.as_slice()))?;
        map.serialize_entry(
            "pending_invitations",
            &Canonical(value.pending_invitations.as_slice()),
        )?;
        if let Some(reference) = &value.retained_floors {
            map.serialize_entry("retained_floors", &Canonical(reference))?;
        }
        map.serialize_entry("schema", &value.schema)?;
        map.serialize_entry("transcript_hash", &value.transcript_hash)?;
        map.serialize_entry("transfer_id", &value.transfer_id)?;
        map.serialize_entry("version", &value.version)?;
        map.end()
    }
}

/// Serialize the closed payload without a Value tree, temporary secret strings or reallocations.
///
/// # Errors
/// Refuses invalid profiles, missing consent, or a payload beyond the simultaneous size ledger.
pub fn encode_payload(
    payload: &TransferPayload,
    transcript: &Transcript,
    th: &str,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    payload.validate_context(transcript, th).map_err(|error| super::transport::wire(&error))?;
    crate::custody::serialize_secret(&Canonical(payload), MAX_HPKE_PLAINTEXT)
        .map_err(|_| SdkError::PairingCode("TransferCapacity"))
}

/// Open once and verify the exact transcript/consent before any target installation.
///
/// # Errors
/// Invalid ciphertext, malformed or noncanonical payload, altered context or selection refuses.
pub fn open_payload(
    receiver: &mut HpkeReceiver,
    ciphertext: &[u8],
    transcript: &Transcript,
    th: &str,
) -> Result<TransferPayload, SdkError> {
    let plaintext = receiver.open(ciphertext)?;
    if plaintext.len() > MAX_HPKE_PLAINTEXT {
        return Err(SdkError::PairingCode("TransferCapacity"));
    }
    // Typed serde visitors reject duplicate and unknown fields; no secret-bearing Value tree.
    let payload: TransferPayload = ramflux_protocol::parse_i_json_secret(&plaintext)
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let canonical = encode_payload(&payload, transcript, th)?;
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok(payload)
}

/// Seal exactly one approved handover payload in the Auth HPKE context.
///
/// # Errors
/// Refuses size/context/consent disagreement or a reused HPKE context.
pub fn seal_payload(
    sender: &mut HpkeSender,
    payload: &TransferPayload,
    transcript: &Transcript,
    th: &str,
) -> Result<Vec<u8>, SdkError> {
    Ok(sender.seal(&encode_payload(payload, transcript, th)?)?)
}

/// Require the complete source denial census and preserve every independently retained target veto.
/// Different control heads require ordinary encrypted reconciliation before mutation.
///
/// # Errors
/// Missing source evidence, conflicting genesis/heads or union overflow refuses the transfer.
pub fn merge_denials(
    payload: &TransferPayload,
    complete_source: &[GroupRestriction],
    target: &[GroupRestriction],
) -> Result<Vec<GroupRestriction>, SdkError> {
    payload.validate().map_err(|error| super::transport::wire(&error))?;
    if payload.group_restriction_summary != complete_source {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let mut merged: std::collections::BTreeMap<_, _> =
        target.iter().map(|row| (row.group_id.clone(), row.clone())).collect();
    for source in complete_source {
        if let Some(existing) = merged.get_mut(&source.group_id) {
            if existing.group_genesis_hash != source.group_genesis_hash
                || existing.control_head_hash != source.control_head_hash
            {
                return Err(SdkError::PairingCode("PublicationPending"));
            }
            for (into, from) in [
                (&mut existing.restriction_hashes, &source.restriction_hashes),
                (&mut existing.revocation_hashes, &source.revocation_hashes),
            ] {
                into.extend(from.iter().cloned());
                into.sort();
                into.dedup();
                if into.len() > 8 {
                    return Err(SdkError::PairingCode("TransferCapacity"));
                }
            }
        } else {
            merged.insert(source.group_id.clone(), source.clone());
        }
    }
    if merged.len() > 64 {
        return Err(SdkError::PairingCode("TransferCapacity"));
    }
    Ok(merged.into_values().collect())
}

/// Encode the complete collection before any artifact is queued. Never truncate it.
/// # Errors
/// Over-count or over-size collections return `TransferFloorsTooLarge`.
pub fn encode_retained_floors(
    floors: &[RetainedFloor],
) -> Result<(RetainedFloorsRef, Zeroizing<Vec<u8>>), SdkError> {
    if floors.len() > 8192 {
        return Err(SdkError::PairingCode("TransferFloorsTooLarge"));
    }
    for floor in floors {
        floor.validate().map_err(|error| super::transport::wire(&error))?;
    }
    let bytes = crate::custody::serialize_secret(&Canonical(floors), 1_048_576)
        .map_err(|_| SdkError::PairingCode("TransferFloorsTooLarge"))?;
    let reference = RetainedFloorsRef {
        count: u64::try_from(floors.len())
            .map_err(|_| SdkError::PairingCode("TransferFloorsTooLarge"))?,
        total_len: u64::try_from(bytes.len())
            .map_err(|_| SdkError::PairingCode("TransferFloorsTooLarge"))?,
        object_hash: ramflux_protocol::custody::object_hash(&floors)?,
    };
    Ok((reference, bytes))
}

/// Verify the commitment and exact canonical collection before exposing any floor.
/// # Errors
/// Wrong count, length, hash, noncanonical JSON or an invalid entry refuses the artifact.
pub fn decode_retained_floors(
    reference: &RetainedFloorsRef,
    bytes: &[u8],
) -> Result<Vec<RetainedFloor>, SdkError> {
    reference.validate().map_err(|error| super::transport::wire(&error))?;
    if bytes.len() > 1_048_576 {
        return Err(SdkError::PairingCode("TransferFloorsTooLarge"));
    }
    if u64::try_from(bytes.len()).ok() != Some(reference.total_len) {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let floors: Vec<RetainedFloor> = ramflux_protocol::parse_i_json_secret(bytes)
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let (actual, canonical) = encode_retained_floors(&floors)?;
    if actual != *reference || canonical.as_slice() != bytes {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    Ok(floors)
}

#[cfg(test)]
mod tests;
