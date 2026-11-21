// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent master custody rules shared by every provider that stores the agent master.
//!
//! Storage is write-once. The seed item `agent-master:<id>` is inserted once and never changed.
//! Each issued master certificate is recorded in its own insert-only item
//! `agent-master-cert:<id>:<range>` whose value is the certificate hash. The rules are written
//! here once; a provider supplies three primitives through [`AgentMasterCells`]. Only vault
//! implementations see the seed; no bus, C ABI or CLI surface returns it.
use super::{AGENT_MASTER_PREFIX, agent_key_unavailable, require_vault_reference};
use crate::SdkError;
use crate::custody::CustodyVaultReason;
use ramflux_crypto::custody::{
    AgentMasterItem, AgentMasterPurpose, AgentMasterRequest, MasterKey, certify_agent_master,
};
use ramflux_protocol::custody::{Envelope, MAX_RANGE, MasterCertificate};
use ramflux_protocol::{decode_base64url, encode_base64url};
use zeroize::Zeroizing;

/// Vault-reference prefix of one recorded master certificate: `agent-master-cert:<id>:<range>`.
pub(crate) const AGENT_MASTER_CERT_PREFIX: &str = "agent-master-cert:";
const SEED_BYTES: usize = 32;
const HASH_BYTES: usize = 32;

/// The three storage primitives the shared rules need. A provider implements them with its own
/// keychain, file or entry store. `insert_item` refuses an existing entry and never overwrites.
pub(crate) trait AgentMasterCells {
    /// `None` when the entry is absent.
    fn read_item(&self, reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError>;
    /// Insert only: refuses an existing entry.
    fn insert_item(&self, reference: &str, value: &[u8]) -> Result<(), SdkError>;
    /// Remove an entry. An absent entry succeeds.
    fn remove_item(&self, reference: &str) -> Result<(), SdkError>;
}

fn invalid() -> SdkError {
    SdkError::CustodyVault(CustodyVaultReason::Corrupt)
}

/// Whether `reference` is a canonical `agent-master-cert:<id>:<range>` with a range in
/// `1..=MAX_RANGE` (no leading zeros) and a valid master id.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn valid_certificate_reference(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix(AGENT_MASTER_CERT_PREFIX) else {
        return false;
    };
    let Some((id, digits)) = rest.split_once(':') else {
        return false;
    };
    let canonical_digits = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && !(digits.len() > 1 && digits.starts_with('0'));
    if !canonical_digits {
        return false;
    }
    let in_range = digits.parse::<u64>().is_ok_and(|range| (1..=MAX_RANGE).contains(&range));
    in_range
        && require_vault_reference(&format!("{AGENT_MASTER_PREFIX}{id}"), AGENT_MASTER_PREFIX)
            .is_ok()
}

/// Reference of the recorded certificate item for `range` of the master `reference`.
pub(crate) fn certificate_reference(reference: &str, range: u64) -> Result<String, SdkError> {
    require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
    if range == 0 || range > MAX_RANGE {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    let id =
        reference.strip_prefix(AGENT_MASTER_PREFIX).ok_or(SdkError::CustodyVaultUnavailable)?;
    Ok(format!("{AGENT_MASTER_CERT_PREFIX}{id}:{range}"))
}

fn seed(bytes: &[u8]) -> Result<Zeroizing<[u8; SEED_BYTES]>, SdkError> {
    let raw = <[u8; SEED_BYTES]>::try_from(bytes).map_err(|_| invalid())?;
    Ok(Zeroizing::new(raw))
}

fn fixed_hash(bytes: &[u8]) -> Result<[u8; HASH_BYTES], SdkError> {
    <[u8; HASH_BYTES]>::try_from(bytes).map_err(|_| invalid())
}

/// Hash of the certificate recorded at `range`, or `None` when none was recorded there.
fn recorded_hash(
    cells: &dyn AgentMasterCells,
    reference: &str,
    range: u64,
) -> Result<Option<[u8; HASH_BYTES]>, SdkError> {
    let item = certificate_reference(reference, range)?;
    cells.read_item(&item)?.map(|bytes| fixed_hash(&bytes)).transpose()
}

/// Create a master: insert its seed once. Refuses an existing entry.
///
/// # Errors
/// Refuses a malformed reference and any insert failure.
pub(crate) fn store(
    cells: &dyn AgentMasterCells,
    reference: &str,
    master: &MasterKey,
) -> Result<(), SdkError> {
    require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
    let seed = master.vault_seed();
    cells.insert_item(reference, &*seed)
}

/// Issue the certificate for `request` and record its hash, or return the certificate already
/// recorded for the same request (signing is deterministic). Any other recorded range refuses.
/// Nothing is returned unless the record is written or already equal.
///
/// # Errors
/// `custody_key_unavailable` for a missing seed or history, a refused rebind, a recorded range
/// with a different hash, or an insert failure. `CustodyVault(Corrupt)` for a malformed record.
pub(crate) fn certify(
    cells: &dyn AgentMasterCells,
    reference: &str,
    request: AgentMasterRequest,
) -> Result<Envelope<MasterCertificate>, SdkError> {
    require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
    let raw = cells.read_item(reference)?.ok_or_else(agent_key_unavailable)?;
    let master = MasterKey::from_vault_seed(&seed(&raw)?);
    let range = request.range;
    let last_certificate_hash = match request.purpose {
        AgentMasterPurpose::Create => None,
        AgentMasterPurpose::Rebind => {
            let prior = range.checked_sub(1).ok_or_else(agent_key_unavailable)?;
            let stored =
                recorded_hash(cells, reference, prior)?.ok_or_else(agent_key_unavailable)?;
            Some(encode_base64url(stored))
        }
    };
    let item = AgentMasterItem { master, last_certificate_hash };
    let (certificate, hash) =
        certify_agent_master(&item, request).map_err(|_| agent_key_unavailable())?;
    let computed = fixed_hash(&decode_base64url(&hash).map_err(|_| invalid())?)?;
    let item_reference = certificate_reference(reference, range)?;
    if let Some(recorded) = cells.read_item(&item_reference)? {
        return if fixed_hash(&recorded)? == computed {
            Ok(certificate)
        } else {
            Err(agent_key_unavailable())
        };
    }
    cells.insert_item(&item_reference, &computed)?;
    Ok(certificate)
}

/// Remove every recorded certificate item for ranges `1..=last_range`, then the seed. The
/// certificates go first, so a failed call can be repeated while the seed still exists.
///
/// # Errors
/// Refuses a malformed reference or a `last_range` beyond the protocol range, and returns
/// provider failures.
pub(crate) fn delete(
    cells: &dyn AgentMasterCells,
    reference: &str,
    last_range: u64,
) -> Result<(), SdkError> {
    require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
    if last_range > MAX_RANGE {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    for range in 1..=last_range {
        cells.remove_item(&certificate_reference(reference, range)?)?;
    }
    cells.remove_item(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_reference_grammar_is_canonical() -> Result<(), SdkError> {
        let master = encode_base64url([9_u8; 32]);
        let reference = format!("{AGENT_MASTER_PREFIX}{master}");
        let item = certificate_reference(&reference, 2)?;
        assert_eq!(item, format!("{AGENT_MASTER_CERT_PREFIX}{master}:2"));
        assert!(valid_certificate_reference(&item), "the builder output is canonical");
        assert!(certificate_reference(&reference, 0).is_err(), "range zero refuses");
        assert!(
            certificate_reference(&reference, MAX_RANGE + 1).is_err(),
            "range past max refuses"
        );
        assert!(certificate_reference("agent-master:short", 1).is_err(), "bad id refuses");
        assert!(!valid_certificate_reference(&format!("{AGENT_MASTER_CERT_PREFIX}{master}:02")));
        assert!(!valid_certificate_reference(&format!("{AGENT_MASTER_CERT_PREFIX}{master}:0")));
        assert!(!valid_certificate_reference(&format!("{AGENT_MASTER_CERT_PREFIX}{master}:x")));
        assert!(!valid_certificate_reference(&format!("{AGENT_MASTER_CERT_PREFIX}{master}")));
        Ok(())
    }

    #[test]
    fn seed_and_hash_lengths_are_fixed() -> Result<(), SdkError> {
        assert!(seed(&[0_u8; 31]).is_err(), "a short seed is corrupt");
        assert!(seed(&[0_u8; 33]).is_err(), "a long seed is corrupt");
        assert_eq!(*seed(&[5_u8; 32])?, [5_u8; 32]);
        assert!(fixed_hash(&[0_u8; 31]).is_err(), "a short hash is corrupt");
        Ok(())
    }
}
