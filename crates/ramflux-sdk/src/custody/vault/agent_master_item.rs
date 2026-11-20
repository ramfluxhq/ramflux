// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Vault item codec of `agent-master:<id>`: the 32-byte master seed, a presence flag, and the hash
//! of the last certificate issued for the master. Only vault implementations see the seed; the
//! item is never returned by any bus, C ABI or CLI surface.
use crate::SdkError;
use crate::custody::CustodyVaultReason;
use ramflux_crypto::custody::{AgentMasterItem, MasterKey};
use ramflux_protocol::{decode_base64url, encode_base64url};
use zeroize::Zeroizing;

/// Fixed item length: seed (32) | presence flag (1) | last certificate hash (32, zero when absent).
pub(crate) const AGENT_MASTER_ITEM_BYTES: usize = 65;
const FLAG_ABSENT: u8 = 0;
const FLAG_PRESENT: u8 = 1;

fn invalid() -> SdkError {
    SdkError::CustodyVault(CustodyVaultReason::Corrupt)
}

/// Encode a master and the hash of its last certificate (`None` before any certificate).
/// The result is zeroized on drop because it holds the seed.
/// # Errors
/// Refuses a last-certificate hash that is not a canonical 32-byte value.
pub(crate) fn encode(
    master: &MasterKey,
    last_certificate_hash: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let seed = master.vault_seed();
    let mut out = Zeroizing::new(Vec::with_capacity(AGENT_MASTER_ITEM_BYTES));
    out.extend_from_slice(&*seed);
    match last_certificate_hash {
        None => {
            out.push(FLAG_ABSENT);
            out.extend_from_slice(&[0_u8; 32]);
        }
        Some(hash) => {
            let raw = decode_base64url(hash).map_err(|_| invalid())?;
            if raw.len() != 32 || encode_base64url(&raw) != hash {
                return Err(invalid());
            }
            out.push(FLAG_PRESENT);
            out.extend_from_slice(&raw);
        }
    }
    Ok(out)
}

/// Decode an item, refusing any length, presence flag or non-zero absent hash field.
/// # Errors
/// `CustodyVault(Corrupt)` for every malformed item.
pub(crate) fn decode(bytes: &[u8]) -> Result<AgentMasterItem, SdkError> {
    if bytes.len() != AGENT_MASTER_ITEM_BYTES {
        return Err(invalid());
    }
    let seed = Zeroizing::new(
        bytes.get(..32).and_then(|raw| <[u8; 32]>::try_from(raw).ok()).ok_or_else(invalid)?,
    );
    let tail = bytes.get(32..).ok_or_else(invalid)?;
    let last_certificate_hash = match tail.split_first() {
        Some((&FLAG_ABSENT, rest)) if rest.iter().all(|byte| *byte == 0) => None,
        Some((&FLAG_PRESENT, rest)) => Some(encode_base64url(rest)),
        _ => return Err(invalid()),
    };
    Ok(AgentMasterItem { master: MasterKey::from_vault_seed(&seed), last_certificate_hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_layout_round_trips_absent_and_present_hashes() -> Result<(), SdkError> {
        let master = MasterKey::generate().map_err(|_| invalid())?;
        let absent = encode(&master, None)?;
        assert_eq!(absent.len(), AGENT_MASTER_ITEM_BYTES, "item length is fixed");
        let decoded = decode(&absent)?;
        assert_eq!(decoded.master.public_key(), master.public_key(), "seed round trip");
        assert!(decoded.last_certificate_hash.is_none(), "absent hash stays absent");
        let hash = encode_base64url([7_u8; 32]);
        let present = encode(&master, Some(&hash))?;
        let decoded = decode(&present)?;
        assert_eq!(decoded.last_certificate_hash.as_deref(), Some(hash.as_str()));
        Ok(())
    }

    #[test]
    fn item_decode_refuses_bad_flag_and_length() -> Result<(), SdkError> {
        let master = MasterKey::generate().map_err(|_| invalid())?;
        let mut bytes = encode(&master, None)?;
        bytes[32] = 9;
        assert!(decode(&bytes).is_err(), "an unknown presence flag must refuse");
        assert!(decode(&bytes[..64]).is_err(), "a short item must refuse");
        Ok(())
    }

    #[test]
    fn encode_refuses_a_non_canonical_hash() -> Result<(), SdkError> {
        let master = MasterKey::generate().map_err(|_| invalid())?;
        assert!(encode(&master, Some("not-a-hash")).is_err(), "a malformed hash must refuse");
        Ok(())
    }
}
