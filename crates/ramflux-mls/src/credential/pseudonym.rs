// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `0xF0D2` pseudonym credential: `{version = 1, pseudonym_pk[32]}`.
//!
//! The key is fresh per `KeyPackage` and group, never published at the home node, and valid only
//! when it equals the leaf signature key.

use openmls::prelude::{Credential, CredentialType};

use crate::{CREDENTIAL_TYPE_PSEUDONYM, MlsError};

/// Format version of the pseudonym credential (the device credential is at v2).
const PSEUDONYM_VERSION: u8 = 1;

/// Encoded length: version byte plus key.
const ENCODED_BYTES: usize = 33;

/// Build the credential for a pseudonym key.
#[must_use]
pub fn issue(pseudonym_pk: &[u8; 32]) -> Credential {
    let mut content = Vec::with_capacity(ENCODED_BYTES);
    content.push(PSEUDONYM_VERSION);
    content.extend_from_slice(pseudonym_pk);
    Credential::new(CredentialType::Other(CREDENTIAL_TYPE_PSEUDONYM), content)
}

/// Verify the credential content against the leaf signature key and return the pseudonym key.
pub(crate) fn verify(content: &[u8], leaf_sig_pk: &[u8; 32]) -> Result<[u8; 32], MlsError> {
    let (version, key) = content
        .split_first()
        .ok_or_else(|| MlsError::CredentialRejected("empty pseudonym credential".to_owned()))?;
    if *version != PSEUDONYM_VERSION {
        return Err(MlsError::CredentialRejected("pseudonym credential version".to_owned()));
    }
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| MlsError::CredentialRejected("pseudonym credential length".to_owned()))?;
    if &key != leaf_sig_pk {
        return Err(MlsError::CredentialRejected(
            "pseudonym key differs from the leaf signature key".to_owned(),
        ));
    }
    Ok(key)
}
