// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration proof receipts expire with their signed proof; live receipts are never evicted.
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::VecDeque;

pub(crate) const REGISTRATION_PROOF_LIMIT: usize = 4096;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RegistrationReceipt {
    pub(crate) key: String,
    pub(crate) expires_at: Option<i64>,
}
pub(crate) fn load_receipts<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<VecDeque<RegistrationReceipt>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Current(RegistrationReceipt),
        Legacy(String),
    }
    let stored = Vec::<Stored>::deserialize(de)?;
    // No truncation: historical live receipts remain fences, even above a newer capacity.
    Ok(stored
        .into_iter()
        .map(|receipt| match receipt {
            Stored::Current(receipt) => receipt,
            Stored::Legacy(key) => RegistrationReceipt { key, expires_at: None },
        })
        .collect())
}
