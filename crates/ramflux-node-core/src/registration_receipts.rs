// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration proof receipts expire with their signed proof; live receipts are never evicted.
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::VecDeque;

pub(crate) const REGISTRATION_PROOF_LIMIT: usize = 4096;
pub(crate) const REGISTRATION_ROOT_LIMIT: usize = 128;
pub(crate) const REGISTRATION_SOURCE_LIMIT: usize = 256;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RegistrationReceipt {
    pub(crate) key: String,
    pub(crate) expires_at: i64,
    pub(crate) root: String,
    pub(crate) source: String,
}
pub(crate) fn load_receipts<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<VecDeque<RegistrationReceipt>, D::Error> {
    VecDeque::<RegistrationReceipt>::deserialize(de)
}

/// Per-source admission is configurable for large shared NATs; invalid settings fail closed.
pub(crate) fn registration_source_limit() -> Result<usize, crate::NodeCoreError> {
    let value = match crate::environment::var("RAMFLUX_REGISTRATION_SOURCE_RECEIPT_LIMIT") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(crate::NodeCoreError::Unauthorized(
                "invalid registration source receipt limit".into(),
            ));
        }
    };
    parse_source_limit(value.as_deref())
}
fn parse_source_limit(value: Option<&str>) -> Result<usize, crate::NodeCoreError> {
    match value {
        None => Ok(REGISTRATION_SOURCE_LIMIT),
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=REGISTRATION_PROOF_LIMIT).contains(n))
            .ok_or_else(|| {
                crate::NodeCoreError::Unauthorized(
                    "invalid registration source receipt limit".into(),
                )
            }),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_receipts_refuse_unbounded_or_ownerless_old_shapes()
    -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Rows {
            #[serde(deserialize_with = "load_receipts")]
            receipts: VecDeque<RegistrationReceipt>,
        }
        let current: Rows = serde_json::from_value(
            serde_json::json!({"receipts":[{"key":"proof","expires_at":100,"root":"root","source":"source"}]}),
        )?;
        assert_eq!(current.receipts.len(), 1);
        for row in [
            serde_json::json!("bare-proof"),
            serde_json::json!({"key":"proof","expires_at":null,"root":null,"source":null}),
            serde_json::json!({"key":"proof","expires_at":100}),
        ] {
            assert!(serde_json::from_value::<Rows>(serde_json::json!({"receipts":[row]})).is_err());
        }
        Ok(())
    }
    #[test]
    fn shared_nat_override_is_bounded_and_invalid_values_fail_closed() {
        assert!(matches!(parse_source_limit(None), Ok(256)));
        assert!(matches!(parse_source_limit(Some("1024")), Ok(1024)));
        for value in ["0", "4097", "", "unbounded", "-1"] {
            assert!(parse_source_limit(Some(value)).is_err());
        }
    }
}
