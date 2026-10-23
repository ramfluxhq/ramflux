// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Erases owned request values immediately after encoding, including seeds encoded as arrays.
use serde_json::Value;
use zeroize::Zeroize;
pub(super) fn wipe(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                wipe(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                wipe(value);
            }
        }
        Value::Number(_) => *value = Value::Number(0.into()),
        Value::Bool(value) => *value = false,
        Value::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wipes_nested_passphrases_and_seed_bytes_after_serialization() -> Result<(), serde_json::Error>
    {
        let mut value = serde_json::json!({"passphrase":"secret","create":{"root_seed":[41,42,43]},"restore":{"account_secret":"restore-secret"}});
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&value)?);
        assert!(String::from_utf8_lossy(&bytes).contains("restore-secret"));
        wipe(&mut value);
        assert_eq!(
            value,
            serde_json::json!({"passphrase":"","create":{"root_seed":[0,0,0]},"restore":{"account_secret":""}})
        );
        Ok(())
    }
}
