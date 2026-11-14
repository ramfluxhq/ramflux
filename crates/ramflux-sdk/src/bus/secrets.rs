// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Erases owned request values immediately after encoding, including seeds encoded as arrays.
use serde_json::Value;
use zeroize::Zeroize;
pub(super) fn wipe(value: &mut Value) {
    match value {
        Value::String(value) => wipe_string(value),
        Value::Array(values) => {
            for value in values {
                wipe(value);
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                wipe_string(&mut key);
                wipe(&mut value);
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
        assert_eq!(value, serde_json::json!({}), "wiping retires keys as well as secret values");
        Ok(())
    }
}

fn wipe_string(value: &mut String) {
    #[cfg(test)]
    let observed = canary::observed(value);
    #[cfg(test)]
    let len = value.len();
    value.zeroize();
    #[cfg(test)]
    if observed {
        canary::record(value, len);
    }
}
#[cfg(test)]
pub(crate) mod canary {
    pub const TEXT: &str = "ABI_WIPE_CANARY_R5_38D79A";
    thread_local! {static STATE:std::cell::Cell<(bool,usize,bool)>=const{std::cell::Cell::new((false,0,true))};}
    pub fn enable() {
        STATE.with(|s| s.set((true, 0, true)));
    }
    pub fn finish() -> (usize, bool) {
        STATE.with(|s| {
            let (_, n, ok) = s.replace((false, 0, true));
            (n, ok)
        })
    }
    pub(super) fn observed(value: &str) -> bool {
        STATE.with(|s| s.get().0) && value.contains(TEXT)
    }
    #[allow(
        unsafe_code,
        reason = "Test-only observation of zeroized, still-owned allocation bytes"
    )]
    pub(super) fn record(value: &String, len: usize) {
        let ok = if value.capacity() >= len {
            // SAFETY: the live String retains its allocation; zeroize initialized every
            // byte through the old length before clearing the logical length.
            unsafe { std::slice::from_raw_parts(value.as_ptr(), len) }.iter().all(|b| *b == 0)
        } else {
            false
        };
        STATE.with(|s| {
            let (active, n, prior) = s.get();
            s.set((active, n + 1, prior && ok));
        });
    }
}
