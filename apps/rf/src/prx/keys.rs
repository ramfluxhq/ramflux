// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! CLI provider key: the OS keychain, then stdin. The bus never uses this path.

use super::refused;
use crate::RfError;
use crate::keychain::{KeyStore, KeychainSecret, OsKeychain};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn provider_key(provider: &str) -> Result<Zeroizing<String>, RfError> {
    if !label_ok(provider) {
        return Err(refused("field_invalid", "provider"));
    }
    let account = format!("prx-provider:{provider}");
    let store = OsKeychain;
    if let Some(secret) = store.load(&account)? {
        let key = Zeroizing::new(secret.passphrase.clone());
        if !key.trim().is_empty() {
            return Ok(key);
        }
    }
    let key = read_stdin_key()?;
    store.store(&account, &KeychainSecret::new((*key).clone(), None))?;
    Ok(key)
}

/// The provider key from stdin alone, for the bus path: no keychain read and no keychain write.
pub(crate) fn stdin_provider_key(provider: &str) -> Result<Zeroizing<String>, RfError> {
    if !label_ok(provider) {
        return Err(refused("field_invalid", "provider"));
    }
    read_stdin_key()
}

fn read_stdin_key() -> Result<Zeroizing<String>, RfError> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut stdin = std::io::stdin();
    let mut chunk = Zeroizing::new([0_u8; 4096]);
    loop {
        let n = stdin.read(&mut chunk[..])?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > 64 * 1024 + 1 {
            return Err(refused("input_invalid", "provider key too large"));
        }
        buf.extend_from_slice(&chunk[..n]);
        chunk[..n].zeroize();
    }
    while buf.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') {
        buf.pop();
    }
    if buf.is_empty() || buf.iter().all(u8::is_ascii_whitespace) {
        return Err(refused("input_missing", "provider key on stdin"));
    }
    let taken = std::mem::take(&mut *buf);
    match String::from_utf8(taken) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(refused("input_invalid", "provider key is not utf-8"))
        }
    }
}

fn label_ok(value: &str) -> bool {
    let Some((first, rest)) = value.as_bytes().split_first() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
