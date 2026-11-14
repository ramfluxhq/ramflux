// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded-cache encrypted comparison rows, independent of the immutable contribution file.
use crate::{AccountDbKey, StorageError};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
pub(super) struct VerificationFile(PathBuf);
impl VerificationFile {
    pub(super) fn create(directory: &Path) -> Result<Self, StorageError> {
        let path = directory.join(format!(
            "verify_{}.db",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        super::super::stage::create_file(&path)?.sync_all()?;
        Ok(Self(path))
    }
    pub(super) fn attach(
        &self,
        db: &rusqlite::Connection,
        key: &AccountDbKey,
    ) -> Result<(), StorageError> {
        let hex = Zeroizing::new(key.sqlcipher_hex());
        let encoded = Zeroizing::new(format!("x'{}'", hex.as_str()));
        db.execute(
            "ATTACH DATABASE ?1 AS verifier KEY ?2",
            rusqlite::params![
                self.0.to_str().ok_or(StorageError::AuthorizationRejected)?,
                encoded.as_str()
            ],
        )?;
        db.execute_batch("PRAGMA verifier.journal_mode=DELETE; PRAGMA verifier.cache_size=-2048; PRAGMA verifier.synchronous=FULL; PRAGMA verifier.secure_delete=ON;")?;
        Ok(())
    }
}
impl Drop for VerificationFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("db-journal"));
    }
}
