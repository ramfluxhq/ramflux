// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original primary signing is fenced durably before a cooperative submission escapes.
use crate::SdkError;
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{DeviceRef, DeviceSet, Envelope},
    parse_i_json,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    ops::Deref,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const LIMIT: u64 = 4096;
/// The key erases before the cross-process signing barrier is released. Keep this
/// owner within local signing work; release it before publishing any public result.
pub(crate) struct PrimarySigningLease {
    key: SelfSigningKey,
    _lock: File,
}
impl Deref for PrimarySigningLease {
    type Target = SelfSigningKey;
    fn deref(&self) -> &SelfSigningKey {
        &self.key
    }
}
impl PrimarySigningLease {
    pub(super) fn new(key: SelfSigningKey, lock: File) -> Self {
        Self { key, _lock: lock }
    }
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmittedPrimaryFence {
    pub(crate) account_id: String,
    pub(crate) operation_id: String,
    pub(crate) base_record_hash: String,
    pub(crate) candidate_hash: String,
    pub(crate) source_ref: DeviceRef,
    pub(crate) old_self_key: String,
}
fn wrong() -> SdkError {
    SdkError::PairingCode("PublicationPending")
}
fn path(dir: &Path) -> PathBuf {
    dir.join("pairing-install/.primary-transfer-fence.json")
}
fn validate(fence: &SubmittedPrimaryFence) -> Result<(), SdkError> {
    super::valid_id(&fence.account_id)?;
    for value in [
        &fence.operation_id,
        &fence.base_record_hash,
        &fence.candidate_hash,
        &fence.source_ref.account_anchor,
        &fence.old_self_key,
    ] {
        let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| wrong())?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != *value {
            return Err(wrong());
        }
    }
    Ok(())
}
fn read(dir: &Path) -> Result<Option<SubmittedPrimaryFence>, SdkError> {
    let file = match crate::platform::fs::open_owner_only_no_follow(&path(dir)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.is_file() || file.metadata()?.len() > LIMIT {
        return Err(wrong());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(wrong());
    }
    let fence: SubmittedPrimaryFence = parse_i_json(&bytes)?;
    validate(&fence)?;
    Ok(Some(fence))
}
pub(crate) fn lock(dir: &Path) -> Result<File, SdkError> {
    let lock = crate::platform::fs::open_owner_only_read_write(&dir.join(".primary-signing.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match crate::platform::fs::try_lock_exclusive(&lock) {
            Ok(()) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SdkError::PairingCode("Busy"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
}
/// Caller holds the signing barrier before any old-primary vault request.
pub(crate) fn require_available(
    dir: &Path,
    id: &str,
    current: &Envelope<DeviceSet>,
) -> Result<(), SdkError> {
    let Some(fence) = read(dir)? else { return Ok(()) };
    if fence.account_id != id || fence.source_ref.account_anchor != current.body.account_anchor {
        return Err(wrong());
    }
    // A positively verified later primary key does not inherit the old key's fence.
    // Ordinary role/current-head checks still run before this predicate and vault use.
    if fence.old_self_key == current.body.master_certificate.body.self_signing_public_key {
        return Err(SdkError::PairingCode("Busy"));
    }
    Ok(())
}
/// Persist before Submitted while holding the same barrier as every primary signer.
/// An uncertain write leaves the fence, exact candidate and all private keys retained.
pub(crate) fn retain_submitted(
    dir: &Path,
    fence: &SubmittedPrimaryFence,
) -> Result<File, SdkError> {
    validate(fence)?;
    let lock = lock(dir)?;
    if let Some(existing) = read(dir)? {
        if existing == *fence {
            return Ok(lock);
        }
        if existing.account_id != fence.account_id
            || existing.source_ref.account_anchor != fence.source_ref.account_anchor
            || existing.old_self_key == fence.old_self_key
        {
            return Err(wrong());
        }
    }
    let directory = dir.join("pairing-install");
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(wrong()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::platform::fs::create_owner_only_dir(&directory)?;
            File::open(dir)?.sync_all()?;
        }
        Err(e) => return Err(e.into()),
    }
    let temporary = directory.join(format!(
        ".primary-fence-{}.tmp",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let mut file = crate::platform::fs::create_new_owner_only(&temporary)?;
    let result = (|| -> Result<(), SdkError> {
        file.write_all(&canonical_json_bytes(fence)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path(dir))?;
        File::open(&directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(lock)
}
