// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The host owns persistent key provisioning; an omitted key is process-local.
use crate::SdkError;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn load(root: &Path, path: Option<&Path>) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let Some(path) = path else { return Ok(Zeroizing::new(ramflux_crypto::random_32()?)) };
    let resolved = std::fs::canonicalize(path)?;
    if !path.is_absolute()
        || resolved.starts_with(root)
        || std::fs::symlink_metadata(path)?.file_type().is_symlink()
    {
        return Err(SdkError::LocalBus("diagnostic key location refused".into()));
    }
    let mut file = crate::platform::fs::open_read_only_no_follow(&resolved)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(SdkError::LocalBus("diagnostic key size refused".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(SdkError::LocalBus("diagnostic key permissions refused".into()));
        }
    }
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(key.as_mut())?;
    Ok(key)
}
