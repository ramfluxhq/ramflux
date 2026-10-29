// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private immutable record files and one atomic publication point for the env/seed pair.

use super::invalid;
use crate::RfError;
use ramflux_crypto::custody::VerifiedNodeRecord;
use ramflux_protocol::{
    custody::{Envelope, NodeIdentityRecord, decode, object_hash},
    encode_base64url,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, RfError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid("custody input must be a regular file, never a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !matches!(metadata.permissions().mode() & 0o777, 0o600 | 0o400 | 0o640 | 0o440) {
            return Err(invalid("custody input permissions must be 0600, 0400, 0640 or 0440"));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("custody input exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, RfError> {
    let bytes = read_private(path, 128)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("node seed must be base64url"))?;
    let decoded = Zeroizing::new(
        ramflux_protocol::decode_base64url(text.trim())
            .map_err(|_| invalid("node seed must be canonical base64url"))?,
    );
    Ok(Zeroizing::new(
        decoded.as_slice().try_into().map_err(|_| invalid("node seed must contain 32 bytes"))?,
    ))
}

fn private_directory(path: &Path) -> Result<(), RfError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(invalid("custody output must be a private directory, never a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(invalid("custody output directory must have mode 0700"));
        }
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<File, RfError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(file)
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(super) struct Destination {
    root: PathBuf,
    _lock: File,
}

impl Destination {
    pub(super) fn open(path: &Path) -> Result<Self, RfError> {
        private_directory(path)?;
        let root = path.canonicalize()?;
        if root.to_str().is_none_or(|text| text.contains(['\n', '\r'])) {
            return Err(invalid("custody output path must be UTF-8 without line breaks"));
        }
        let lock = write_new(&root.join(".lock"), b"")?;
        Ok(Self { root, _lock: lock })
    }

    pub(super) fn current_record(&self) -> Result<Option<Envelope<NodeIdentityRecord>>, RfError> {
        let env = self.root.join("custody.env");
        if !env.try_exists()? {
            return Ok(None);
        }
        let bytes = read_private(&env, 16 * 1024)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid custody.env"))?;
        let raw = text
            .lines()
            .find_map(|line| line.strip_prefix("RAMFLUX_CUSTODY_NODE_RECORD_FILE="))
            .ok_or_else(|| invalid("custody.env has no predecessor record"))?;
        let decoded = raw
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .ok_or_else(|| invalid("invalid custody.env record path"))?
            .replace("'\\''", "'");
        if quote(&decoded) != raw {
            return Err(invalid("invalid custody.env record path"));
        }
        let path = PathBuf::from(decoded);
        if path.parent() != Some(self.root.join("records").as_path()) {
            return Err(invalid("custody predecessor must be in this output directory"));
        }
        let record =
            decode::<Envelope<NodeIdentityRecord>>(&read_private(&path, 512 * 1024)?, 512 * 1024)
                .map_err(|error| invalid(error.to_string()))?;
        let hash = object_hash(&record).map_err(|error| invalid(error.to_string()))?;
        if path != self.root.join("records").join(format!("{hash}.json")) {
            return Err(invalid("custody predecessor content does not match its retained hash"));
        }
        Ok(Some(record))
    }

    pub(super) fn publish(
        &self,
        node: &VerifiedNodeRecord,
        seed: &[u8; 32],
    ) -> Result<PathBuf, RfError> {
        let records = self.root.join("records");
        private_directory(&records)?;
        let path = records.join(format!("{}.json", node.hash()));
        let bytes = ramflux_protocol::canonical_json_bytes(node.envelope())
            .map_err(|error| invalid(error.to_string()))?;
        write_new(&path, &bytes)?;
        File::open(&records)?.sync_all()?;
        let path_text = path.to_str().ok_or_else(|| invalid("invalid record path"))?;
        let seed = Zeroizing::new(encode_base64url(seed));
        let fragment = Zeroizing::new(format!(
            "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY={}\nRAMFLUX_CUSTODY_NODE_RECORD_FILE={}\nRAMFLUX_CUSTODY_PROXY_SIGNING_SEED={}\n",
            node.envelope().body.node_signing_public_key,
            quote(path_text),
            *seed,
        ));
        let temporary = self.root.join(format!(".custody-env-{}", node.hash()));
        write_new(&temporary, fragment.as_bytes())?;
        let destination = self.root.join("custody.env");
        fs::rename(temporary, &destination)?;
        File::open(&self.root)?.sync_all()?;
        Ok(destination)
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.root.join(".lock"));
    }
}
