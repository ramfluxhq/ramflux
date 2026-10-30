// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable epoch fragments and signed records, never a mutable prepared-head pointer.

use super::{
    invalid,
    operation_lock::OperationLock,
    private_fs::{self, PrivateDir},
};
use crate::RfError;
use ramflux_crypto::custody::VerifiedNodeRecord;
use ramflux_protocol::{
    custody::{Envelope, NodeIdentityRecord, decode, object_hash},
    encode_base64url,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, RfError> {
    let bytes = private_fs::read_input(path, 128, true)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("node seed must be base64url"))?;
    let decoded = Zeroizing::new(
        ramflux_protocol::decode_base64url(text.trim())
            .map_err(|_| invalid("node seed must be canonical base64url"))?,
    );
    Ok(Zeroizing::new(
        decoded.as_slice().try_into().map_err(|_| invalid("node seed must contain 32 bytes"))?,
    ))
}

pub(super) fn read_deployed(path: &Path) -> Result<Envelope<NodeIdentityRecord>, RfError> {
    decode(&private_fs::read_input(path, 512 * 1024, false)?, 512 * 1024)
        .map_err(|error| invalid(error.to_string()))
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(super) struct Destination {
    root: PathBuf,
    directory: PrivateDir,
    records: PrivateDir,
    _lock: OperationLock,
}

impl Destination {
    pub(super) fn open(path: &Path, now: u64) -> Result<Self, RfError> {
        let directory = PrivateDir::open(path)?;
        let root = directory.canonical_path(path)?;
        let lock = OperationLock::acquire(&directory, now)?;
        directory.remove_abandoned_temporaries()?;
        let records = directory.child("records")?;
        records.remove_abandoned_temporaries()?;
        directory.sync()?;
        Ok(Self { root, directory, records, _lock: lock })
    }

    /// Returns whether another preparation of the same epoch must use a hash suffix.
    pub(super) fn check_preparation(
        &self,
        previous: Option<&VerifiedNodeRecord>,
        force: bool,
    ) -> Result<bool, RfError> {
        let names = self.directory.names()?;
        let Some(previous) = previous else {
            if names.iter().any(|name| !matches!(name.as_str(), "." | ".." | ".lock" | "records")) {
                return Err(invalid(
                    "custody output already exists; use custody-renew --deployed-record with the installed record",
                ));
            }
            return Ok(false);
        };
        let epoch = previous
            .envelope()
            .body
            .epoch
            .checked_add(1)
            .ok_or_else(|| invalid("record epoch overflow"))?;
        let primary = format!("custody-epoch-{epoch}.env");
        let prefix = format!("custody-epoch-{epoch}-");
        let mut prepared = names.iter().any(|name| {
            name == &primary
                || (name.starts_with(&prefix)
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("env")))
        });
        // Retain and recognize an existing r2 fragment, but never use it as the predecessor.
        if self.directory.exists("custody.env")? {
            let legacy = self.legacy_record()?;
            prepared |= legacy.body.epoch == epoch
                && legacy.body.previous_record_hash.as_deref() == Some(previous.hash());
        }
        if prepared && !force {
            return Err(invalid(
                "DEMO_CUSTODY_ALREADY_PREPARED: a successor of the deployed epoch already exists; deploy it first or use --force-new-proxy to retain another immutable preparation",
            ));
        }
        Ok(prepared)
    }

    fn legacy_record(&self) -> Result<Envelope<NodeIdentityRecord>, RfError> {
        let bytes = self.directory.read("custody.env", 16 * 1024, true)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid custody.env"))?;
        let raw = text
            .lines()
            .find_map(|line| line.strip_prefix("RAMFLUX_CUSTODY_NODE_RECORD_FILE="))
            .ok_or_else(|| invalid("custody.env has no record path"))?;
        let decoded = raw
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .ok_or_else(|| invalid("invalid custody.env record path"))?
            .replace("'\\''", "'");
        if quote(&decoded) != raw {
            return Err(invalid("invalid custody.env record path"));
        }
        let path = Path::new(&decoded);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid custody.env record filename"))?;
        let record = decode::<Envelope<NodeIdentityRecord>>(
            &self.records.read(name, 512 * 1024, false)?,
            512 * 1024,
        )
        .map_err(|error| invalid(error.to_string()))?;
        let hash = object_hash(&record).map_err(|error| invalid(error.to_string()))?;
        if name != format!("{hash}.json") {
            return Err(invalid("custody record content does not match its retained hash"));
        }
        Ok(record)
    }

    fn retain_record(&self, node: &VerifiedNodeRecord) -> Result<(), RfError> {
        let name = format!("{}.json", node.hash());
        let bytes = ramflux_protocol::canonical_json_bytes(node.envelope())
            .map_err(|error| invalid(error.to_string()))?;
        if self.records.exists(&name)? {
            if *self.records.read(&name, 512 * 1024, false)? != bytes {
                return Err(invalid("custody retained record differs from its authenticated hash"));
            }
        } else {
            self.records.write_immutable(&name, &bytes)?;
        }
        self.records.sync()
    }

    pub(super) fn publish(
        &self,
        node: &VerifiedNodeRecord,
        seed: &[u8; 32],
        previous: Option<&VerifiedNodeRecord>,
        repeated: bool,
    ) -> Result<PathBuf, RfError> {
        self.directory.check_path(&self.root)?;
        self.records.check_child(&self.directory, "records")?;
        if let Some(previous) = previous {
            self.retain_record(previous)?;
        }
        self.retain_record(node)?;
        let path = self.root.join("records").join(format!("{}.json", node.hash()));
        let path_text = path.to_str().ok_or_else(|| invalid("invalid record path"))?;
        let seed = Zeroizing::new(encode_base64url(seed));
        let fragment = Zeroizing::new(format!(
            "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY={}\nRAMFLUX_CUSTODY_NODE_RECORD_FILE={}\nRAMFLUX_CUSTODY_PROXY_SIGNING_SEED={}\n",
            node.envelope().body.node_signing_public_key,
            quote(path_text),
            *seed,
        ));
        let epoch = node.envelope().body.epoch;
        let name = if repeated {
            format!("custody-epoch-{epoch}-{}.env", node.hash())
        } else {
            format!("custody-epoch-{epoch}.env")
        };
        self.directory.check_path(&self.root)?;
        self.directory.write_immutable(&name, fragment.as_bytes())?;
        // Backward-compatible initial-install fragment only; renewal never rewrites it.
        if previous.is_none() {
            self.directory.write_immutable("custody.env", fragment.as_bytes())?;
        }
        self.directory.check_path(&self.root)?;
        self.records.check_child(&self.directory, "records")?;
        Ok(self.root.join(name))
    }
}
