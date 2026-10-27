// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable public discovery evidence, indexed by hash/key instead of rewriting history.
use crate::SdkError;
use ramflux_crypto::custody::{NodeKeyBinding, VerifiedNodeRecord, verify_node_identity_record};
use ramflux_protocol::custody::{Envelope, NodeIdentityRecord};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(super) struct NodePins {
    root: PathBuf,
    node_id: String,
    public: String,
}
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
fn read<T: for<'de> serde::Deserialize<'de> + serde::Serialize>(
    path: &Path,
    limit: usize,
) -> Result<T, SdkError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    Ok(ramflux_protocol::custody::decode(&bytes, limit)?)
}
fn create(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read(path)? != bytes {
                return Err(invalid());
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
impl NodePins {
    pub(super) fn new(root: &Path, node_id: &str, public: &str) -> Result<Self, SdkError> {
        let id = ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.node_pin_path.v1",
            node_id.as_bytes(),
        );
        let root = root.join("custody_network").join(id);
        fs::create_dir_all(&root)?;
        for name in ["history", "keys", "publics"] {
            fs::create_dir_all(root.join(name))?;
        }
        Ok(Self { root, node_id: node_id.into(), public: public.into() })
    }
    pub(super) fn current_hash(&self) -> Result<Option<String>, SdkError> {
        let _lock = self.lock()?;
        let head = self.root.join("head.json");
        if head.try_exists()? { Ok(Some(read(&head, 1024)?)) } else { Ok(None) }
    }
    pub(super) fn observe(
        &self,
        record: &Envelope<NodeIdentityRecord>,
        now: u64,
    ) -> Result<VerifiedNodeRecord, SdkError> {
        let next = verify_node_identity_record(record, &self.node_id, &self.public, now)?;
        let _lock = self.lock()?;
        let mut known = std::collections::BTreeMap::new();
        let mut publics = std::collections::BTreeMap::new();
        let entries: Vec<_> = next.key_bindings().collect();
        for (id, binding) in &entries {
            let public = &binding.public_key;
            let path = self.root.join("keys").join(id);
            if path.try_exists()? {
                known.insert((*id).to_owned(), read::<NodeKeyBinding>(&path, 4096)?);
            }
            let path = self.root.join("publics").join(public);
            if path.try_exists()? {
                publics.insert((*public).clone(), read::<String>(&path, 1024)?);
            }
        }
        let head = self.root.join("head.json");
        if head.try_exists()? {
            let hash: String = read(&head, 1024)?;
            let old = self.history(&hash, now)?;
            old.verify_successor(&next, |id| known.get(id).cloned(), |p| publics.get(p).cloned())?;
        }
        create(
            &self.root.join("history").join(next.hash()),
            &ramflux_protocol::canonical_json_bytes(record)?,
        )?;
        for (id, binding) in entries {
            let public = &binding.public_key;
            create(&self.root.join("keys").join(id), &serde_json::to_vec(&binding)?)?;
            create(&self.root.join("publics").join(public), &serde_json::to_vec(&id)?)?;
        }
        let temp = self.root.join(format!(
            ".head-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        create(&temp, &serde_json::to_vec(next.hash())?)?;
        fs::rename(temp, head)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(next)
    }
    fn history(&self, hash: &str, now: u64) -> Result<VerifiedNodeRecord, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(hash).map_err(|_| invalid())?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != hash {
            return Err(invalid());
        }
        let record: Envelope<NodeIdentityRecord> =
            read(&self.root.join("history").join(hash), 512 * 1024)?;
        let record = verify_node_identity_record(&record, &self.node_id, &self.public, now)?;
        if record.hash() != hash {
            return Err(invalid());
        }
        Ok(record)
    }
    fn lock(&self) -> Result<fs::File, SdkError> {
        use std::os::unix::fs::OpenOptionsExt;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.root.join(".pins.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }
}

impl NodePins {
    pub(super) fn observe_peer(
        &self,
        publication: &ramflux_protocol::custody::Publication,
        device: &ramflux_protocol::custody::DeviceRef,
        bundle: &serde_json::Value,
        custodian: Option<&ramflux_protocol::custody::Publication>,
        now: u64,
    ) -> Result<(), SdkError> {
        let verified = verify_authority(publication, custodian, now)?;
        if let Some(human) = custodian {
            let human = verify_authority(human, None, now)?;
            self.observe_authority(&human)?;
        }
        let cert = verified.authorize(device, "message", now)?;
        let bytes = ramflux_protocol::canonical_json_bytes(bundle)?;
        let bundle: ramflux_crypto::PrekeyBundle =
            ramflux_protocol::custody::decode(&bytes, 64 * 1024)?;
        if bundle.device_id != device.device_id
            || bundle.device_epoch != device.device_epoch
            || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(bundle.identity_key)
                != cert.agreement_identity_public_key
            || bundle.identity_key != bundle.device_agreement_x25519_public
            || bundle.identity_commitment != publication.record.body.principal_id
        {
            return Err(invalid());
        }
        ramflux_crypto::verify_prekey_bundle(
            &ramflux_crypto::verifying_key_from_base64url(&cert.branch_signing_public_key)?,
            &bundle,
        )?;
        self.observe_authority(&verified)?;
        Ok(())
    }
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerPins {
    pins: ramflux_crypto::custody::AuthorityPins,
    accepted: Option<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>>,
}
impl NodePins {
    fn observe_authority(
        &self,
        verified: &ramflux_crypto::custody::VerifiedRecord,
    ) -> Result<(), SdkError> {
        use ramflux_crypto::custody::PinOutcome;
        let _lock = self.lock()?;
        let path = self.root.join(format!("peer-{}.json", verified.envelope().body.account_anchor));
        let mut state: PeerPins =
            if path.try_exists()? { read(&path, 8 * 1024 * 1024)? } else { PeerPins::default() };
        let outcome = state.pins.observe(verified)?;
        if outcome == PinOutcome::Advanced {
            state.accepted = Some(verified.envelope().clone());
        }
        let temp = self.root.join(format!(
            ".peer-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let bytes = serde_json::to_vec(&state)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        create(&temp, &bytes)?;
        fs::rename(temp, path)?;
        fs::File::open(&self.root)?.sync_all()?;
        if outcome == PinOutcome::Fenced {
            return Err(invalid());
        }
        state.pins.require_current(verified)?;
        Ok(())
    }
}
pub(super) fn verify_authority(
    publication: &ramflux_protocol::custody::Publication,
    custodian: Option<&ramflux_protocol::custody::Publication>,
    now: u64,
) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
    let human = custodian
        .map(|p| {
            ramflux_crypto::custody::verify_record(&p.record, now, p.compacted_ids.as_deref(), None)
        })
        .transpose()?;
    Ok(ramflux_crypto::custody::verify_record(
        &publication.record,
        now,
        publication.compacted_ids.as_deref(),
        human.as_ref(),
    )?)
}

pub(super) fn log_unbound(root: &Path) -> Result<(), SdkError> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = root.join("custody_network").join("unbound-connections.log");
    let mut file = fs::OpenOptions::new().append(true).create(true).mode(0o600).open(path)?;
    writeln!(file, "{} no_channel_binding explicit_client_opt_in", super::network::now()?)?;
    file.sync_all()?;
    Ok(())
}

impl NodePins {
    fn dm_receipt_path(&self, sender: &str) -> PathBuf {
        let name = ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.custody_dm_receipt_sender.v1",
            sender.as_bytes(),
        );
        self.root.join("dm-receipts").join(format!("{name}.json"))
    }
    pub(super) fn dm_was_acknowledged(
        &self,
        sender: &str,
        key: &str,
        now: u64,
    ) -> Result<bool, SdkError> {
        let _lock = self.lock()?;
        let legacy = self.root.join("dm-receipts.json");
        if legacy.try_exists()? {
            let receipts: std::collections::BTreeMap<String, u64> = read(&legacy, 512 * 1024)?;
            if receipts.get(key).is_some_and(|expiry| *expiry >= now) {
                return Ok(true);
            }
        }
        let path = self.dm_receipt_path(sender);
        if !path.try_exists()? {
            return Ok(false);
        }
        let receipts: std::collections::BTreeMap<String, u64> = read(&path, 512 * 1024)?;
        Ok(receipts.get(key).is_some_and(|expiry| *expiry >= now))
    }
    pub(super) fn remember_dm_acknowledgement(
        &self,
        sender: &str,
        key: String,
        expiry: u64,
        now: u64,
    ) -> Result<(), SdkError> {
        let _lock = self.lock()?;
        let directory = self.root.join("dm-receipts");
        fs::create_dir_all(&directory)?;
        let path = self.dm_receipt_path(sender);
        let mut receipts: std::collections::BTreeMap<String, u64> = if path.try_exists()? {
            read(&path, 512 * 1024)?
        } else {
            std::collections::BTreeMap::new()
        };
        receipts.retain(|_, until| *until >= now);
        if receipts.contains_key(&key) {
            return Ok(());
        }
        if receipts.len() >= 4096 {
            return Err(ramflux_protocol::custody::CustodyRefusal::Capacity.into());
        }
        if expiry < now {
            return Err(invalid());
        }
        receipts.insert(key, expiry);
        let temporary = directory.join(format!(
            ".dm-receipts-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        create(&temporary, &serde_json::to_vec(&receipts)?)?;
        fs::rename(temporary, path)?;
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    #[test]
    fn acknowledged_dm_receipts_survive_reopen_until_signed_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let pins = NodePins::new(&root.0, "node", &ramflux_crypto::fixture_public_key_base64url())?;
        assert!(!pins.dm_was_acknowledged("sender", "message", 100)?);
        pins.remember_dm_acknowledgement("sender", "message".into(), 200, 100)?;
        let restored =
            NodePins::new(&root.0, "node", &ramflux_crypto::fixture_public_key_base64url())?;
        assert!(restored.dm_was_acknowledged("sender", "message", 101)?);
        pins.remember_dm_acknowledgement("sender", "message".into(), 200, 101)?;
        assert!(!restored.dm_was_acknowledged("sender", "message", 201)?);
        assert!(pins.remember_dm_acknowledgement("sender", "expired".into(), 200, 201).is_err());
        Ok(())
    }
    #[test]
    fn dm_receipt_capacity_isolated_per_authenticated_sender()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let pins = NodePins::new(&root.0, "node", &ramflux_crypto::fixture_public_key_base64url())?;
        let path = pins.dm_receipt_path("sender-a");
        fs::create_dir_all(path.parent().ok_or("receipt parent")?)?;
        let receipts: std::collections::BTreeMap<_, _> =
            (0..4096).map(|n| (format!("receipt-{n}"), 200_u64)).collect();
        create(&path, &serde_json::to_vec(&receipts)?)?;
        assert!(pins.remember_dm_acknowledgement("sender-a", "overflow".into(), 200, 100).is_err());
        pins.remember_dm_acknowledgement("sender-b", "available".into(), 200, 100)?;
        assert!(pins.dm_was_acknowledged("sender-b", "available", 101)?);
        Ok(())
    }
}
