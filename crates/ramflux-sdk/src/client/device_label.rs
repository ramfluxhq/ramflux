// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private device labels. They travel only on the own-device Control channel.
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::device_label::{
    BODY_SCHEMA, DevicePlatform, MAX_SIGNED_RECORD_BYTES, SIGNED_SCHEMA, linked_at_ms,
    normalize_label,
};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

const INDEX_KEY: &str = "device-label/index.v1";
const PENDING_KEY: &str = "device.label.pending.v1";
const SKEW_MS: u64 = 300_000;
const COPY_DOMAIN: &str = "ramflux.sdk.device_label.v1";
const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelBody {
    schema: String,
    device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform: Option<DevicePlatform>,
    written_at_ms: u64,
    writer_device_id: String,
    writer_device_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedLabel {
    schema: String,
    body: LabelBody,
    signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingFace {
    label: String,
    platform: String,
    written_at_ms: u64,
}

/// Label and platform supplied by the calling device on a pairing enrol call.
#[derive(Clone, Debug)]
pub(crate) struct PairingDeclaration {
    label: String,
    platform: DevicePlatform,
    written_at_ms: u64,
}

/// Fields merged onto one `device.list` row. Database absence leaves the private fields empty.
pub(crate) struct ListFace {
    pub label: Option<String>,
    pub platform: Option<String>,
    pub linked_at: Option<u64>,
    pub last_active_at: Option<u64>,
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

fn utc_day(ms: u64) -> u64 {
    ms - ms % DAY_MS
}

fn row_key(device_id: &str) -> String {
    format!(
        "device-label/v1/{}",
        ramflux_protocol::hash_hex("ramflux.device_label.row", device_id.as_bytes())
    )
}

fn seen_key(device_id: &str) -> String {
    format!(
        "device-label/seen/v1/{}",
        ramflux_protocol::hash_hex("ramflux.device_label.seen", device_id.as_bytes())
    )
}

fn pending_path(root: &Path, account_id: &str) -> PathBuf {
    let name = ramflux_protocol::hash_hex("ramflux.device_label.pending", account_id.as_bytes());
    root.join("device-label-pending").join(format!("{name}.json"))
}

fn refused(reason: &str) -> SdkError {
    SdkError::LocalBus(reason.to_owned())
}

fn account_rows(client: &RamfluxClient) -> Result<Option<&AccountDb>, SdkError> {
    match client.account_db() {
        Ok(db) => Ok(Some(db)),
        Err(SdkError::AccountDbNotUnlocked) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read an optional enrol declaration. Both fields or neither.
/// # Errors
/// The method is an enrol call and exactly one of the two fields is set, or a value is invalid.
pub(crate) fn pairing_declaration(
    method: &str,
    body: &serde_json::Value,
) -> Result<Option<PairingDeclaration>, SdkError> {
    if !matches!(
        method,
        "device.pair.begin" | "device.pair.join" | "device.transfer.begin" | "device.transfer.join"
    ) {
        return Ok(None);
    }
    let label = body.get("device_label").filter(|value| !value.is_null());
    let platform = body.get("platform").filter(|value| !value.is_null());
    match (label, platform) {
        (None, None) => Ok(None),
        (Some(label), Some(platform)) => {
            let label = label.as_str().ok_or_else(|| refused("invalid device label"))?;
            let platform = platform.as_str().ok_or_else(|| refused("invalid device platform"))?;
            Ok(Some(PairingDeclaration {
                label: normalize_label(label)?,
                platform: DevicePlatform::parse(platform)?,
                written_at_ms: wall_ms().max(1),
            }))
        }
        _ => Err(refused("device label and platform are set together")),
    }
}

impl RamfluxClient {
    /// Remember a pairing declaration and sign it once this device's branch matches the roster.
    /// # Errors
    /// Storage or signature failures. A branch that is not installed yet keeps the declaration.
    pub(crate) fn accept_pairing_declaration(
        &self,
        root: &Path,
        account_id: &str,
        declaration: Option<&PairingDeclaration>,
    ) -> Result<(), SdkError> {
        if let Some(declaration) = declaration {
            let pending = PendingFace {
                label: declaration.label.clone(),
                platform: declaration.platform.as_str().to_owned(),
                written_at_ms: declaration.written_at_ms,
            };
            write_pending_file(&pending_path(root, account_id), &pending)?;
            if self.account_db().is_ok() {
                self.set_projection_checkpoint(PENDING_KEY, &serde_json::to_string(&pending)?)?;
            }
        }
        self.try_sign_pending(root, account_id)
    }

    /// Rename one active own device. Platform is unchanged.
    /// # Errors
    /// Unknown device, invalid label, or a missing branch key.
    pub(crate) fn rename_device(
        &self,
        device_id: &str,
        label: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let label = normalize_label(label)?;
        let platform = self.stored_platform(device_id)?;
        let previous = self.stored_written_at(device_id)?;
        let written_at_ms = next_written_at(previous);
        let signed = self.sign_label(device_id, Some(label.clone()), platform, written_at_ms)?;
        self.store_signed(&signed)?;
        self.ensure_fanout()?;
        Ok(serde_json::json!({
            "device_id": device_id,
            "label": signed.body.label,
            "platform": signed.body.platform.map(|platform| platform.as_str().to_owned()),
            "written_at_ms": signed.body.written_at_ms,
        }))
    }

    /// Queue the current label book toward every other active device.
    /// # Errors
    /// Storage failures. A sibling that is not in the directory yet is retried later.
    pub(crate) fn ensure_fanout(&self) -> Result<(), SdkError> {
        let home = match (self.account_index(), self.account_db()) {
            (Ok(index), Ok(db)) => Some((index.root().to_path_buf(), db.local_account_id.clone())),
            _ => None,
        };
        if let Some((root, id)) = home {
            self.try_sign_pending(&root, &id)?;
        } else {
            self.sign_checkpoint_only()?;
        }
        self.fanout_records()
    }

    fn fanout_records(&self) -> Result<(), SdkError> {
        let Some(native) = self.born_v3_account.as_deref() else { return Ok(()) };
        let local = native.local_device_id()?.to_owned();
        let anchor = native.record().body.account_anchor.clone();
        let targets: Vec<String> = native
            .record()
            .body
            .devices
            .iter()
            .filter(|device| device.status == DeviceSetStatus::Active && device.device_id != local)
            .map(|device| device.device_id.clone())
            .collect();
        let records = self.load_index()?;
        for device_id in records {
            let Some(signed) = self.load_signed(&device_id)? else { continue };
            let bytes = canonical_record(&signed)?;
            for target in &targets {
                match self.stage_label(&anchor, target, &signed.signature, &bytes) {
                    Ok(()) | Err(SdkError::InboundPending(_) | SdkError::NetworkingPending) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Record that an authenticated own-device sync was seen. Coarse to the UTC day.
    /// # Errors
    /// Storage failures. A locked database is ignored so receive can proceed.
    pub(crate) fn note_device_seen(&self, device_id: &str) -> Result<(), SdkError> {
        let Some(db) = account_rows(self)? else { return Ok(()) };
        let day = utc_day(wall_ms());
        let key = seen_key(device_id);
        let current = db.load_actor_state::<u64>(&key)?;
        if current.is_some_and(|stored| stored >= day) {
            return Ok(());
        }
        db.persist_actor_state(&key, &day)?;
        Ok(())
    }

    /// Private columns for one roster row.
    /// # Errors
    /// Storage failures other than a locked database.
    pub(crate) fn list_face(
        &self,
        device_id: &str,
        is_local: bool,
        not_before_unix_seconds: Option<u64>,
    ) -> Result<ListFace, SdkError> {
        let signed = self.load_signed(device_id)?;
        let (label, platform) = match signed {
            Some(signed) => match verify_stored(self, &signed) {
                Ok(body) => {
                    (body.label, body.platform.map(|platform| platform.as_str().to_owned()))
                }
                Err(_) => (None, None),
            },
            None => (None, None),
        };
        let last_active_at =
            if is_local { Some(utc_day(wall_ms())) } else { self.load_seen(device_id)? };
        Ok(ListFace {
            label,
            platform,
            linked_at: not_before_unix_seconds.and_then(linked_at_ms),
            last_active_at,
        })
    }

    /// Authenticate one own-device label control and keep it when it is the latest write.
    /// # Errors
    /// Malformed, unsigned, or wrongly attributed records.
    pub(crate) fn receive_device_label(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        label: &g::OwnDeviceLabel,
    ) -> Result<(), SdkError> {
        let bytes = label.signed_record_json.as_slice();
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_RECORD_BYTES {
            return Err(refused("device label record is empty or too large"));
        }
        let signed: SignedLabel = ramflux_protocol::parse_i_json(bytes)
            .map_err(|_| refused("device label record is not canonical JSON"))?;
        if canonical_record(&signed)? != bytes {
            return Err(refused("device label record is not canonical"));
        }
        let body = verify_incoming(self, source, &signed)?;
        let device_id = body.device_id.clone();
        if !self.newer_than_stored(&device_id, &body, &signed.signature)? {
            return Ok(());
        }
        self.store_signed(&signed)?;
        self.note_device_seen(source.device_id())?;
        Ok(())
    }

    fn try_sign_pending(&self, root: &Path, account_id: &str) -> Result<(), SdkError> {
        let path = pending_path(root, account_id);
        let pending = if self.account_db().is_ok() {
            self.pending_from_checkpoint()?.or(read_pending_file(&path)?)
        } else {
            read_pending_file(&path)?
        };
        let Some(pending) = pending else { return Ok(()) };
        match self.sign_pending(&pending) {
            Ok(()) => {
                if self.account_db().is_ok() {
                    self.set_projection_checkpoint(PENDING_KEY, "")?;
                }
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|error| {
                        SdkError::LocalBus(format!("device label pending file: {error}"))
                    })?;
                }
                self.fanout_records()?;
                Ok(())
            }
            Err(SdkError::IdentityRootMissing | SdkError::NetworkingPending) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn sign_checkpoint_only(&self) -> Result<(), SdkError> {
        let Some(pending) = self.pending_from_checkpoint()? else { return Ok(()) };
        match self.sign_pending(&pending) {
            Ok(()) => self.set_projection_checkpoint(PENDING_KEY, ""),
            Err(SdkError::IdentityRootMissing | SdkError::NetworkingPending) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn sign_pending(&self, pending: &PendingFace) -> Result<(), SdkError> {
        let local = self.local_device_id()?;
        let platform = DevicePlatform::parse(&pending.platform)?;
        let signed = self.sign_label(
            &local,
            Some(pending.label.clone()),
            Some(platform),
            pending.written_at_ms,
        )?;
        if self.newer_than_stored(&local, &signed.body, &signed.signature)? {
            self.store_signed(&signed)?;
        }
        Ok(())
    }

    fn pending_from_checkpoint(&self) -> Result<Option<PendingFace>, SdkError> {
        if account_rows(self)?.is_none() {
            return Ok(None);
        }
        let Some(value) = self.projection_checkpoint(PENDING_KEY)? else { return Ok(None) };
        if value.is_empty() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&value)?))
    }

    fn sign_label(
        &self,
        device_id: &str,
        label: Option<String>,
        platform: Option<DevicePlatform>,
        written_at_ms: u64,
    ) -> Result<SignedLabel, SdkError> {
        let (local, writer_epoch, writer_key) = {
            let native = self.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
            let local = native.local_device_id()?.to_owned();
            let record = native.record();
            let writer = record
                .body
                .devices
                .iter()
                .find(|device| {
                    device.device_id == local && device.status == DeviceSetStatus::Active
                })
                .ok_or(SdkError::IdentityRootMissing)?;
            let certificate =
                writer.branch_certificate.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let active = record.body.devices.iter().any(|device| {
                device.device_id == device_id && device.status == DeviceSetStatus::Active
            });
            if !active {
                return Err(refused("device is not an active sibling"));
            }
            (
                local,
                certificate.body.device_epoch,
                certificate.body.branch_signing_public_key.clone(),
            )
        };
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let local_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
        if local_key != writer_key || branch.device_id != local {
            return Err(SdkError::IdentityRootMissing);
        }
        let body = LabelBody {
            schema: BODY_SCHEMA.to_owned(),
            device_id: device_id.to_owned(),
            label,
            platform,
            written_at_ms,
            writer_device_id: local,
            writer_device_epoch: writer_epoch,
        };
        if written_at_ms == 0
            || written_at_ms > wall_ms().saturating_add(SKEW_MS).saturating_add(DAY_MS)
        {
            return Err(refused("device label timestamp is not current"));
        }
        let signature = ramflux_crypto::sign_protocol_object_with_device_branch(branch, &body)?;
        let signed = SignedLabel { schema: SIGNED_SCHEMA.to_owned(), body, signature };
        if canonical_record(&signed)?.len() > MAX_SIGNED_RECORD_BYTES {
            return Err(refused("device label record is too large"));
        }
        Ok(signed)
    }

    fn store_signed(&self, signed: &SignedLabel) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let device_id = signed.body.device_id.clone();
        let key = row_key(&device_id);
        db.write_transaction(|| {
            db.persist_actor_state(&key, signed)?;
            let mut index = db.load_actor_state::<BTreeSet<String>>(INDEX_KEY)?.unwrap_or_default();
            if index.len() >= ramflux_protocol::custody::MAX_ENROLLMENT_ROSTER
                && !index.contains(&device_id)
            {
                return Err(SdkError::LocalBus("device label index is full".into()));
            }
            index.insert(device_id);
            db.persist_actor_state(INDEX_KEY, &index)?;
            Ok(())
        })
    }

    fn load_index(&self) -> Result<BTreeSet<String>, SdkError> {
        let Some(db) = account_rows(self)? else { return Ok(BTreeSet::new()) };
        Ok(db.load_actor_state(INDEX_KEY)?.unwrap_or_default())
    }

    fn load_signed(&self, device_id: &str) -> Result<Option<SignedLabel>, SdkError> {
        let Some(db) = account_rows(self)? else { return Ok(None) };
        Ok(db.load_actor_state(&row_key(device_id))?)
    }

    fn load_seen(&self, device_id: &str) -> Result<Option<u64>, SdkError> {
        let Some(db) = account_rows(self)? else { return Ok(None) };
        Ok(db.load_actor_state(&seen_key(device_id))?)
    }

    fn stored_platform(&self, device_id: &str) -> Result<Option<DevicePlatform>, SdkError> {
        Ok(self.load_signed(device_id)?.and_then(|signed| signed.body.platform))
    }

    fn stored_written_at(&self, device_id: &str) -> Result<Option<u64>, SdkError> {
        Ok(self.load_signed(device_id)?.map(|signed| signed.body.written_at_ms))
    }

    fn newer_than_stored(
        &self,
        device_id: &str,
        body: &LabelBody,
        signature: &str,
    ) -> Result<bool, SdkError> {
        let Some(stored) = self.load_signed(device_id)? else { return Ok(true) };
        Ok(rank(body, signature) > rank(&stored.body, &stored.signature))
    }

    fn local_device_id(&self) -> Result<String, SdkError> {
        Ok(self
            .born_v3_account
            .as_deref()
            .ok_or(SdkError::NetworkingPending)?
            .local_device_id()?
            .to_owned())
    }

    fn stage_label(
        &self,
        anchor: &str,
        target: &str,
        signature: &str,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        let device = self.device_identity_for_root(anchor, target)?;
        let id = ramflux_protocol::hash_base64url(
            COPY_DOMAIN,
            &[signature.as_bytes(), target.as_bytes()].concat(),
        );
        let control = crate::client::generated_control::control_from_payload(
            g::control::Payload::OwnDeviceLabel(g::OwnDeviceLabel {
                signed_record_json: bytes.to_vec(),
            }),
        )?;
        let body = prost::Message::encode_to_vec(&control);
        let created_at = crate::time::now_unix_timestamp();
        crate::bus::own_device_copy::stage_to(
            self,
            crate::client::own_device_copy::OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Control,
                id: &id,
                created_at,
                conversation: "device-label",
                group: None,
                body: &body,
            },
            &device,
        )
    }
}

fn next_written_at(previous: Option<u64>) -> u64 {
    let now = wall_ms().max(1);
    match previous {
        Some(previous) => now.max(previous.saturating_add(1)),
        None => now,
    }
}

fn timestamp_ok(written: u64, now: u64, previous: Option<u64>) -> bool {
    written > 0
        && (written <= now.saturating_add(SKEW_MS)
            || previous.is_some_and(|stored| written == stored.saturating_add(1)))
}

fn rank<'a>(body: &'a LabelBody, signature: &'a str) -> (u64, &'a str, &'a str) {
    (body.written_at_ms, body.writer_device_id.as_str(), signature)
}

fn canonical_record(signed: &SignedLabel) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(signed)?)
}

fn verify_stored(client: &RamfluxClient, signed: &SignedLabel) -> Result<LabelBody, SdkError> {
    if signed.schema != SIGNED_SCHEMA || signed.body.schema != BODY_SCHEMA {
        return Err(refused("device label schema mismatch"));
    }
    let native = client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    let writer = native
        .record()
        .body
        .devices
        .iter()
        .find(|device| {
            device.device_id == signed.body.writer_device_id
                && device.device_epoch == signed.body.writer_device_epoch
                && device.status == DeviceSetStatus::Active
        })
        .ok_or_else(|| refused("device label writer is not active"))?;
    let certificate = writer
        .branch_certificate
        .as_ref()
        .ok_or_else(|| refused("device label writer has no branch"))?;
    let bytes = ramflux_protocol::signed_bytes(&signed.body)?;
    ramflux_crypto::verify_canonical_signature(
        &bytes,
        &signed.signature,
        &certificate.body.branch_signing_public_key,
    )?;
    if let Some(label) = &signed.body.label
        && normalize_label(label).ok().as_ref() != Some(label)
    {
        return Err(refused("device label is not normalized"));
    }
    Ok(signed.body.clone())
}

fn verify_incoming(
    client: &RamfluxClient,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    signed: &SignedLabel,
) -> Result<LabelBody, SdkError> {
    let body = verify_stored(client, signed)?;
    if source.root_commitment() != client.own_account_anchor()?
        || source.device_id() != body.writer_device_id
    {
        return Err(refused("device label writer does not match the sender"));
    }
    let previous = client.stored_written_at(&body.device_id)?;
    if !timestamp_ok(body.written_at_ms, wall_ms(), previous) {
        return Err(refused("device label timestamp is not current"));
    }
    let native = client.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
    if !native.record().body.devices.iter().any(|device| {
        device.device_id == body.device_id && device.status == DeviceSetStatus::Active
    }) {
        return Err(refused("device label names an inactive device"));
    }
    Ok(body)
}

fn write_pending_file(path: &Path, pending: &PendingFace) -> Result<(), SdkError> {
    let parent = path.parent().ok_or_else(|| refused("device label pending path"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| SdkError::LocalBus(format!("device label pending directory: {error}")))?;
    crate::platform::fs::set_owner_only_dir(parent)?;
    let bytes = serde_json::to_vec(pending)?;
    if bytes.len() > 1024 {
        return Err(refused("device label pending record is too large"));
    }
    let mut file = if path.exists() {
        crate::platform::fs::open_owner_only_truncate(path)?
    } else {
        crate::platform::fs::create_new_owner_only(path)?
    };
    file.write_all(&bytes)
        .map_err(|error| SdkError::LocalBus(format!("device label pending write: {error}")))?;
    file.sync_all()
        .map_err(|error| SdkError::LocalBus(format!("device label pending sync: {error}")))?;
    Ok(())
}

fn read_pending_file(path: &Path) -> Result<Option<PendingFace>, SdkError> {
    if !path.exists() {
        return Ok(None);
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| SdkError::LocalBus(format!("device label pending read: {error}")))?;
    let mut buf = [0_u8; 1024];
    let read = file
        .read(&mut buf)
        .map_err(|error| SdkError::LocalBus(format!("device label pending read: {error}")))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| SdkError::LocalBus(format!("device label pending read: {error}")))?
        != 0
    {
        return Err(refused("device label pending file is too large"));
    }
    Ok(Some(serde_json::from_slice(&buf[..read])?))
}
