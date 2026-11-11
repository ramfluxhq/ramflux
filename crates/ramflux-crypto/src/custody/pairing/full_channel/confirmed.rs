// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A1 phase owner: Ready consumes r0; the first A data object is the base manifest.
use super::{CryptoError, FullDataCipher, FullDataKeys, FullOpened, PairingRole};
use ramflux_protocol::custody::pairing::{PairingWire, full_transfer::DataPacket};

pub struct FullConfirmedChannel {
    cipher: FullDataCipher,
    base_manifest_hash: String,
    ready: bool,
    manifest_started: bool,
}
impl FullConfirmedChannel {
    /// The binding hash is frozen by `StartFull` and Auth-HPKE, not supplied by the Ready peer.
    /// # Errors
    /// Refuses a malformed base hash.
    pub fn new(
        role: PairingRole,
        keys: FullDataKeys,
        base_manifest_hash: String,
    ) -> Result<Self, CryptoError> {
        DataPacket::Receipt {
            manifest_hash: base_manifest_hash.clone(),
            durable_through: None,
            credit: 0,
        }
        .validate()?;
        Ok(Self {
            cipher: FullDataCipher::new(role, keys),
            base_manifest_hash,
            ready: false,
            manifest_started: false,
        })
    }
    /// Seal Ready once after successful HPKE open. Repeated polls use retry(0).
    /// # Errors
    /// Refuses another role/phase; never resets responder counters.
    pub fn seal_ready(&mut self) -> Result<(u64, Vec<u8>), CryptoError> {
        self.cipher.live()?;
        if self.cipher.role != PairingRole::Responder || self.ready {
            return Err(CryptoError::Pairing("WrongRole"));
        }
        let packet = DataPacket::Receipt {
            manifest_hash: self.base_manifest_hash.clone(),
            durable_through: None,
            credit: 0,
        };
        let sealed = self.cipher.seal(&packet.encode_secret()?)?;
        self.ready = true;
        Ok(sealed)
    }
    /// Authenticate the exact Ready before permitting A's first manifest.
    /// # Errors
    /// Wrong base hash retires the channel with `ManifestMismatch`; other shapes/phases refuse.
    pub fn open_ready(&mut self, counter: u64, ciphertext: &[u8]) -> Result<(), CryptoError> {
        self.cipher.live()?;
        if self.cipher.role != PairingRole::Initiator || self.ready || counter != 0 {
            return self.cipher.fail("WrongContext");
        }
        let FullOpened::New(bytes) = self.cipher.open(counter, ciphertext)? else {
            return self.cipher.fail("Replay");
        };
        let Ok(packet) = DataPacket::from_wire_bytes(&bytes) else {
            return self.cipher.fail("InvalidInput");
        };
        match packet {
            DataPacket::Receipt { manifest_hash, durable_through: None, credit: 0 } => {
                if manifest_hash != self.base_manifest_hash {
                    return self.cipher.fail("ManifestMismatch");
                }
            }
            _ => return self.cipher.fail("WrongContext"),
        }
        self.ready = true;
        Ok(())
    }
    /// Seal ordinary packets after Ready, with the base `SourceManifest` first from A.
    /// # Errors
    /// Refuses premature data or a different first A object, then preserves cipher counters.
    pub fn seal_packet(&mut self, packet: &DataPacket) -> Result<(u64, Vec<u8>), CryptoError> {
        self.cipher.live()?;
        if !self.ready {
            return Err(CryptoError::Pairing("PublicationPending"));
        }
        let first = self.cipher.role == PairingRole::Initiator && !self.manifest_started;
        if first && !self.is_base_manifest(packet) {
            return Err(CryptoError::Pairing("ManifestMismatch"));
        }
        let sealed = self.cipher.seal(&packet.encode_secret()?)?;
        if first {
            self.manifest_started = true;
        }
        Ok(sealed)
    }
    /// Open ordinary packets only after Ready; duplicate ciphertext never imports twice.
    /// # Errors
    /// Refuses premature packets, malformed plaintext or a different first A data object.
    pub fn open_packet(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<Option<DataPacket>, CryptoError> {
        self.cipher.live()?;
        if !self.ready {
            return Err(CryptoError::Pairing("PublicationPending"));
        }
        let FullOpened::New(bytes) = self.cipher.open(counter, ciphertext)? else {
            return Ok(None);
        };
        let Ok(packet) = DataPacket::from_wire_bytes(&bytes) else {
            return self.cipher.fail("InvalidInput");
        };
        if self.cipher.role == PairingRole::Responder && !self.manifest_started {
            if !self.is_base_manifest(&packet) {
                return self.cipher.fail("ManifestMismatch");
            }
            self.manifest_started = true;
        }
        Ok(Some(packet))
    }
    fn is_base_manifest(&self, packet: &DataPacket) -> bool {
        matches!(packet, DataPacket::Manifest { manifest_hash, offset, .. }
            if manifest_hash == &self.base_manifest_hash && offset.0 == 0)
    }
    /// # Errors
    /// Refuses packets outside the bounded retry cache.
    pub fn retry(&self, counter: u64) -> Result<&[u8], CryptoError> {
        self.cipher.retry(counter)
    }
    /// # Errors
    /// Refuses an unsent packet or a retired channel. This is only a transport acknowledgement.
    pub fn acknowledge_packet(&mut self, counter: u64) -> Result<(), CryptoError> {
        self.cipher.acknowledge_packet(counter)
    }
}
