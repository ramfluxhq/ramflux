// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A1 phase owner: Ready consumes r0; the first A data object is the base manifest.
use super::{CryptoError, FullDataCipher, FullDataKeys, FullOpened, PairingRole};
use ramflux_protocol::custody::pairing::{PairingWire, full_transfer::DataPacket};

#[derive(PartialEq, Eq)]
enum ForwardPosition {
    Awaiting,
    Manifest,
    Idle,
}
#[derive(PartialEq, Eq)]
enum ReversePosition {
    Required,
    Seen,
    Preserved,
}
#[derive(PartialEq, Eq)]
enum ControlPhase {
    Blocked,
    DuplexVerified,
}

pub struct FullConfirmedChannel {
    cipher: FullDataCipher,
    base_manifest_hash: String,
    ready: bool,
    manifest_started: bool,
    forward_position: ForwardPosition,
    reverse_position: ReversePosition,
    controls: ControlPhase,
    idle_last_verified: Option<String>,
    initial_epoch: bool,
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
            forward_position: ForwardPosition::Awaiting,
            reverse_position: ReversePosition::Required,
            controls: ControlPhase::Blocked,
            idle_last_verified: None,
            initial_epoch: true,
        })
    }
    /// A reconnect starts the currently streamed manifest, while Ready still binds the base.
    /// The receiver's durable manifest ledger must apply all three M2 rules before chunks.
    /// # Errors
    /// Refuses a malformed original base hash.
    pub fn resume(
        role: PairingRole,
        keys: FullDataKeys,
        base_manifest_hash: String,
    ) -> Result<Self, CryptoError> {
        let mut channel = Self::new(role, keys, base_manifest_hash)?;
        channel.initial_epoch = false;
        Ok(channel)
    }
    /// Resume with the last forward `DataVerified` hash read from this endpoint's OWN
    /// durable stage. Never supply a hash from the new packet, relay or peer template.
    /// # Errors
    /// Refuses malformed local hashes. This restores no publication approval.
    pub fn resume_with_idle(
        role: PairingRole,
        keys: FullDataKeys,
        base_manifest_hash: String,
        last_verified: String,
    ) -> Result<Self, CryptoError> {
        DataPacket::Idle { last_verified: last_verified.clone() }.validate()?;
        let mut channel = Self::resume(role, keys, base_manifest_hash)?;
        channel.idle_last_verified = Some(last_verified);
        Ok(channel)
    }
    /// Bind optional reconnect Idle to this endpoint's own saved forward DV hash.
    /// Call before its first forward position, including after Ready authentication.
    /// # Errors
    /// Refuses an initial/started epoch, malformed hash or a changed saved binding.
    pub fn expect_idle_position(&mut self, last_verified: String) -> Result<(), CryptoError> {
        self.cipher.live()?;
        DataPacket::Idle { last_verified: last_verified.clone() }.validate()?;
        if self.initial_epoch
            || self.forward_position != ForwardPosition::Awaiting
            || self.idle_last_verified.as_ref().is_some_and(|old| old != &last_verified)
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        self.idle_last_verified = Some(last_verified);
        Ok(())
    }
    /// Preserve the reverse position only after the coordinator reads its own complete
    /// durable duplex from a pending installed tail. This opens no control/approval gate.
    /// # Errors
    /// Refuses an initial or already-positioned epoch; a peer packet cannot supply this proof.
    pub fn preserve_completed_reverse_on_resume(&mut self) -> Result<(), CryptoError> {
        self.cipher.live()?;
        if self.initial_epoch
            || self.forward_position != ForwardPosition::Awaiting
            || self.reverse_position != ReversePosition::Required
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        self.reverse_position = ReversePosition::Preserved;
        Ok(())
    }
    /// The trusted coordinator calls this ONLY after reading its durable forward `DataVerified`
    /// and applied reverse proof. `transfer_ready_held` means its exact saved, verified full
    /// preservation control is present. This opens a data transport gate, never authority;
    /// native candidate, private approval, phase and publication checks remain mandatory.
    pub fn allow_controls_after_verified_duplex(&mut self, transfer_ready_held: bool) {
        self.controls = ControlPhase::DuplexVerified;
        if transfer_ready_held {
            self.reverse_position = ReversePosition::Preserved;
        }
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
    /// Seal ordinary packets after Ready, with the current `SourceManifest` first from A.
    /// # Errors
    /// Refuses premature data or a different first A object, then preserves cipher counters.
    pub fn seal_packet(&mut self, packet: &DataPacket) -> Result<(u64, Vec<u8>), CryptoError> {
        self.cipher.live()?;
        if !self.ready {
            return Err(CryptoError::Pairing("PublicationPending"));
        }
        if Self::is_ready_shape(packet) && !self.manifest_started {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        self.require_packet_position(packet, self.cipher.role)?;
        let sealed = self.cipher.seal(&packet.encode_secret()?)?;
        self.record_position(packet, self.cipher.role);
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
        if Self::is_ready_shape(&packet) {
            return if self.manifest_started { Ok(None) } else { self.cipher.fail("WrongContext") };
        }
        let sender = if self.cipher.role == PairingRole::Initiator {
            PairingRole::Responder
        } else {
            PairingRole::Initiator
        };
        if let Err(error) = self.require_packet_position(&packet, sender) {
            self.cipher.retire_material();
            return Err(error);
        }
        self.record_position(&packet, sender);
        Ok(Some(packet))
    }
    fn require_packet_position(
        &self,
        packet: &DataPacket,
        sender: PairingRole,
    ) -> Result<(), CryptoError> {
        if sender == PairingRole::Initiator && self.forward_position == ForwardPosition::Awaiting {
            if !self.is_first_manifest(packet) && !self.is_first_idle(packet) {
                return Err(CryptoError::Pairing("ManifestMismatch"));
            }
        } else if matches!(packet, DataPacket::Idle { .. }) {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        if sender == PairingRole::Responder {
            if self.forward_position == ForwardPosition::Awaiting {
                return Err(CryptoError::Pairing("WrongContext"));
            }
            if self.reverse_position == ReversePosition::Required
                && !matches!(packet, DataPacket::Manifest { offset, .. } if offset.0 == 0)
            {
                return Err(CryptoError::Pairing("ManifestMismatch"));
            }
        }
        if let DataPacket::Control { payload } = packet {
            if self.controls == ControlPhase::Blocked {
                return Err(CryptoError::Pairing("PublicationPending"));
            }
            payload.require_sender(if sender == PairingRole::Initiator {
                "initiator"
            } else {
                "responder"
            })?;
        }
        Ok(())
    }
    fn record_position(&mut self, packet: &DataPacket, sender: PairingRole) {
        if sender == PairingRole::Initiator && self.forward_position == ForwardPosition::Awaiting {
            self.forward_position = if matches!(packet, DataPacket::Idle { .. }) {
                ForwardPosition::Idle
            } else {
                ForwardPosition::Manifest
            };
        }
        if matches!(packet, DataPacket::Manifest { .. }) {
            self.manifest_started = true;
            if sender == PairingRole::Responder {
                self.reverse_position = ReversePosition::Seen;
            }
        }
    }
    fn is_first_idle(&self, packet: &DataPacket) -> bool {
        !self.initial_epoch
            && matches!(packet, DataPacket::Idle { last_verified }
            if self.idle_last_verified.as_ref() == Some(last_verified))
    }
    fn is_first_manifest(&self, packet: &DataPacket) -> bool {
        matches!(packet, DataPacket::Manifest { manifest_hash, offset, .. }
            if (!self.initial_epoch || manifest_hash == &self.base_manifest_hash) && offset.0 == 0)
    }
    fn is_ready_shape(packet: &DataPacket) -> bool {
        matches!(packet, DataPacket::Receipt { durable_through: None, credit: 0, .. })
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
