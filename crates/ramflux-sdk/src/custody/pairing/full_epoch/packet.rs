// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Token/scope/Ready bridge to the bounded full cipher. No semantic or native permission.
use super::{
    FullEpoch, FullPairingTransport, PairingRole, SdkError, SecretBase64, encode_base64url, wire,
    wrong,
};
use ramflux_crypto::custody::pairing::FullConfirmedChannel;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{
            DataPacket, PROFILE, U64,
            relay::{
                CloseFull, ClosedFull, EncryptedPacket, HpkeConfirmFull, PollFull, PolledFull,
                SendFull, SendFullControl, SentFull, SentFullControl,
            },
        },
    },
    decode_base64url,
};
use zeroize::Zeroizing;

/// Memory-only authenticated data epoch. Drop on lock/cancel; no serialized channel state.
/// The first position must be a manifest. Idle/durable-duplex controls remain unavailable
/// until the coordinator supplies its own committed application ledger.
pub struct FullPacketEpoch {
    channel: Option<FullConfirmedChannel>,
    token: Option<SecretBase64>,
    lease_id: String,
    epoch: String,
    role: PairingRole,
    expires_at: u64,
    last_received: Option<u64>,
}
impl FullEpoch {
    /// A uses only its own frozen binding, after both original-branch proofs passed.
    /// # Errors
    /// Refuses another role, binding or already consumed HPKE owner.
    pub fn source_control(self) -> Result<(FullPacketEpoch, HpkeConfirmFull), SdkError> {
        if crate::custody::network_now()? >= self.expires_at {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        if self.role != PairingRole::Initiator {
            return Err(wrong());
        }
        let setup = self.verified.setup_sender(&self.binding)?;
        let control = HpkeConfirmFull {
            confirmation: encode_base64url(setup.confirmation),
            enc: encode_base64url(setup.enc),
            epoch: self.epoch.clone(),
            kind: "hpke_confirm".into(),
            lease_id: self.lease_id.clone(),
            role: "initiator".into(),
        };
        control.validate().map_err(|error| wire(&error))?;
        let channel =
            FullConfirmedChannel::resume(self.role, setup.keys, self.binding.manifest_hash)?;
        Ok((
            FullPacketEpoch {
                channel: Some(channel),
                token: Some(self.token),
                lease_id: self.lease_id,
                epoch: self.epoch,
                role: self.role,
                expires_at: self.expires_at,
                last_received: None,
            },
            control,
        ))
    }
    /// B constructs HPKE info/AAD exclusively from its frozen attempt and retained context.
    /// # Errors
    /// Refuses node-substituted scope or confirmation before creating a packet channel.
    pub fn destination_control(
        mut self,
        control: &HpkeConfirmFull,
    ) -> Result<FullPacketEpoch, SdkError> {
        if crate::custody::network_now()? >= self.expires_at {
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        if self.role != PairingRole::Responder {
            return Err(wrong());
        }
        let keys = self.verified.open_control(control, &self.binding)?;
        let channel = FullConfirmedChannel::resume(self.role, keys, self.binding.manifest_hash)?;
        Ok(FullPacketEpoch {
            channel: Some(channel),
            token: Some(self.token),
            lease_id: self.lease_id,
            epoch: self.epoch,
            role: self.role,
            expires_at: self.expires_at,
            last_received: None,
        })
    }
}
impl FullPacketEpoch {
    fn channel(&mut self) -> Result<&mut FullConfirmedChannel, SdkError> {
        if crate::custody::network_now()? >= self.expires_at {
            self.retire();
            return Err(SdkError::PairingCode("LeaseExpired"));
        }
        self.channel.as_mut().ok_or_else(wrong)
    }
    fn retire(&mut self) {
        self.channel = None;
        self.token = None;
    }
    fn wrap(&self, counter: u64, ciphertext: Vec<u8>) -> EncryptedPacket {
        EncryptedPacket {
            ciphertext: encode_base64url(ciphertext),
            counter: U64(counter),
            epoch: self.epoch.clone(),
            lease_id: self.lease_id.clone(),
            role: self.role.as_str().into(),
        }
    }
    fn peer(&self, packet: &EncryptedPacket) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        packet.validate().map_err(|error| wire(&error))?;
        if packet.epoch != self.epoch
            || packet.lease_id != self.lease_id
            || packet.role == self.role.as_str()
        {
            return Err(wrong());
        }
        decode_base64url(&packet.ciphertext).map(Zeroizing::new).map_err(|_| wrong())
    }
    /// B's only pre-position packet: exact encrypted Ready at responder counter zero.
    /// # Errors
    /// Refuses another role/phase or exhausted/retired cipher.
    pub fn seal_ready(&mut self) -> Result<EncryptedPacket, SdkError> {
        let result = self.channel()?.seal_ready().map_err(SdkError::from);
        match result {
            Ok((counter, ciphertext)) => Ok(self.wrap(counter, ciphertext)),
            Err(error) => {
                self.retire();
                Err(error)
            }
        }
    }
    /// A verifies Ready's base hash before any source data object can be sealed.
    /// # Errors
    /// Refuses wrong scope/counter/base hash, duplicate Ready or a retired channel.
    pub fn accept_ready(&mut self, packet: &EncryptedPacket) -> Result<(), SdkError> {
        let result = (|| {
            let ciphertext = self.peer(packet)?;
            self.channel()?.open_ready(packet.counter.0, &ciphertext)?;
            self.last_received = Some(packet.counter.0);
            Ok(())
        })();
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Seal one data packet. A manifest must position each direction before chunks;
    /// this gate alone never validates a manifest chain or applies content.
    /// # Errors
    /// Refuses phase/order/counter/cache limits or a retired channel.
    pub fn seal_packet(&mut self, packet: &DataPacket) -> Result<EncryptedPacket, SdkError> {
        let result = self.channel()?.seal_packet(packet).map_err(SdkError::from);
        match result {
            Ok((counter, ciphertext)) => Ok(self.wrap(counter, ciphertext)),
            Err(error) => {
                self.retire();
                Err(error)
            }
        }
    }
    /// Authenticate exact peer scope and decrypt a typed packet. The application owner
    /// must finish its durable/semantic work before issuing a corresponding receipt.
    /// # Errors
    /// Refuses malformed/reordered/replayed peer data; all key/token material is retired.
    pub fn open_packet(
        &mut self,
        packet: &EncryptedPacket,
    ) -> Result<Option<DataPacket>, SdkError> {
        let result = (|| {
            let ciphertext = self.peer(packet)?;
            let opened = self.channel()?.open_packet(packet.counter.0, &ciphertext)?;
            self.last_received =
                Some(self.last_received.map_or(packet.counter.0, |old| old.max(packet.counter.0)));
            Ok(opened)
        })();
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Authenticate and assemble one manifest part before exposing a complete object.
    /// The caller owns the bounded assembler for this one stream/epoch and must still
    /// apply its OWN signature/catalog/native/parent/application ledger gates. Exact
    /// encrypted retries do not append twice. Any framing/hash refusal retires the epoch.
    /// # Errors
    /// Refuses non-manifest objects, malformed canonical bytes, hash mismatch or scope.
    pub fn open_manifest_part(
        &mut self,
        packet: &EncryptedPacket,
        assembler: &mut ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler,
    ) -> Result<Option<ramflux_protocol::custody::pairing::full_transfer::SourceManifest>, SdkError>
    {
        let result = (|| {
            let Some(part) = self.open_packet(packet)? else { return Ok(None) };
            assembler.push(&part).map_err(|error| wire(&error))
        })();
        if result.is_err() {
            *assembler =
                ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler::default();
            self.retire();
        }
        result
    }
    /// Send a previously sealed exact packet on A2. Relay acceptance only releases the
    /// two-packet ciphertext cache; it never retires immutable cuts or proves application.
    /// Queue Busy retries the same cached ciphertext within the existing request deadline.
    /// # Errors
    /// Any network/scope/ACK failure retires the epoch. Resume uses fresh HPKE keys.
    pub async fn send(
        &mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
        packet: EncryptedPacket,
    ) -> Result<(), SdkError> {
        let result = async {
            if packet.lease_id != self.lease_id
                || packet.epoch != self.epoch
                || packet.role != self.role.as_str()
            {
                return Err(wrong());
            }
            let counter = packet.counter.0;
            // Require the exact cached ciphertext, not another packet supplied by a caller.
            let expected = encode_base64url(self.channel()?.retry(counter)?);
            if expected != packet.ciphertext {
                return Err(wrong());
            }
            let request = SendFull {
                kind: "send_full".into(),
                packet,
                profile: PROFILE.into(),
                token: self.token.as_ref().ok_or_else(wrong)?.clone(),
            };
            let sent: SentFull =
                tokio::time::timeout(super::super::transport::REQUEST_DEADLINE, async {
                    loop {
                        self.channel()?;
                        match relay.send_full(origin, &request).await {
                            Err(SdkError::PairingCode("Busy")) => {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                            result => break result,
                        }
                    }
                })
                .await
                .map_err(|_| SdkError::PairingCode("ResumeRequired"))??;
            if sent.counter.0 != counter {
                return Err(wrong());
            }
            self.channel()?.acknowledge_packet(counter)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.retire();
        }
        result
    }
}

impl FullPacketEpoch {
    /// Send A's exact local HPKE confirmation on the bounded A2 control route.
    /// # Errors
    /// Refuses wrong scope/role or transport errors and retires the local epoch.
    pub async fn send_control(
        &mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
        control: HpkeConfirmFull,
    ) -> Result<(), SdkError> {
        let result = async {
            self.channel()?;
            if self.role != PairingRole::Initiator
                || control.lease_id != self.lease_id
                || control.epoch != self.epoch
                || control.role != self.role.as_str()
            {
                return Err(wrong());
            }
            let request = SendFullControl {
                control,
                kind: "send_full_control".into(),
                profile: PROFILE.into(),
                token: self.token.as_ref().ok_or_else(wrong)?.clone(),
            };
            let _: SentFullControl = relay.send_full_control(origin, &request).await?;
            self.channel()?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Send the complete canonical signed manifest in bounded encrypted parts, with at
    /// most one transport-unacknowledged part at a time. This positions the data channel;
    /// the endpoint must independently admit its local native/chain/phase state first.
    /// No database or stage-key borrow may be held while awaiting this method.
    /// # Errors
    /// Refuses malformed/oversized objects, wrong channel phase or any relay failure.
    pub async fn send_manifest(
        &mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
        manifest: &ramflux_protocol::custody::pairing::full_transfer::SourceManifest,
    ) -> Result<String, SdkError> {
        use ramflux_protocol::custody::pairing::full_transfer::{CHUNK_BYTES, manifest_hash};
        let result = async {
            let bytes = Zeroizing::new(manifest.to_wire_bytes().map_err(|error| wire(&error))?);
            let hash = encode_base64url(manifest_hash(manifest).map_err(|error| wire(&error))?);
            for (index, part) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
                let packet = DataPacket::Manifest {
                    manifest_hash: hash.clone(),
                    offset: U64((index as u64) * u64::from(CHUNK_BYTES)),
                    total: U64(bytes.len() as u64),
                    bytes: SecretBase64::from_bytes(part),
                };
                let encrypted = self.seal_packet(&packet)?;
                self.send(relay, origin, encrypted).await?;
            }
            Ok(hash)
        }
        .await;
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Poll/authenticate one manifest part into this epoch's caller-owned bounded assembler.
    /// A returned object has passed exact framing/hash checks only, never semantic admission.
    /// # Errors
    /// Refuses wrong scope/packet kind, changed assembly operands or malformed manifest bytes.
    pub async fn poll_manifest(
        &mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
        assembler: &mut ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler,
    ) -> Result<Option<ramflux_protocol::custody::pairing::full_transfer::SourceManifest>, SdkError>
    {
        let result = async {
            let Some(packet) = self.poll(relay, origin).await? else { return Ok(None) };
            self.open_manifest_part(&packet, assembler)
        }
        .await;
        if result.is_err() {
            *assembler =
                ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler::default();
            self.retire();
        }
        result
    }
    /// Poll one encrypted peer packet. Queue acknowledgement derives only from the
    /// last authenticated packet; it is never a durable or semantic data receipt.
    /// # Errors
    /// Refuses expired/retired scope, malformed peer packet or network failure.
    pub async fn poll(
        &mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
    ) -> Result<Option<EncryptedPacket>, SdkError> {
        let result = async {
            self.channel()?;
            let request = PollFull {
                acknowledged: self.last_received.map(U64),
                epoch: self.epoch.clone(),
                kind: "poll_full".into(),
                lease_id: self.lease_id.clone(),
                profile: PROFILE.into(),
                role: self.role.as_str().into(),
                token: self.token.as_ref().ok_or_else(wrong)?.clone(),
            };
            let reply: PolledFull =
                tokio::time::timeout(super::super::transport::REQUEST_DEADLINE, async {
                    loop {
                        self.channel()?;
                        match relay.poll_full(origin, &request).await {
                            Err(SdkError::PairingCode("Busy")) => {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                            result => break result,
                        }
                    }
                })
                .await
                .map_err(|_| SdkError::PairingCode("ResumeRequired"))??;
            self.channel()?;
            if let Some(packet) = &reply.packet {
                self.peer(packet)?;
            }
            Ok(reply.packet)
        }
        .await;
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Retire this epoch's tokens/queues only; no lease, source cut or journal cleanup.
    /// # Errors
    /// Returns close transport failure after unconditionally dropping local keys/token.
    pub async fn close(
        mut self,
        relay: &dyn FullPairingTransport,
        origin: &str,
    ) -> Result<(), SdkError> {
        let request = CloseFull {
            epoch: self.epoch.clone(),
            kind: "close_full".into(),
            lease_id: self.lease_id.clone(),
            profile: PROFILE.into(),
            role: self.role.as_str().into(),
            token: self.token.take().ok_or_else(wrong)?,
        };
        self.channel = None;
        let _: ClosedFull = relay.close_full(origin, &request).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
