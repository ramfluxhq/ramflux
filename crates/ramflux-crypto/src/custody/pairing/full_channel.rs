// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded exporter-key channel. A lease reconnect must create a wholly new instance/epoch.
use super::{FullDataKeys, PairingRole};
mod confirmed;
use crate::CryptoError;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
pub use confirmed::FullConfirmedChannel;
use ramflux_protocol::custody::pairing::full_transfer::PACKETS_PER_KEY;
use std::collections::VecDeque;
use zeroize::{Zeroize, Zeroizing};

const RESUME_STOP: &[u8] =
    b"{\"code\":\"ResumeRequired\",\"kind\":\"stop\",\"retry_after_ms\":null}";

pub const FULL_PACKET_PLAINTEXT_BYTES: usize =
    ramflux_protocol::custody::pairing::full_transfer::PACKET_PLAINTEXT_BYTES;
pub enum FullOpened {
    New(Zeroizing<Vec<u8>>),
    Duplicate,
}
pub struct FullDataCipher {
    role: PairingRole,
    send: Zeroizing<[u8; 32]>,
    receive: Zeroizing<[u8; 32]>,
    context: Zeroizing<Vec<u8>>,
    sent: u64,
    received: u64,
    dead: bool,
    outgoing: VecDeque<(u64, Vec<u8>)>,
    incoming: VecDeque<(u64, Vec<u8>)>,
}
impl FullDataCipher {
    #[must_use]
    pub fn new(role: PairingRole, keys: FullDataKeys) -> Self {
        let (send, receive) = match role {
            PairingRole::Initiator => (keys.initiator, keys.responder),
            PairingRole::Responder => (keys.responder, keys.initiator),
        };
        Self {
            role,
            send,
            receive,
            context: keys.packet_context,
            sent: 0,
            received: 0,
            dead: false,
            outgoing: VecDeque::with_capacity(2),
            incoming: VecDeque::with_capacity(2),
        }
    }
    #[must_use]
    pub fn remaining_send_packets(&self) -> u64 {
        PACKETS_PER_KEY - self.sent
    }
    /// Seal exactly once per counter. The authenticated transport releases cached packets.
    /// # Errors
    /// Refuses over-size input, a full two-packet cache, a closed context or the rekey boundary.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), CryptoError> {
        self.live()?;
        if plaintext.len() > FULL_PACKET_PLAINTEXT_BYTES {
            return self.fail("InvalidInput");
        }
        if self.sent >= PACKETS_PER_KEY
            || (self.sent == PACKETS_PER_KEY - 1 && plaintext != RESUME_STOP)
        {
            return Err(CryptoError::Pairing("ResumeRequired"));
        }
        if self.outgoing.len() == 2 {
            return Err(CryptoError::Pairing("Busy"));
        }
        let counter = self.sent;
        let mut output = Zeroizing::new(plaintext.to_vec());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.send.as_ref()));
        let tag = cipher
            .encrypt_in_place_detached(
                &nonce(counter),
                &self.aad(self.role.byte(), counter),
                &mut output,
            )
            .map_err(|_| CryptoError::Pairing("channel_aead"))?;
        output.extend_from_slice(&tag);
        let output = std::mem::take(&mut *output);
        self.outgoing.push_back((counter, output.clone()));
        self.sent += 1;
        if plaintext == RESUME_STOP {
            self.retire_material();
        }
        Ok((counter, output))
    }
    /// Retries return identical cached ciphertext and never invoke Seal again.
    /// # Errors
    /// Refuses a closed context or a packet no longer in the bounded retry window.
    pub fn retry(&self, counter: u64) -> Result<&[u8], CryptoError> {
        self.live()?;
        self.outgoing
            .iter()
            .find(|(index, _)| *index == counter)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or(CryptoError::Pairing("Replay"))
    }
    /// Release transport-acknowledged ciphertext; this is not a durable data receipt.
    /// # Errors
    /// Refuses an unsent counter or a closed context.
    pub fn acknowledge_packet(&mut self, counter: u64) -> Result<(), CryptoError> {
        self.live()?;
        if counter >= self.sent {
            return Err(CryptoError::Pairing("Replay"));
        }
        while self.outgoing.front().is_some_and(|(index, _)| *index <= counter) {
            self.outgoing.pop_front();
        }
        Ok(())
    }
    /// Return plaintext once; exact cached duplicates are re-ACKable without re-import.
    /// # Errors
    /// Refuses skipped/altered/replayed counters, context reflection, over-size or failed AEAD.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<FullOpened, CryptoError> {
        self.live()?;
        if ciphertext.len() < 16 || ciphertext.len() > FULL_PACKET_PLAINTEXT_BYTES + 16 {
            return self.fail("InvalidInput");
        }
        if counter < self.received {
            return if self
                .incoming
                .iter()
                .any(|(index, bytes)| *index == counter && bytes == ciphertext)
            {
                Ok(FullOpened::Duplicate)
            } else {
                self.fail("Replay")
            };
        }
        if counter != self.received {
            return self.fail("Replay");
        }
        if counter >= PACKETS_PER_KEY {
            return self.fail("ResumeRequired");
        }
        let length = ciphertext.len() - 16;
        let mut plaintext = Zeroizing::new(ciphertext[..length].to_vec());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.receive.as_ref()));
        if cipher
            .decrypt_in_place_detached(
                &nonce(counter),
                &self.aad(1 - self.role.byte(), counter),
                &mut plaintext,
                Tag::from_slice(&ciphertext[length..]),
            )
            .is_err()
        {
            return self.fail("channel_aead");
        }
        if counter == PACKETS_PER_KEY - 1 && plaintext.as_slice() != RESUME_STOP {
            return self.fail("ResumeRequired");
        }
        if self.incoming.len() == 2 {
            self.incoming.pop_front();
        }
        self.incoming.push_back((counter, ciphertext.to_vec()));
        self.received += 1;
        if plaintext.as_slice() == RESUME_STOP {
            self.retire_material();
        }
        Ok(FullOpened::New(plaintext))
    }
    fn aad(&self, role: u8, counter: u64) -> Zeroizing<Vec<u8>> {
        let mut aad = Zeroizing::new(Vec::with_capacity(self.context.len() + 9));
        aad.extend_from_slice(&self.context);
        aad.push(role);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad
    }
    fn live(&self) -> Result<(), CryptoError> {
        if self.dead { Err(CryptoError::Pairing("Retired")) } else { Ok(()) }
    }
    fn retire_material(&mut self) {
        self.send.zeroize();
        self.receive.zeroize();
        self.context.zeroize();
        self.dead = true;
        self.outgoing.clear();
        self.incoming.clear();
    }
    fn fail<T>(&mut self, code: &'static str) -> Result<T, CryptoError> {
        self.retire_material();
        Err(CryptoError::Pairing(code))
    }
}
fn nonce(counter: u64) -> Nonce {
    let mut nonce = Nonce::default();
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests;
