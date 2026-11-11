// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Committed X25519 SAS: full-context SHA-256 commitments, TH-salted HKDF, role MACs, channel AEAD.
use super::cleanup::PairingSecrets;
use crate::{CryptoError, hkdf_sha256};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use ramflux_protocol::custody::pairing::{RoleContext, SasContext, require_context_version};
use ramflux_protocol::{decode_base64url, domain, encode_base64url};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Standard Matrix SAS emoji table (index, glyph, English name). Horse is U+1F434.
pub const SAS_EMOJI: [(&str, &str); 64] = [
    ("🐶", "Dog"),
    ("🐱", "Cat"),
    ("🦁", "Lion"),
    ("🐴", "Horse"),
    ("🦄", "Unicorn"),
    ("🐷", "Pig"),
    ("🐘", "Elephant"),
    ("🐰", "Rabbit"),
    ("🐼", "Panda"),
    ("🐓", "Rooster"),
    ("🐧", "Penguin"),
    ("🐢", "Turtle"),
    ("🐟", "Fish"),
    ("🐙", "Octopus"),
    ("🦋", "Butterfly"),
    ("🌷", "Flower"),
    ("🌳", "Tree"),
    ("🌵", "Cactus"),
    ("🍄", "Mushroom"),
    ("🌏", "Globe"),
    ("🌙", "Moon"),
    ("☁️", "Cloud"),
    ("🔥", "Fire"),
    ("🍌", "Banana"),
    ("🍎", "Apple"),
    ("🍓", "Strawberry"),
    ("🌽", "Corn"),
    ("🍕", "Pizza"),
    ("🎂", "Cake"),
    ("❤️", "Heart"),
    ("😀", "Smiley"),
    ("🤖", "Robot"),
    ("🎩", "Hat"),
    ("👓", "Glasses"),
    ("🔧", "Spanner"),
    ("🎅", "Santa"),
    ("👍", "Thumbs Up"),
    ("☂️", "Umbrella"),
    ("⌛", "Hourglass"),
    ("⏰", "Clock"),
    ("🎁", "Gift"),
    ("💡", "Light Bulb"),
    ("📕", "Book"),
    ("✏️", "Pencil"),
    ("📎", "Paperclip"),
    ("✂️", "Scissors"),
    ("🔒", "Lock"),
    ("🔑", "Key"),
    ("🔨", "Hammer"),
    ("☎️", "Telephone"),
    ("🏁", "Flag"),
    ("🚂", "Train"),
    ("🚲", "Bicycle"),
    ("✈️", "Aeroplane"),
    ("🚀", "Rocket"),
    ("🏆", "Trophy"),
    ("⚽", "Ball"),
    ("🎸", "Guitar"),
    ("🎺", "Trumpet"),
    ("🔔", "Bell"),
    ("⚓", "Anchor"),
    ("🎧", "Headphones"),
    ("📁", "Folder"),
    ("📌", "Pin"),
];

/// One SAS emoji selected by a 6-bit index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SasEmoji {
    pub index: u8,
    pub glyph: &'static str,
    pub name: &'static str,
}

/// SAS ceremony role. Commitment role byte is 0 for initiator and 1 for responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRole {
    Initiator,
    Responder,
}

impl PairingRole {
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
    fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
    fn parse(role: &str) -> Result<Self, CryptoError> {
        match role {
            "initiator" => Ok(Self::Initiator),
            "responder" => Ok(Self::Responder),
            _ => Err(CryptoError::Pairing("role")),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Committed,
    Ready,
    Dead,
}

/// Local commitment waiting for the peer reveal. Secrets are memory-only.
#[derive(ZeroizeOnDrop)]
pub struct PendingSas<C: SasContext = RoleContext> {
    #[zeroize(skip)]
    role: PairingRole,
    #[zeroize(skip)]
    phase: Phase,
    #[zeroize(skip)]
    context: C,
    #[zeroize(skip)]
    commitment: [u8; 32],
    #[zeroize(skip)]
    peer_commitment: Option<[u8; 32]>,
    secrets: PairingSecrets,
}

/// Shared SAS after both reveals. Channel use requires both local and peer confirmation MACs.
#[derive(ZeroizeOnDrop)]
pub struct EstablishedSas {
    #[zeroize(skip)]
    role: PairingRole,
    #[zeroize(skip)]
    dead: bool,
    #[zeroize(skip)]
    transcript_hash: [u8; 32],
    #[zeroize(skip)]
    emoji: [u8; 7],
    #[zeroize(skip)]
    local_confirmed: bool,
    #[zeroize(skip)]
    peer_confirmed: bool,
    #[zeroize(skip)]
    send_counter: u64,
    #[zeroize(skip)]
    recv_counter: u64,
    secrets: PairingSecrets,
}

/// Freeze a complete role context and return its selected v2/v3 profile commitment.
///
/// # Errors
/// Rejects a role/sas-key mismatch, an all-zero SAS public key, or an invalid context.
pub fn commit<C: SasContext>(
    role: PairingRole,
    context: &C,
    sas_secret: &[u8; 32],
    salt: &[u8; 32],
) -> Result<PendingSas<C>, CryptoError> {
    if context.role() != role.as_str() {
        return Err(CryptoError::Pairing("role_mismatch"));
    }
    let public = PublicKey::from(&StaticSecret::from(*sas_secret)).to_bytes();
    if public.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::Pairing("all_zero_sas_key"));
    }
    if encode_base64url(public) != context.sas_key() {
        return Err(CryptoError::Pairing("sas_key_mismatch"));
    }
    Ok(PendingSas {
        role,
        phase: Phase::Committed,
        context: context.clone(),
        commitment: sha256(&context.commitment_preimage(salt)?),
        peer_commitment: None,
        secrets: PairingSecrets::pending(*sas_secret, *salt),
    })
}

impl<C: SasContext> PendingSas<C> {
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Salt of the local reveal. Refused until the peer commitment is stored.
    ///
    /// # Errors
    /// Rejects a cleaned session or a missing peer commitment.
    pub fn salt(&self) -> Result<[u8; 32], CryptoError> {
        self.require_ready()?;
        Ok(self.secrets.salt)
    }

    /// Frozen local context. Refused until the peer commitment is stored.
    ///
    /// # Errors
    /// Rejects a cleaned session or a missing peer commitment.
    pub fn context(&self) -> Result<&C, CryptoError> {
        self.require_ready()?;
        Ok(&self.context)
    }

    /// Local reveal, only after the peer commitment is stored.
    ///
    /// # Errors
    /// Rejects a cleaned session or a missing peer commitment.
    pub fn reveal(&self) -> Result<([u8; 32], &C), CryptoError> {
        Ok((self.salt()?, self.context()?))
    }

    /// Store the peer commitment before any reveal is accepted.
    ///
    /// # Errors
    /// Rejects a cleaned session, the wrong peer role, or a conflicting duplicate commitment.
    pub fn store_peer_commitment(
        &mut self,
        role: PairingRole,
        commitment: [u8; 32],
    ) -> Result<(), CryptoError> {
        self.require_live()?;
        if role != self.role.peer() {
            return self.fail("role_mismatch");
        }
        match self.phase {
            Phase::Ready if self.peer_commitment == Some(commitment) => Ok(()),
            Phase::Ready => self.fail("duplicate_commit"),
            Phase::Committed => {
                self.peer_commitment = Some(commitment);
                self.phase = Phase::Ready;
                Ok(())
            }
            Phase::Dead => Err(CryptoError::Pairing("cleaned")),
        }
    }

    /// Verify the peer reveal against the frozen commitment and derive SAS/MAC/channel keys.
    ///
    /// # Errors
    /// Rejects a cleaned session, a missing/mismatched commitment, non-contributory DH, or an invalid transcript.
    pub fn establish(
        mut self,
        peer: &C,
        peer_salt: &[u8; 32],
    ) -> Result<EstablishedSas, CryptoError> {
        if self.phase == Phase::Dead {
            return Err(CryptoError::Pairing("cleaned"));
        }
        match self.establish_inner(peer, peer_salt) {
            Ok(established) => {
                self.secrets.cleanup();
                Ok(established)
            }
            Err(error) => {
                self.secrets.cleanup();
                Err(error)
            }
        }
    }

    /// Decode the peer's original bytes under this ceremony's frozen profile.
    /// # Errors
    /// A different context version returns `UpdateRequired`, without any v2/v3 fallback.
    pub fn establish_wire(
        self,
        peer: &[u8],
        salt: &[u8; 32],
    ) -> Result<EstablishedSas, CryptoError> {
        require_context_version(peer, C::VERSION)?;
        self.establish(&C::from_wire_bytes(peer)?, salt)
    }

    /// Cancel or expire a pending ceremony and wipe the SAS secret.
    pub fn cleanup(&mut self) {
        self.die();
    }

    fn die(&mut self) {
        if self.phase != Phase::Dead {
            self.phase = Phase::Dead;
            self.secrets.cleanup();
        }
    }

    fn fail<T>(&mut self, reason: &'static str) -> Result<T, CryptoError> {
        self.die();
        Err(CryptoError::Pairing(reason))
    }

    fn require_live(&self) -> Result<(), CryptoError> {
        if self.phase == Phase::Dead { Err(CryptoError::Pairing("cleaned")) } else { Ok(()) }
    }

    fn require_ready(&self) -> Result<(), CryptoError> {
        self.require_live()?;
        match self.phase {
            Phase::Ready => Ok(()),
            Phase::Committed => Err(CryptoError::Pairing("peer_commit_missing")),
            Phase::Dead => Err(CryptoError::Pairing("cleaned")),
        }
    }

    fn require_local_sas_key(&self) -> Result<(), CryptoError> {
        let local_public = PublicKey::from(&StaticSecret::from(self.secrets.sas_secret)).to_bytes();
        if encode_base64url(local_public) == self.context.sas_key() {
            Ok(())
        } else {
            Err(CryptoError::Pairing("sas_key_mismatch"))
        }
    }

    fn establish_inner(
        &mut self,
        peer: &C,
        peer_salt: &[u8; 32],
    ) -> Result<EstablishedSas, CryptoError> {
        self.require_ready()?;
        self.require_local_sas_key()?;
        let expected = self.peer_commitment.ok_or(CryptoError::Pairing("peer_commit_missing"))?;
        if PairingRole::parse(peer.role())? != self.role.peer() {
            return Err(CryptoError::Pairing("role_mismatch"));
        }
        let computed = sha256(&peer.commitment_preimage(peer_salt)?);
        if computed != expected {
            return Err(CryptoError::Pairing("commitment_mismatch"));
        }
        let ikm = Zeroizing::new(self.diffie_hellman_ikm(peer)?);
        let transcript_hash = self.transcript_hash_for(peer)?;
        derived_session(self.role, transcript_hash, ikm, Zeroizing::new(self.secrets.salt))
    }

    fn diffie_hellman_ikm(&self, peer: &C) -> Result<[u8; 32], CryptoError> {
        let peer_public = x25519_public(peer.sas_key())?;
        let local_public = PublicKey::from(&StaticSecret::from(self.secrets.sas_secret)).to_bytes();
        if peer_public == local_public {
            return Err(CryptoError::Pairing("reflection"));
        }
        let shared = StaticSecret::from(self.secrets.sas_secret)
            .diffie_hellman(&PublicKey::from(peer_public));
        if !shared.was_contributory() {
            return Err(CryptoError::Pairing("noncontributory"));
        }
        let ikm = shared.to_bytes();
        Ok(ikm)
    }

    fn transcript_hash_for(&self, peer: &C) -> Result<[u8; 32], CryptoError> {
        Ok(sha256(&self.context.paired_preimage(peer, self.role == PairingRole::Initiator)?))
    }

    #[cfg(test)]
    pub(super) fn secrets_are_cleared(&self) -> bool {
        self.secrets.is_wiped()
    }
}

impl EstablishedSas {
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }
    #[must_use]
    pub fn emoji_indices(&self) -> [u8; 7] {
        self.emoji
    }
    #[must_use]
    pub fn emoji(&self) -> [SasEmoji; 7] {
        self.emoji.map(|index| {
            let (glyph, name) = SAS_EMOJI[usize::from(index)];
            SasEmoji { index, glyph, name }
        })
    }

    /// Bind the locally displayed transcript hash. A false match consumes the ceremony.
    ///
    /// # Errors
    /// Rejects a repeat confirmation, a TH mismatch, a false comparison, or a wiped session.
    pub fn confirm_local(
        &mut self,
        displayed_hash: &[u8; 32],
        matches: bool,
    ) -> Result<[u8; 32], CryptoError> {
        self.require_live()?;
        if self.local_confirmed {
            return Err(CryptoError::Pairing("already_confirmed"));
        }
        if displayed_hash != &self.transcript_hash {
            return self.fail("transcript_hash");
        }
        if !matches {
            return self.fail("sas_mismatch");
        }
        let mac = hmac_th(self.local_confirm_key(), &self.transcript_hash)?;
        self.local_confirmed = true;
        self.drop_confirm_keys();
        Ok(mac)
    }

    /// Accept the peer role MAC. A boolean `confirmed` flag is not an input.
    ///
    /// # Errors
    /// Rejects a repeat confirmation, a MAC that does not match the peer confirm key and TH, or a wiped session.
    pub fn accept_peer_mac(&mut self, mac: &[u8; 32]) -> Result<(), CryptoError> {
        self.require_live()?;
        if self.peer_confirmed {
            return Err(CryptoError::Pairing("already_confirmed"));
        }
        let mut verifier = <HmacSha256 as hmac::KeyInit>::new_from_slice(self.peer_confirm_key())
            .map_err(|_| CryptoError::HmacFailed)?;
        verifier.update(&self.transcript_hash);
        if verifier.verify_slice(mac).is_err() {
            return self.fail("confirm_mac");
        }
        self.peer_confirmed = true;
        self.drop_confirm_keys();
        Ok(())
    }

    /// Seal a channel frame. Nonce is the big-endian send counter in a 12-byte AEAD nonce.
    ///
    /// # Errors
    /// Rejects use before both confirmations, AEAD failure, or a wiped session.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), CryptoError> {
        self.require_channel()?;
        let counter = self.send_counter;
        let Some(next) = counter.checked_add(1) else {
            return self.fail("channel_counter");
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.send_key()));
        let nonce = nonce96(counter);
        let Ok(ciphertext) =
            cipher.encrypt(&nonce, Payload { msg: plaintext, aad: &self.transcript_hash })
        else {
            return self.fail("channel_aead");
        };
        self.send_counter = next;
        Ok((counter, ciphertext))
    }

    /// Open a channel frame. Counters must be consecutive from 0 with no replay.
    ///
    /// # Errors
    /// Rejects a skipped/repeated counter, AEAD failure, or use before both confirmations.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.require_channel()?;
        if counter != self.recv_counter {
            return self.fail("channel_counter");
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.recv_key()));
        let nonce = nonce96(counter);
        let Ok(plaintext) =
            cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: &self.transcript_hash })
        else {
            return self.fail("channel_aead");
        };
        let Some(next) = self.recv_counter.checked_add(1) else {
            return self.fail("channel_counter");
        };
        self.recv_counter = next;
        Ok(Zeroizing::new(plaintext))
    }

    /// Wipe remaining keys after success, cancel, expiry or caller-driven abort.
    pub fn cleanup(&mut self) {
        self.dead = true;
        self.local_confirmed = false;
        self.peer_confirmed = false;
        self.secrets.cleanup();
    }

    fn require_live(&self) -> Result<(), CryptoError> {
        if self.dead { Err(CryptoError::Pairing("cleaned")) } else { Ok(()) }
    }
    fn require_channel(&mut self) -> Result<(), CryptoError> {
        self.require_live()?;
        if self.local_confirmed && self.peer_confirmed {
            Ok(())
        } else {
            self.fail("human_confirmation_required")
        }
    }
    fn fail<T>(&mut self, reason: &'static str) -> Result<T, CryptoError> {
        self.cleanup();
        Err(CryptoError::Pairing(reason))
    }
    fn drop_confirm_keys(&mut self) {
        if self.local_confirmed && self.peer_confirmed {
            self.secrets.confirm_i.zeroize();
            self.secrets.confirm_r.zeroize();
        }
    }
    fn local_confirm_key(&self) -> &[u8; 32] {
        match self.role {
            PairingRole::Initiator => &self.secrets.confirm_i,
            PairingRole::Responder => &self.secrets.confirm_r,
        }
    }
    fn peer_confirm_key(&self) -> &[u8; 32] {
        match self.role {
            PairingRole::Initiator => &self.secrets.confirm_r,
            PairingRole::Responder => &self.secrets.confirm_i,
        }
    }
    fn send_key(&self) -> &[u8; 32] {
        match self.role {
            PairingRole::Initiator => &self.secrets.channel_i,
            PairingRole::Responder => &self.secrets.channel_r,
        }
    }
    fn recv_key(&self) -> &[u8; 32] {
        match self.role {
            PairingRole::Initiator => &self.secrets.channel_r,
            PairingRole::Responder => &self.secrets.channel_i,
        }
    }

    #[cfg(test)]
    pub(super) fn secrets_are_cleared(&self) -> bool {
        self.secrets.is_wiped()
    }
}

/// Map seven 6-bit indices onto the Matrix SAS table.
///
/// # Errors
/// Rejects an index greater than 63.
pub fn emoji_from_indices(indices: [u8; 7]) -> Result<[SasEmoji; 7], CryptoError> {
    let mut out = [SasEmoji { index: 0, glyph: SAS_EMOJI[0].0, name: SAS_EMOJI[0].1 }; 7];
    for (slot, index) in out.iter_mut().zip(indices) {
        *slot = sas_emoji(index)?;
    }
    Ok(out)
}

fn sas_emoji(index: u8) -> Result<SasEmoji, CryptoError> {
    let (glyph, name) =
        SAS_EMOJI.get(usize::from(index)).ok_or(CryptoError::Pairing("emoji_index"))?;
    Ok(SasEmoji { index, glyph, name })
}

fn derived_session(
    role: PairingRole,
    transcript_hash: [u8; 32],
    shared: Zeroizing<[u8; 32]>,
    salt: Zeroizing<[u8; 32]>,
) -> Result<EstablishedSas, CryptoError> {
    let mut secrets = PairingSecrets::pending([0; 32], *salt);
    secrets.shared = *shared;
    drop(shared);
    drop(salt);
    expand(
        &secrets.shared,
        &transcript_hash,
        domain::CUSTODY_PAIRING_CONFIRM_INITIATOR,
        &mut secrets.confirm_i,
    )?;
    expand(
        &secrets.shared,
        &transcript_hash,
        domain::CUSTODY_PAIRING_CONFIRM_RESPONDER,
        &mut secrets.confirm_r,
    )?;
    expand(
        &secrets.shared,
        &transcript_hash,
        domain::CUSTODY_PAIRING_CHANNEL_INITIATOR,
        &mut secrets.channel_i,
    )?;
    expand(
        &secrets.shared,
        &transcript_hash,
        domain::CUSTODY_PAIRING_CHANNEL_RESPONDER,
        &mut secrets.channel_r,
    )?;
    let mut sas_bytes = [0_u8; 6];
    expand(&secrets.shared, &transcript_hash, domain::CUSTODY_PAIRING_SAS, &mut sas_bytes)?;
    let emoji = emoji_indices(sas_bytes);
    sas_bytes.zeroize();
    secrets.shared.zeroize();
    secrets.salt.zeroize();
    Ok(EstablishedSas {
        role,
        dead: false,
        transcript_hash,
        emoji,
        local_confirmed: false,
        peer_confirmed: false,
        send_counter: 0,
        recv_counter: 0,
        secrets,
    })
}

pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn expand(ikm: &[u8; 32], salt: &[u8; 32], info: &str, out: &mut [u8]) -> Result<(), CryptoError> {
    hkdf_sha256(salt, ikm, info.as_bytes(), out)
}

fn hmac_th(key: &[u8; 32], transcript_hash: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|_| CryptoError::HmacFailed)?;
    mac.update(transcript_hash);
    Ok(mac.finalize().into_bytes().into())
}

fn nonce96(counter: u64) -> Nonce {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

fn x25519_public(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = decode_base64url(value).map_err(|_| CryptoError::Pairing("sas_key"))?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::Pairing("sas_key"))?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::Pairing("all_zero_sas_key"));
    }
    Ok(key)
}

fn emoji_indices(bytes: [u8; 6]) -> [u8; 7] {
    let packed =
        u64::from_be_bytes([0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]) >> 6;
    core::array::from_fn(|index| ((packed >> (36 - 6 * index)) & 0x3f) as u8)
}
