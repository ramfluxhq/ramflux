use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ramflux_protocol::{
    HeaderField, HeaderKind, canonical_header_bytes, encode_base64url, header_hash_base64url,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CryptoError, FrankingCommitmentInput, X25519KeyPair, blake3_256, franking_commitment,
    hkdf_sha256,
};

const ROLE_INITIATOR_SEND: &[u8] = b"initiator_send";
const ROLE_RECIPIENT_SEND: &[u8] = b"recipient_send";
const DIRECTION_SEND: &[u8] = b"send";
const DIRECTION_RECV: &[u8] = b"recv";

struct RatchetContextParts<'a> {
    session_id: &'a str,
    local_device_id_hash: [u8; 32],
    remote_device_id_hash: [u8; 32],
    device_epoch_local: u64,
    device_epoch_remote: u64,
    dh_ratchet_step: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmSession {
    pub session_id: String,
    pub bootstrap_transcript_hash: [u8; 32],
    pub root_key: Secret32,
    pub sending_chain_key: Secret32,
    pub receiving_chain_key: Secret32,
    pub send_counter: u64,
    pub receive_counter: u64,
    pub dhs_private: Option<Secret32>,
    pub dhs_public: Option<[u8; 32]>,
    pub dhr_public: Option<[u8; 32]>,
    pub sender_device_id_hash: [u8; 32],
    pub recipient_device_id_hash: [u8; 32],
    pub device_epoch_local: u64,
    pub device_epoch_remote: u64,
    pub dh_ratchet_step: u64,
    pub is_initiator_side: bool,
    pub previous_sending_chain_length: u64,
    pub max_skip: usize,
    pub skipped_message_keys: BTreeMap<String, MessageKeys>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmSessionSnapshot {
    schema: String,
    version: u32,
    session_id: String,
    bootstrap_transcript_hash: [u8; 32],
    root_key: [u8; 32],
    sending_chain_key: [u8; 32],
    receiving_chain_key: [u8; 32],
    send_counter: u64,
    receive_counter: u64,
    dhs_private: Option<[u8; 32]>,
    dhs_public: Option<[u8; 32]>,
    dhr_public: Option<[u8; 32]>,
    sender_device_id_hash: [u8; 32],
    recipient_device_id_hash: [u8; 32],
    device_epoch_local: u64,
    device_epoch_remote: u64,
    dh_ratchet_step: u64,
    is_initiator_side: bool,
    previous_sending_chain_length: u64,
    max_skip: usize,
    skipped_message_keys: BTreeMap<String, MessageKeysSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmCiphertext {
    pub session_id: String,
    pub counter: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub ratchet_public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub previous_chain_length: u64,
    #[serde(default)]
    pub sender_device_id_hash: [u8; 32],
    #[serde(default)]
    pub recipient_device_id_hash: [u8; 32],
    #[serde(default)]
    pub device_epoch: u64,
    #[serde(default)]
    pub message_event_id: String,
    #[serde(default)]
    pub canonical_header_bytes: Vec<u8>,
    #[serde(default)]
    pub header_hash: String,
    #[serde(default)]
    pub key_commitment: String,
    #[serde(default)]
    pub franking_commitment: String,
    #[serde(default)]
    pub commitment: String,
    #[serde(default)]
    pub ciphertext_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct MessageKeys {
    pub aead_key: [u8; 32],
    pub nonce: [u8; 12],
    pub commitment_key: [u8; 32],
    pub opening_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MessageKeysSnapshot {
    aead_key: [u8; 32],
    nonce: [u8; 12],
    commitment_key: [u8; 32],
    opening_key: [u8; 32],
}

impl DmSessionSnapshot {
    #[must_use]
    pub const fn root_key_bytes(&self) -> [u8; 32] {
        self.root_key
    }
}

impl DmSession {
    /// # Errors
    /// Returns an error when KDF expansion fails.
    pub fn initiator(
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let session_id = ratchet_session_id(
            &local_device_id_hash,
            &remote_device_id_hash,
            &bootstrap_transcript_hash,
        );
        let (send, recv) = derive_initial_chains(
            &root_seed,
            &RatchetContextParts {
                session_id: &session_id,
                local_device_id_hash,
                remote_device_id_hash,
                device_epoch_local: 0,
                device_epoch_remote: 0,
                dh_ratchet_step: 0,
            },
        )?;
        Ok(Self::new(
            session_id,
            bootstrap_transcript_hash,
            root_seed,
            send,
            recv,
            None,
            None,
            None,
            local_device_id_hash,
            remote_device_id_hash,
            true,
        ))
    }

    /// # Errors
    /// Returns an error when KDF expansion fails.
    pub fn recipient(
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let session_id = ratchet_session_id(
            &remote_device_id_hash,
            &local_device_id_hash,
            &bootstrap_transcript_hash,
        );
        let (recv, send) = derive_initial_chains(
            &root_seed,
            &RatchetContextParts {
                session_id: &session_id,
                local_device_id_hash: remote_device_id_hash,
                remote_device_id_hash: local_device_id_hash,
                device_epoch_local: 0,
                device_epoch_remote: 0,
                dh_ratchet_step: 0,
            },
        )?;
        Ok(Self::new(
            session_id,
            bootstrap_transcript_hash,
            root_seed,
            send,
            recv,
            None,
            None,
            None,
            local_device_id_hash,
            remote_device_id_hash,
            false,
        ))
    }

    /// # Errors
    /// Returns an error when the initial DH ratchet cannot derive its sending chain.
    pub fn initiator_with_remote_ratchet(
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
        local_ratchet: &X25519KeyPair,
        remote_ratchet_public: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let session_id = ratchet_session_id(
            &local_device_id_hash,
            &remote_device_id_hash,
            &bootstrap_transcript_hash,
        );
        let dh = local_ratchet.secret.diffie_hellman(&X25519PublicKey::from(remote_ratchet_public));
        let context = RatchetContextParts {
            session_id: &session_id,
            local_device_id_hash,
            remote_device_id_hash,
            device_epoch_local: 0,
            device_epoch_remote: 0,
            dh_ratchet_step: 0,
        };
        let (root_key, sending_chain_key) =
            derive_root_and_chain(&root_seed, dh.as_bytes(), &context, ROLE_INITIATOR_SEND)?;
        let (_unused_recv, receiving_chain_key) = derive_initial_chains(&root_key, &context)?;
        let mut session = Self::new(
            session_id,
            bootstrap_transcript_hash,
            root_key,
            sending_chain_key,
            receiving_chain_key,
            Some(local_ratchet.secret.to_bytes()),
            Some(local_ratchet.public),
            Some(remote_ratchet_public),
            local_device_id_hash,
            remote_device_id_hash,
            true,
        );
        session.dh_ratchet_step = 1;
        Ok(session)
    }

    /// # Errors
    /// Returns an error when the recipient session cannot be initialized.
    pub fn recipient_with_local_ratchet(
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
        local_ratchet: &X25519KeyPair,
    ) -> Result<Self, CryptoError> {
        let session_id = ratchet_session_id(
            &remote_device_id_hash,
            &local_device_id_hash,
            &bootstrap_transcript_hash,
        );
        let (receiving_chain_key, sending_chain_key) = derive_initial_chains(
            &root_seed,
            &RatchetContextParts {
                session_id: &session_id,
                local_device_id_hash: remote_device_id_hash,
                remote_device_id_hash: local_device_id_hash,
                device_epoch_local: 0,
                device_epoch_remote: 0,
                dh_ratchet_step: 0,
            },
        )?;
        Ok(Self::new(
            session_id,
            bootstrap_transcript_hash,
            root_seed,
            sending_chain_key,
            receiving_chain_key,
            Some(local_ratchet.secret.to_bytes()),
            Some(local_ratchet.public),
            None,
            local_device_id_hash,
            remote_device_id_hash,
            false,
        ))
    }

    #[must_use]
    pub fn with_header_identity(
        mut self,
        sender_device_id_hash: [u8; 32],
        recipient_device_id_hash: [u8; 32],
        device_epoch: u64,
    ) -> Self {
        self.sender_device_id_hash = sender_device_id_hash;
        self.recipient_device_id_hash = recipient_device_id_hash;
        self.device_epoch_local = device_epoch;
        self
    }

    #[must_use]
    pub const fn with_device_epochs(
        mut self,
        device_epoch_local: u64,
        device_epoch_remote: u64,
    ) -> Self {
        self.device_epoch_local = device_epoch_local;
        self.device_epoch_remote = device_epoch_remote;
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        session_id: String,
        bootstrap_transcript_hash: [u8; 32],
        root_key: [u8; 32],
        sending_chain_key: [u8; 32],
        receiving_chain_key: [u8; 32],
        dhs_private: Option<[u8; 32]>,
        local_public: Option<[u8; 32]>,
        remote_public: Option<[u8; 32]>,
        sender_device_id_hash: [u8; 32],
        recipient_device_id_hash: [u8; 32],
        is_initiator_side: bool,
    ) -> Self {
        Self {
            session_id,
            bootstrap_transcript_hash,
            root_key: Secret32::new(root_key),
            sending_chain_key: Secret32::new(sending_chain_key),
            receiving_chain_key: Secret32::new(receiving_chain_key),
            send_counter: 0,
            receive_counter: 0,
            dhs_private: dhs_private.map(Secret32::new),
            dhs_public: local_public,
            dhr_public: remote_public,
            sender_device_id_hash,
            recipient_device_id_hash,
            device_epoch_local: 0,
            device_epoch_remote: 0,
            dh_ratchet_step: 0,
            is_initiator_side,
            previous_sending_chain_length: 0,
            max_skip: default_dm_max_skip(),
            skipped_message_keys: BTreeMap::new(),
        }
    }

    /// # Errors
    /// Returns an error when encryption, canonical header encoding, or KDF expansion fails.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<DmCiphertext, CryptoError> {
        let counter = self.send_counter;
        let ratchet_public_key = self.dhs_public;
        let previous_chain_length = self.previous_sending_chain_length;
        let message_event_id = format!("{}:{counter}", self.session_id);
        let send_direction_tag = self.send_direction_tag();
        let direction_context = self.direction_context(
            send_direction_tag,
            &ratchet_public_key.unwrap_or([0_u8; 32]),
            counter,
            self.device_epoch_remote,
        );
        let (next_chain, message_secret) =
            kdf_ck(self.sending_chain_key.expose(), &direction_context)?;
        let header = DmHeader {
            ratchet_session_id: self.session_id.clone(),
            sender_device_id_hash: self.sender_device_id_hash,
            recipient_device_id_hash: self.recipient_device_id_hash,
            dh_ratchet_public: ratchet_public_key.unwrap_or([0_u8; 32]),
            pn: previous_chain_length,
            n: counter,
            device_epoch: self.device_epoch_local,
            message_event_id,
        };
        let canonical = header.canonical_header_bytes()?;
        let message_context =
            self.message_context(send_direction_tag, counter, &canonical, associated_data);
        let message_keys = derive_message_keys(&message_secret, &message_context)?;
        let aad = dm_header_associated_data(associated_data, &canonical);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_keys.aead_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&message_keys.nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_err| CryptoError::AeadFailed)?;
        let commitments = franking_commitment(&FrankingCommitmentInput {
            plaintext,
            sender_device_id_hash: &self.sender_device_id_hash,
            message_event_id: &header.message_event_id,
            canonical_header_bytes: &canonical,
            associated_data,
            ciphertext: &ciphertext,
            opening_key: &message_keys.opening_key,
            commitment_key: &message_keys.commitment_key,
        });
        self.sending_chain_key = Secret32::new(next_chain);
        self.send_counter = self.send_counter.saturating_add(1);
        Ok(DmCiphertext {
            session_id: self.session_id.clone(),
            counter,
            nonce: message_keys.nonce,
            ciphertext,
            ratchet_public_key,
            previous_chain_length,
            sender_device_id_hash: self.sender_device_id_hash,
            recipient_device_id_hash: self.recipient_device_id_hash,
            device_epoch: self.device_epoch_local,
            message_event_id: header.message_event_id,
            canonical_header_bytes: canonical,
            header_hash: commitments.header_hash,
            key_commitment: commitments.key_commitment,
            franking_commitment: commitments.franking_commitment,
            commitment: commitments.commitment,
            ciphertext_hash: commitments.ciphertext_hash,
        })
    }

    /// # Errors
    /// Returns an error when ratchet validation, commitment verification, or decryption fails.
    pub fn decrypt(
        &mut self,
        ciphertext: &DmCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let header = DmHeader {
            ratchet_session_id: ciphertext.session_id.clone(),
            sender_device_id_hash: ciphertext.sender_device_id_hash,
            recipient_device_id_hash: ciphertext.recipient_device_id_hash,
            dh_ratchet_public: ciphertext.ratchet_public_key.unwrap_or([0_u8; 32]),
            pn: ciphertext.previous_chain_length,
            n: ciphertext.counter,
            device_epoch: ciphertext.device_epoch,
            message_event_id: ciphertext.message_event_id.clone(),
        };
        let canonical = header.canonical_header_bytes()?;
        let computed_header_hash = header_hash_base64url(HeaderKind::DmMessage, &header.fields());
        if computed_header_hash? != ciphertext.header_hash {
            return Err(CryptoError::CommitmentMismatch);
        }
        let skipped_key_id = Some(skipped_key_id(
            &ciphertext.ratchet_public_key.unwrap_or([0_u8; 32]),
            ciphertext.counter,
        ));
        let mut used_skipped_key = false;
        let message_keys = if let Some(key_id) = skipped_key_id
            && let Some(message_keys) = self.skipped_message_keys.remove(&key_id)
        {
            used_skipped_key = true;
            message_keys
        } else {
            self.ratchet_for_header(&header, associated_data)?;
            if ciphertext.counter < self.receive_counter {
                return Err(CryptoError::AeadFailed);
            }
            self.skip_message_keys(ciphertext.counter, &header, associated_data)?;
            let recv_direction_tag = self.recv_direction_tag();
            let remote_epoch = header.device_epoch;
            let direction_context = self.direction_context(
                recv_direction_tag,
                &header.dh_ratchet_public,
                ciphertext.counter,
                remote_epoch,
            );
            let (_next_chain, message_secret) =
                kdf_ck(self.receiving_chain_key.expose(), &direction_context)?;
            let message_context = self.message_context(
                recv_direction_tag,
                ciphertext.counter,
                &canonical,
                associated_data,
            );
            derive_message_keys(&message_secret, &message_context)?
        };
        let aad = dm_header_associated_data(associated_data, &canonical);
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(&message_keys.aead_key))
            .decrypt(
                Nonce::from_slice(&ciphertext.nonce),
                Payload { msg: ciphertext.ciphertext.as_ref(), aad: &aad },
            )
            .map_err(|_err| CryptoError::AeadFailed)?;
        verify_commitments(ciphertext, &plaintext, associated_data, &canonical, &message_keys)?;
        if !used_skipped_key {
            let recv_direction_tag = self.recv_direction_tag();
            self.receiving_chain_key = Secret32::new(advance_chain_key(
                self.receiving_chain_key.expose(),
                &self.direction_context(
                    recv_direction_tag,
                    &header.dh_ratchet_public,
                    ciphertext.counter,
                    header.device_epoch,
                ),
            )?);
            self.receive_counter = self.receive_counter.saturating_add(1);
        }
        Ok(plaintext)
    }

    #[must_use]
    pub fn ratchet_public_key(&self) -> Option<[u8; 32]> {
        self.dhs_public
    }

    #[must_use]
    pub fn snapshot(&self) -> DmSessionSnapshot {
        DmSessionSnapshot {
            schema: "ramflux.dm_session.snapshot.v1".to_owned(),
            version: 1,
            session_id: self.session_id.clone(),
            bootstrap_transcript_hash: self.bootstrap_transcript_hash,
            root_key: *self.root_key.expose(),
            sending_chain_key: *self.sending_chain_key.expose(),
            receiving_chain_key: *self.receiving_chain_key.expose(),
            send_counter: self.send_counter,
            receive_counter: self.receive_counter,
            dhs_private: self.dhs_private.as_ref().map(|secret| *secret.expose()),
            dhs_public: self.dhs_public,
            dhr_public: self.dhr_public,
            sender_device_id_hash: self.sender_device_id_hash,
            recipient_device_id_hash: self.recipient_device_id_hash,
            device_epoch_local: self.device_epoch_local,
            device_epoch_remote: self.device_epoch_remote,
            dh_ratchet_step: self.dh_ratchet_step,
            is_initiator_side: self.is_initiator_side,
            previous_sending_chain_length: self.previous_sending_chain_length,
            max_skip: self.max_skip,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(key_id, keys)| {
                    (
                        key_id.clone(),
                        MessageKeysSnapshot {
                            aead_key: keys.aead_key,
                            nonce: keys.nonce,
                            commitment_key: keys.commitment_key,
                            opening_key: keys.opening_key,
                        },
                    )
                })
                .collect(),
        }
    }

    /// # Errors
    /// Returns an error when the snapshot schema or version is unsupported.
    pub fn from_snapshot(snapshot: DmSessionSnapshot) -> Result<Self, CryptoError> {
        if snapshot.schema != "ramflux.dm_session.snapshot.v1" || snapshot.version != 1 {
            return Err(CryptoError::UnsupportedDmSessionSnapshot);
        }
        Ok(Self {
            session_id: snapshot.session_id,
            bootstrap_transcript_hash: snapshot.bootstrap_transcript_hash,
            root_key: Secret32::new(snapshot.root_key),
            sending_chain_key: Secret32::new(snapshot.sending_chain_key),
            receiving_chain_key: Secret32::new(snapshot.receiving_chain_key),
            send_counter: snapshot.send_counter,
            receive_counter: snapshot.receive_counter,
            dhs_private: snapshot.dhs_private.map(Secret32::new),
            dhs_public: snapshot.dhs_public,
            dhr_public: snapshot.dhr_public,
            sender_device_id_hash: snapshot.sender_device_id_hash,
            recipient_device_id_hash: snapshot.recipient_device_id_hash,
            device_epoch_local: snapshot.device_epoch_local,
            device_epoch_remote: snapshot.device_epoch_remote,
            dh_ratchet_step: snapshot.dh_ratchet_step,
            is_initiator_side: snapshot.is_initiator_side,
            previous_sending_chain_length: snapshot.previous_sending_chain_length,
            max_skip: snapshot.max_skip,
            skipped_message_keys: snapshot
                .skipped_message_keys
                .into_iter()
                .map(|(key_id, keys)| {
                    (
                        key_id,
                        MessageKeys {
                            aead_key: keys.aead_key,
                            nonce: keys.nonce,
                            commitment_key: keys.commitment_key,
                            opening_key: keys.opening_key,
                        },
                    )
                })
                .collect(),
        })
    }

    fn ratchet_for_header(
        &mut self,
        header: &DmHeader,
        associated_data: &[u8],
    ) -> Result<(), CryptoError> {
        let remote_public = header.dh_ratchet_public;
        if remote_public == [0_u8; 32] || self.dhr_public == Some(remote_public) {
            return Ok(());
        }
        self.skip_message_keys(header.pn, header, associated_data)?;
        self.dhr_public = Some(remote_public);
        let local_private = self.dhs_private.as_ref().ok_or(CryptoError::AeadFailed)?;
        let dh = StaticSecret::from(*local_private.expose())
            .diffie_hellman(&X25519PublicKey::from(remote_public));
        self.device_epoch_remote = header.device_epoch;
        let (root_key, receiving_chain_key) = derive_root_and_chain(
            self.root_key.expose(),
            dh.as_bytes(),
            &self.ratchet_context_parts(),
            self.remote_sender_role_tag(),
        )?;
        self.root_key = Secret32::new(root_key);
        self.receiving_chain_key = Secret32::new(receiving_chain_key);
        self.dh_ratchet_step = self.dh_ratchet_step.saturating_add(1);
        self.receive_counter = 0;

        self.previous_sending_chain_length = self.send_counter;
        let new_local = X25519KeyPair::random()?;
        let dh = new_local.secret.diffie_hellman(&X25519PublicKey::from(remote_public));
        let (root_key, sending_chain_key) = derive_root_and_chain(
            self.root_key.expose(),
            dh.as_bytes(),
            &self.ratchet_context_parts(),
            self.local_sender_role_tag(),
        )?;
        self.root_key = Secret32::new(root_key);
        self.sending_chain_key = Secret32::new(sending_chain_key);
        self.dh_ratchet_step = self.dh_ratchet_step.saturating_add(1);
        self.dhs_private = Some(Secret32::new(new_local.secret.to_bytes()));
        self.dhs_public = Some(new_local.public);
        self.send_counter = 0;
        Ok(())
    }

    fn direction_context(
        &self,
        direction_tag: &[u8],
        dh_ratchet_public: &[u8; 32],
        chain_index: u64,
        device_epoch_remote: u64,
    ) -> Vec<u8> {
        let (device_epoch_local, device_epoch_remote) =
            self.canonical_epoch_pair(device_epoch_remote);
        direction_context(
            &self.session_id,
            direction_tag,
            dh_ratchet_public,
            chain_index,
            device_epoch_local,
            device_epoch_remote,
        )
    }

    const fn canonical_epoch_pair(&self, current_remote_epoch: u64) -> (u64, u64) {
        if self.is_initiator_side {
            (self.device_epoch_local, current_remote_epoch)
        } else {
            (current_remote_epoch, self.device_epoch_local)
        }
    }

    const fn canonical_device_hash_pair(&self) -> ([u8; 32], [u8; 32]) {
        if self.is_initiator_side {
            (self.sender_device_id_hash, self.recipient_device_id_hash)
        } else {
            (self.recipient_device_id_hash, self.sender_device_id_hash)
        }
    }

    fn ratchet_context_parts(&self) -> RatchetContextParts<'_> {
        let (local_device_id_hash, remote_device_id_hash) = self.canonical_device_hash_pair();
        let (device_epoch_local, device_epoch_remote) =
            self.canonical_epoch_pair(self.device_epoch_remote);
        RatchetContextParts {
            session_id: &self.session_id,
            local_device_id_hash,
            remote_device_id_hash,
            device_epoch_local,
            device_epoch_remote,
            dh_ratchet_step: self.dh_ratchet_step,
        }
    }

    const fn send_direction_tag(&self) -> &'static [u8] {
        if self.is_initiator_side { DIRECTION_SEND } else { DIRECTION_RECV }
    }

    const fn recv_direction_tag(&self) -> &'static [u8] {
        if self.is_initiator_side { DIRECTION_RECV } else { DIRECTION_SEND }
    }

    const fn local_sender_role_tag(&self) -> &'static [u8] {
        if self.is_initiator_side { ROLE_INITIATOR_SEND } else { ROLE_RECIPIENT_SEND }
    }

    const fn remote_sender_role_tag(&self) -> &'static [u8] {
        if self.is_initiator_side { ROLE_RECIPIENT_SEND } else { ROLE_INITIATOR_SEND }
    }

    fn message_context(
        &self,
        direction_tag: &[u8],
        message_number: u64,
        canonical_header: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        message_context(
            &self.session_id,
            direction_tag,
            message_number,
            canonical_header,
            associated_data,
        )
    }

    fn skip_message_keys(
        &mut self,
        until_counter: u64,
        reference_header: &DmHeader,
        associated_data: &[u8],
    ) -> Result<(), CryptoError> {
        if until_counter < self.receive_counter {
            return Ok(());
        }
        let skipped = until_counter.saturating_sub(self.receive_counter);
        if usize::try_from(skipped).map_or(true, |skipped| skipped > self.max_skip) {
            return Err(CryptoError::MaxSkipExceeded);
        }
        let remote_public = self.dhr_public.unwrap_or([0_u8; 32]);
        while self.receive_counter < until_counter {
            let mut skipped_header = reference_header.clone();
            skipped_header.n = self.receive_counter;
            skipped_header.message_event_id =
                format!("{}:{}", self.session_id, self.receive_counter);
            let recv_direction_tag = self.recv_direction_tag();
            let direction_context = self.direction_context(
                recv_direction_tag,
                &skipped_header.dh_ratchet_public,
                self.receive_counter,
                skipped_header.device_epoch,
            );
            let (_next_chain, message_secret) =
                kdf_ck(self.receiving_chain_key.expose(), &direction_context)?;
            let canonical = skipped_header.canonical_header_bytes()?;
            let message_context = self.message_context(
                recv_direction_tag,
                self.receive_counter,
                &canonical,
                associated_data,
            );
            let key = derive_message_keys(&message_secret, &message_context)?;
            self.skipped_message_keys
                .insert(skipped_key_id(&remote_public, self.receive_counter), key);
            self.receiving_chain_key = Secret32::new(advance_chain_key(
                self.receiving_chain_key.expose(),
                &direction_context,
            )?);
            self.receive_counter = self.receive_counter.saturating_add(1);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DmHeader {
    ratchet_session_id: String,
    sender_device_id_hash: [u8; 32],
    recipient_device_id_hash: [u8; 32],
    dh_ratchet_public: [u8; 32],
    pn: u64,
    n: u64,
    device_epoch: u64,
    message_event_id: String,
}

impl DmHeader {
    fn fields(&self) -> [HeaderField; 8] {
        [
            HeaderField::string(1, self.ratchet_session_id.clone()),
            HeaderField::bytes32(2, self.sender_device_id_hash),
            HeaderField::bytes32(3, self.recipient_device_id_hash),
            HeaderField::bytes32(4, self.dh_ratchet_public),
            HeaderField::u64(5, self.pn),
            HeaderField::u64(6, self.n),
            HeaderField::u64(7, self.device_epoch),
            HeaderField::string(8, self.message_event_id.clone()),
        ]
    }

    fn canonical_header_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(canonical_header_bytes(HeaderKind::DmMessage, &self.fields())?)
    }
}

const fn default_dm_max_skip() -> usize {
    1000
}

#[must_use]
pub fn ratchet_session_id(
    local_device_id_hash: &[u8; 32],
    remote_device_id_hash: &[u8; 32],
    bootstrap_transcript_hash: &[u8; 32],
) -> String {
    encode_base64url(ratchet_session_id_bytes(
        local_device_id_hash,
        remote_device_id_hash,
        bootstrap_transcript_hash,
    ))
}

#[must_use]
pub fn ratchet_session_id_bytes(
    local_device_id_hash: &[u8; 32],
    remote_device_id_hash: &[u8; 32],
    bootstrap_transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        ramflux_protocol::domain::DM_RATCHET_ROOT.len() + local_device_id_hash.len() * 2 + 32,
    );
    input.extend_from_slice(ramflux_protocol::domain::DM_RATCHET_ROOT.as_bytes());
    input.extend_from_slice(local_device_id_hash);
    input.extend_from_slice(remote_device_id_hash);
    input.extend_from_slice(bootstrap_transcript_hash);
    blake3_256(ramflux_protocol::domain::DM_RATCHET_ROOT, &input)
}

fn skipped_key_id(ratchet_public_key: &[u8; 32], counter: u64) -> String {
    format!("{}:{counter}", encode_base64url(ratchet_public_key))
}

fn dm_header_associated_data(associated_data: &[u8], canonical_header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(associated_data);
    aad.extend_from_slice(canonical_header);
    aad
}

fn derive_root_and_chain(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
    context_parts: &RatchetContextParts<'_>,
    role_tag: &[u8],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let transcript_context = transcript_context(context_parts, role_tag);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::DM_RATCHET_ROOT.as_bytes());
    info.extend_from_slice(&transcript_context);
    let mut output = [0_u8; 64];
    hkdf_sha256(root_key, dh_output, &info, &mut output)?;
    let mut new_root = [0_u8; 32];
    new_root.copy_from_slice(&output[..32]);
    let mut chain = [0_u8; 32];
    chain.copy_from_slice(&output[32..]);
    Ok((new_root, chain))
}

fn derive_initial_chains(
    root_seed: &[u8; 32],
    context_parts: &RatchetContextParts<'_>,
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let (_root_initiator, initiator_send_chain) =
        derive_root_and_chain(root_seed, root_seed, context_parts, ROLE_INITIATOR_SEND)?;
    let (_root_recipient, recipient_send_chain) =
        derive_root_and_chain(root_seed, root_seed, context_parts, ROLE_RECIPIENT_SEND)?;
    Ok((initiator_send_chain, recipient_send_chain))
}

fn kdf_ck(
    chain_key: &[u8; 32],
    direction_context: &[u8],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let salt = blake3_256(ramflux_protocol::domain::DM_RATCHET_CHAIN, direction_context);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::DM_RATCHET_CHAIN.as_bytes());
    info.extend_from_slice(direction_context);
    let mut output = [0_u8; 64];
    hkdf_sha256(&salt, chain_key, &info, &mut output)?;
    let mut next_chain = [0_u8; 32];
    next_chain.copy_from_slice(&output[..32]);
    let mut message_secret = [0_u8; 32];
    message_secret.copy_from_slice(&output[32..]);
    Ok((next_chain, message_secret))
}

fn advance_chain_key(
    chain_key: &[u8; 32],
    direction_context: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let (next, _message_secret) = kdf_ck(chain_key, direction_context)?;
    Ok(next)
}

fn transcript_context(parts: &RatchetContextParts<'_>, role_tag: &[u8]) -> Vec<u8> {
    let mut context =
        Vec::with_capacity(parts.session_id.len() + 32 + 32 + 8 + 8 + 8 + role_tag.len());
    context.extend_from_slice(parts.session_id.as_bytes());
    context.extend_from_slice(&parts.local_device_id_hash);
    context.extend_from_slice(&parts.remote_device_id_hash);
    context.extend_from_slice(&parts.device_epoch_local.to_be_bytes());
    context.extend_from_slice(&parts.device_epoch_remote.to_be_bytes());
    context.extend_from_slice(&parts.dh_ratchet_step.to_be_bytes());
    context.extend_from_slice(role_tag);
    context
}

fn direction_context(
    session_id: &str,
    direction_tag: &[u8],
    dh_ratchet_public: &[u8; 32],
    chain_index: u64,
    device_epoch_local: u64,
    device_epoch_remote: u64,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(session_id.len() + direction_tag.len() + 32 + 8 + 8 + 8);
    context.extend_from_slice(session_id.as_bytes());
    context.extend_from_slice(direction_tag);
    context.extend_from_slice(dh_ratchet_public);
    context.extend_from_slice(&chain_index.to_be_bytes());
    context.extend_from_slice(&device_epoch_local.to_be_bytes());
    context.extend_from_slice(&device_epoch_remote.to_be_bytes());
    context
}

fn message_context(
    session_id: &str,
    direction_tag: &[u8],
    message_number: u64,
    canonical_header: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let header_hash = ramflux_protocol::blake3_hash_bytes(
        ramflux_protocol::domain::COMMITTING_AEAD_HEADER,
        canonical_header,
    );
    let associated_data_hash =
        blake3_256(ramflux_protocol::domain::DM_RATCHET_MESSAGE, associated_data);
    let mut context = Vec::with_capacity(session_id.len() + direction_tag.len() + 8 + 32 + 32);
    context.extend_from_slice(session_id.as_bytes());
    context.extend_from_slice(direction_tag);
    context.extend_from_slice(&message_number.to_be_bytes());
    context.extend_from_slice(&header_hash);
    context.extend_from_slice(&associated_data_hash);
    context
}

pub(crate) fn derive_message_keys(
    message_secret: &[u8; 32],
    message_context: &[u8],
) -> Result<MessageKeys, CryptoError> {
    let salt = blake3_256(ramflux_protocol::domain::DM_RATCHET_MESSAGE, message_context);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::DM_RATCHET_MESSAGE.as_bytes());
    info.extend_from_slice(message_context);
    let mut output = [0_u8; 108];
    hkdf_sha256(&salt, message_secret, &info, &mut output)?;
    let mut aead_key = [0_u8; 32];
    aead_key.copy_from_slice(&output[..32]);
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&output[32..44]);
    let mut commitment_key = [0_u8; 32];
    commitment_key.copy_from_slice(&output[44..76]);
    let mut opening_key = [0_u8; 32];
    opening_key.copy_from_slice(&output[76..108]);
    Ok(MessageKeys { aead_key, nonce, commitment_key, opening_key })
}

fn verify_commitments(
    ciphertext: &DmCiphertext,
    plaintext: &[u8],
    associated_data: &[u8],
    canonical_header: &[u8],
    message_keys: &MessageKeys,
) -> Result<(), CryptoError> {
    let commitments = franking_commitment(&FrankingCommitmentInput {
        plaintext,
        sender_device_id_hash: &ciphertext.sender_device_id_hash,
        message_event_id: &ciphertext.message_event_id,
        canonical_header_bytes: canonical_header,
        associated_data,
        ciphertext: &ciphertext.ciphertext,
        opening_key: &message_keys.opening_key,
        commitment_key: &message_keys.commitment_key,
    });
    if commitments.key_commitment != ciphertext.key_commitment {
        return Err(CryptoError::KeyCommitmentMismatch);
    }
    if commitments.franking_commitment != ciphertext.franking_commitment {
        return Err(CryptoError::CommitmentMismatch);
    }
    if commitments.commitment != ciphertext.commitment {
        return Err(CryptoError::CommitmentMismatch);
    }
    Ok(())
}
