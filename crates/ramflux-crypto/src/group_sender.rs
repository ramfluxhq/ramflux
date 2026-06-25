// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{
    HeaderField, HeaderKind, canonical_header_bytes, decode_base64url, encode_base64url,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CryptoError, FrankingCommitmentInput, blake3_256, franking_commitment, hkdf_sha256,
    write_len_prefixed,
};

pub const MAX_GROUP_SKIP: usize = 2000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GroupMemberCommitment {
    pub member_device_id_hash: [u8; 32],
    pub member_role: String,
    pub member_device_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSenderKeyDistribution {
    pub group_id_hash: [u8; 32],
    pub group_epoch: u64,
    pub group_key_epoch: u64,
    pub sender_device_id_hash: [u8; 32],
    pub sender_key_id: String,
    pub sender_chain_key: [u8; 32],
    pub sender_signing_public_key: [u8; 32],
    pub membership_commitment_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct GroupSenderKeyState {
    pub group_id_hash: [u8; 32],
    pub group_epoch: u64,
    pub group_key_epoch: u64,
    pub sender_device_id_hash: [u8; 32],
    pub sender_key_id: String,
    pub sender_chain_key: [u8; 32],
    pub sender_message_number: u64,
    pub sender_signing_public_key: [u8; 32],
    pub membership_commitment_hash: [u8; 32],
    #[zeroize(skip)]
    pub max_group_skip: usize,
    #[zeroize(skip)]
    skipped_message_keys: BTreeMap<u64, GroupMessageKeys>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GroupCiphertext {
    pub group_id_hash: [u8; 32],
    pub group_epoch: u64,
    pub group_key_epoch: u64,
    pub sender_device_id_hash: [u8; 32],
    pub sender_key_id: String,
    pub sender_message_number: u64,
    pub message_event_id: String,
    pub membership_commitment_hash: [u8; 32],
    pub canonical_header_bytes: Vec<u8>,
    pub header_hash: String,
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: String,
    pub key_commitment: String,
    pub franking_commitment: String,
    pub commitment: String,
    pub signature_by_sender_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
struct GroupMessageKeys {
    aead_key: [u8; 32],
    nonce: [u8; 12],
    commitment_key: [u8; 32],
    opening_key: [u8; 32],
}

impl GroupSenderKeyState {
    #[must_use]
    pub fn from_distribution(distribution: GroupSenderKeyDistribution) -> Self {
        Self {
            group_id_hash: distribution.group_id_hash,
            group_epoch: distribution.group_epoch,
            group_key_epoch: distribution.group_key_epoch,
            sender_device_id_hash: distribution.sender_device_id_hash,
            sender_key_id: distribution.sender_key_id,
            sender_chain_key: distribution.sender_chain_key,
            sender_message_number: 0,
            sender_signing_public_key: distribution.sender_signing_public_key,
            membership_commitment_hash: distribution.membership_commitment_hash,
            max_group_skip: MAX_GROUP_SKIP,
            skipped_message_keys: BTreeMap::new(),
        }
    }

    /// # Errors
    /// Returns an error when canonical header encoding, KDF, signing, or AEAD encryption fails.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<GroupCiphertext, CryptoError> {
        let message_number = self.sender_message_number;
        let message_event_id =
            format!("group:{}:{message_number}", encode_base64url(self.group_id_hash));
        let context = self.context_bytes(message_number);
        let (next_chain, message_secret) = kdf_ck_sender(&self.sender_chain_key, &context)?;
        let keys = derive_group_message_keys(&message_secret, &context)?;
        let header = self.header_fields(message_number, &message_event_id);
        let canonical = canonical_header_bytes(HeaderKind::GroupMessage, &header)?;
        let aad = header_associated_data(associated_data, &canonical);
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&keys.aead_key))
            .encrypt(Nonce::from_slice(&keys.nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_err| CryptoError::AeadFailed)?;
        let commitments = franking_commitment(&FrankingCommitmentInput {
            plaintext,
            sender_device_id_hash: &self.sender_device_id_hash,
            message_event_id: &message_event_id,
            canonical_header_bytes: &canonical,
            associated_data,
            ciphertext: &ciphertext,
            opening_key: &keys.opening_key,
            commitment_key: &keys.commitment_key,
        });
        let signature_preimage = group_signature_preimage(
            &canonical,
            &commitments.commitment,
            &commitments.ciphertext_hash,
        );
        let signature_by_sender_key =
            encode_base64url(signing_key.sign(&signature_preimage).to_bytes());
        self.sender_chain_key = next_chain;
        self.sender_message_number = self.sender_message_number.saturating_add(1);
        Ok(GroupCiphertext {
            group_id_hash: self.group_id_hash,
            group_epoch: self.group_epoch,
            group_key_epoch: self.group_key_epoch,
            sender_device_id_hash: self.sender_device_id_hash,
            sender_key_id: self.sender_key_id.clone(),
            sender_message_number: message_number,
            message_event_id,
            membership_commitment_hash: self.membership_commitment_hash,
            canonical_header_bytes: canonical,
            header_hash: commitments.header_hash,
            ciphertext,
            ciphertext_hash: commitments.ciphertext_hash,
            key_commitment: commitments.key_commitment,
            franking_commitment: commitments.franking_commitment,
            commitment: commitments.commitment,
            signature_by_sender_key,
        })
    }

    /// # Errors
    /// Returns an error when the sender key is unavailable, membership mismatches, signature
    /// verification fails, skip limits are exceeded, commitment verification fails, or AEAD fails.
    pub fn decrypt(
        &mut self,
        ciphertext: &GroupCiphertext,
        associated_data: &[u8],
        expected_membership_commitment_hash: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        self.validate_ciphertext_identity(ciphertext)?;
        if &ciphertext.membership_commitment_hash != expected_membership_commitment_hash {
            return Err(CryptoError::MembershipCommitmentMismatch);
        }
        verify_group_signature(ciphertext, &self.sender_signing_public_key)?;
        let keys = if let Some(keys) =
            self.skipped_message_keys.remove(&ciphertext.sender_message_number)
        {
            keys
        } else {
            self.skip_to(ciphertext.sender_message_number)?;
            let context = self.context_bytes(ciphertext.sender_message_number);
            let (_next_chain, message_secret) = kdf_ck_sender(&self.sender_chain_key, &context)?;
            derive_group_message_keys(&message_secret, &context)?
        };
        let aad = header_associated_data(associated_data, &ciphertext.canonical_header_bytes);
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(&keys.aead_key))
            .decrypt(
                Nonce::from_slice(&keys.nonce),
                Payload { msg: ciphertext.ciphertext.as_ref(), aad: &aad },
            )
            .map_err(|_err| CryptoError::AeadFailed)?;
        let commitments = franking_commitment(&FrankingCommitmentInput {
            plaintext: &plaintext,
            sender_device_id_hash: &ciphertext.sender_device_id_hash,
            message_event_id: &ciphertext.message_event_id,
            canonical_header_bytes: &ciphertext.canonical_header_bytes,
            associated_data,
            ciphertext: &ciphertext.ciphertext,
            opening_key: &keys.opening_key,
            commitment_key: &keys.commitment_key,
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
        if ciphertext.sender_message_number == self.sender_message_number {
            let context = self.context_bytes(ciphertext.sender_message_number);
            let (next_chain, _message_secret) = kdf_ck_sender(&self.sender_chain_key, &context)?;
            self.sender_chain_key = next_chain;
            self.sender_message_number = self.sender_message_number.saturating_add(1);
        }
        Ok(plaintext)
    }

    fn validate_ciphertext_identity(
        &self,
        ciphertext: &GroupCiphertext,
    ) -> Result<(), CryptoError> {
        if self.group_id_hash != ciphertext.group_id_hash
            || self.group_epoch != ciphertext.group_epoch
            || self.group_key_epoch != ciphertext.group_key_epoch
            || self.sender_device_id_hash != ciphertext.sender_device_id_hash
            || self.sender_key_id != ciphertext.sender_key_id
        {
            return Err(CryptoError::GroupSenderKeyUnavailable);
        }
        Ok(())
    }

    fn skip_to(&mut self, target: u64) -> Result<(), CryptoError> {
        if target < self.sender_message_number {
            return Ok(());
        }
        let skipped = target.saturating_sub(self.sender_message_number);
        if usize::try_from(skipped).map_or(true, |count| count > self.max_group_skip) {
            return Err(CryptoError::MaxSkipExceeded);
        }
        while self.sender_message_number < target {
            let context = self.context_bytes(self.sender_message_number);
            let (next_chain, message_secret) = kdf_ck_sender(&self.sender_chain_key, &context)?;
            self.skipped_message_keys.insert(
                self.sender_message_number,
                derive_group_message_keys(&message_secret, &context)?,
            );
            self.sender_chain_key = next_chain;
            self.sender_message_number = self.sender_message_number.saturating_add(1);
        }
        Ok(())
    }

    fn header_fields(&self, message_number: u64, message_event_id: &str) -> [HeaderField; 8] {
        [
            HeaderField::bytes32(1, self.group_id_hash),
            HeaderField::u64(2, self.group_epoch),
            HeaderField::u64(3, self.group_key_epoch),
            HeaderField::bytes32(4, self.sender_device_id_hash),
            HeaderField::string(5, self.sender_key_id.clone()),
            HeaderField::u64(6, message_number),
            HeaderField::string(7, message_event_id.to_owned()),
            HeaderField::bytes32(8, self.membership_commitment_hash),
        ]
    }

    fn context_bytes(&self, message_number: u64) -> Vec<u8> {
        let mut context = Vec::new();
        context.extend_from_slice(&self.group_id_hash);
        context.extend_from_slice(&self.group_epoch.to_be_bytes());
        context.extend_from_slice(&self.group_key_epoch.to_be_bytes());
        context.extend_from_slice(&self.sender_device_id_hash);
        context.extend_from_slice(self.sender_key_id.as_bytes());
        context.extend_from_slice(&message_number.to_be_bytes());
        context.extend_from_slice(&self.membership_commitment_hash);
        context
    }
}

#[must_use]
pub fn membership_commitment_hash(
    group_id_hash: [u8; 32],
    group_epoch: u64,
    group_key_epoch: u64,
    members: &[GroupMemberCommitment],
    group_policy_hash: [u8; 32],
    sender_key_id: &str,
) -> [u8; 32] {
    let mut sorted = members.to_vec();
    sorted.sort_by(|left, right| {
        left.member_device_id_hash
            .cmp(&right.member_device_id_hash)
            .then(left.member_role.cmp(&right.member_role))
            .then(left.member_device_epoch.cmp(&right.member_device_epoch))
    });
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ramflux_protocol::domain::GROUP_SENDER_KEY_DISTRIBUTION.as_bytes());
    preimage.extend_from_slice(&group_id_hash);
    preimage.extend_from_slice(&group_epoch.to_be_bytes());
    preimage.extend_from_slice(&group_key_epoch.to_be_bytes());
    for member in sorted {
        preimage.extend_from_slice(&member.member_device_id_hash);
        write_len_prefixed(&mut preimage, member.member_role.as_bytes());
        preimage.extend_from_slice(&member.member_device_epoch.to_be_bytes());
    }
    preimage.extend_from_slice(&group_policy_hash);
    write_len_prefixed(&mut preimage, sender_key_id.as_bytes());
    blake3_256(ramflux_protocol::domain::GROUP_SENDER_KEY_DISTRIBUTION, &preimage)
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn create_group_sender_key_distribution(
    group_id_hash: [u8; 32],
    group_epoch: u64,
    group_key_epoch: u64,
    sender_device_id_hash: [u8; 32],
    sender_key_id: String,
    sender_chain_key: [u8; 32],
    sender_signing_public_key: [u8; 32],
    membership_commitment_hash: [u8; 32],
) -> GroupSenderKeyDistribution {
    GroupSenderKeyDistribution {
        group_id_hash,
        group_epoch,
        group_key_epoch,
        sender_device_id_hash,
        sender_key_id,
        sender_chain_key,
        sender_signing_public_key,
        membership_commitment_hash,
    }
}

fn kdf_ck_sender(
    sender_chain_key: &[u8; 32],
    group_sender_context: &[u8],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let salt = blake3_256(ramflux_protocol::domain::GROUP_SENDER_KEY_CHAIN, group_sender_context);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::GROUP_SENDER_KEY_CHAIN.as_bytes());
    info.extend_from_slice(group_sender_context);
    let mut output = [0_u8; 64];
    hkdf_sha256(&salt, sender_chain_key, &info, &mut output)?;
    let mut next_chain = [0_u8; 32];
    next_chain.copy_from_slice(&output[..32]);
    let mut message_secret = [0_u8; 32];
    message_secret.copy_from_slice(&output[32..]);
    Ok((next_chain, message_secret))
}

fn derive_group_message_keys(
    message_secret: &[u8; 32],
    group_sender_context: &[u8],
) -> Result<GroupMessageKeys, CryptoError> {
    let salt = blake3_256(ramflux_protocol::domain::GROUP_SENDER_KEY_MESSAGE, group_sender_context);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::GROUP_SENDER_KEY_MESSAGE.as_bytes());
    info.extend_from_slice(group_sender_context);
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
    Ok(GroupMessageKeys { aead_key, nonce, commitment_key, opening_key })
}

fn header_associated_data(associated_data: &[u8], canonical_header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(associated_data);
    aad.extend_from_slice(canonical_header);
    aad
}

fn group_signature_preimage(
    canonical_header: &[u8],
    commitment: &str,
    ciphertext_hash: &str,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(canonical_header);
    write_len_prefixed(&mut preimage, commitment.as_bytes());
    write_len_prefixed(&mut preimage, ciphertext_hash.as_bytes());
    preimage
}

fn verify_group_signature(
    ciphertext: &GroupCiphertext,
    sender_signing_public_key: &[u8; 32],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(sender_signing_public_key)
        .map_err(|_err| CryptoError::VerifyFailed)?;
    let signature_bytes = decode_base64url(&ciphertext.signature_by_sender_key)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureLength(signature_bytes.len()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let preimage = group_signature_preimage(
        &ciphertext.canonical_header_bytes,
        &ciphertext.commitment,
        &ciphertext.ciphertext_hash,
    );
    key.verify_strict(&preimage, &signature).map_err(|_err| CryptoError::VerifyFailed)
}
