// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded XChaCha20-Poly1305 entry codec. No filesystem or provider selection.
//! `RustCrypto` clears retained cipher/MAC state with the enabled zeroize features.
//! chacha20 0.9.1 `HChaCha` local state/subkey and CPU-register copies remain outside
//! the owned-buffer guarantee; this codec introduces no KDF or application subkey.
//! Enabled poly1305 zeroize clears software r/h/pad and the autodetected union
//! containing software/AVX2 state; SIMD register and intermediate copies are not promised.
use super::cleanup::Secret;
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};

pub(super) const HEADER_LEN: usize = 80;
pub(super) const MAX_PLAINTEXT: usize = 8192;
pub(super) const MAX_RECORD: usize = 8288;
const DOMAIN: &[u8] = b"ramflux.identity.linux_vault.entry.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum Error {
    #[error("invalid vault record size")]
    RecordSize,
    #[error("invalid vault magic")]
    Magic,
    #[error("unsupported vault version")]
    Version,
    #[error("invalid vault realm")]
    Realm,
    #[error("invalid vault kind")]
    Kind,
    #[error("invalid vault realm/kind combination")]
    Combination,
    #[error("invalid vault generation")]
    Generation,
    #[error("invalid vault plaintext length")]
    Length,
    #[error("invalid vault account binding")]
    Account,
    #[error("invalid vault reference binding")]
    Reference,
    #[error("vault authentication failed")]
    Authentication,
    #[error("vault randomness unavailable")]
    Random,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Binding<'a> {
    pub realm: u8,
    pub kind: u8,
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub key_id: [u8; 16],
    pub account: &'a str,
    pub reference: &'a str,
}

fn valid_fields(realm: u8, kind: u8, generation: u64, len: usize) -> Result<(), Error> {
    if !(1..=3).contains(&realm) {
        return Err(Error::Realm);
    }
    if !(1..=4).contains(&kind) {
        return Err(Error::Kind);
    }
    if !matches!((realm, kind), (1, 1) | (2, 2) | (3, 3 | 4)) {
        return Err(Error::Combination);
    }
    if generation == 0 {
        return Err(Error::Generation);
    }
    let valid_len = match kind {
        1 => len == 32,
        2 => len == 64,
        _ => (1..=MAX_PLAINTEXT).contains(&len),
    };
    if !valid_len {
        return Err(Error::Length);
    }
    Ok(())
}

impl Binding<'_> {
    fn validate(self, len: usize) -> Result<(), Error> {
        valid_fields(self.realm, self.kind, self.generation, len)?;
        crate::custody::valid_id(self.account).map_err(|_| Error::Account)?;
        let reference = match self.kind {
            1 => self.reference,
            2 => self.reference.strip_prefix("branch:").ok_or(Error::Reference)?,
            3 => self.reference.strip_prefix("agent-provisioning:").ok_or(Error::Reference)?,
            _ => {
                return if self.reference.strip_prefix("unlock:") == Some(self.account) {
                    Ok(())
                } else {
                    Err(Error::Reference)
                };
            }
        };
        if reference.len() != 43 {
            return Err(Error::Reference);
        }
        let bytes = ramflux_protocol::decode_base64url(reference).map_err(|_| Error::Reference)?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(&bytes) != reference {
            return Err(Error::Reference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    realm: u8,
    kind: u8,
    vault_id: [u8; 16],
    generation: u64,
    key_id: [u8; 16],
    nonce: [u8; 24],
    len: u32,
}
impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0; HEADER_LEN];
        out[..8].copy_from_slice(b"RFVLT001");
        out[8..10].copy_from_slice(&1_u16.to_be_bytes());
        out[10] = self.realm;
        out[11] = self.kind;
        out[12..28].copy_from_slice(&self.vault_id);
        out[28..36].copy_from_slice(&self.generation.to_be_bytes());
        out[36..52].copy_from_slice(&self.key_id);
        out[52..76].copy_from_slice(&self.nonce);
        out[76..80].copy_from_slice(&self.len.to_be_bytes());
        out
    }
    fn decode(record: &[u8]) -> Result<Self, Error> {
        if !(HEADER_LEN + 16..=MAX_RECORD).contains(&record.len()) {
            return Err(Error::RecordSize);
        }
        if &record[..8] != b"RFVLT001" {
            return Err(Error::Magic);
        }
        if record[8..10] != 1_u16.to_be_bytes() {
            return Err(Error::Version);
        }
        let generation =
            u64::from_be_bytes(record[28..36].try_into().map_err(|_| Error::RecordSize)?);
        let len = u32::from_be_bytes(record[76..80].try_into().map_err(|_| Error::RecordSize)?);
        valid_fields(record[10], record[11], generation, len as usize)?;
        if record.len() != HEADER_LEN + len as usize + 16 {
            return Err(Error::RecordSize);
        }
        Ok(Self {
            realm: record[10],
            kind: record[11],
            vault_id: record[12..28].try_into().map_err(|_| Error::RecordSize)?,
            generation,
            key_id: record[36..52].try_into().map_err(|_| Error::RecordSize)?,
            nonce: record[52..76].try_into().map_err(|_| Error::RecordSize)?,
            len,
        })
    }
    fn matches(&self, binding: Binding<'_>) -> bool {
        self.realm == binding.realm
            && self.kind == binding.kind
            && self.vault_id == binding.vault_id
            && self.generation == binding.generation
            && self.key_id == binding.key_id
    }
}
fn aad(header: &[u8; HEADER_LEN], binding: Binding<'_>) -> Result<Vec<u8>, Error> {
    fn append(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
        out.extend_from_slice(
            &u32::try_from(value.len()).map_err(|_| Error::Length)?.to_be_bytes(),
        );
        out.extend_from_slice(value);
        Ok(())
    }
    // Only bounded public metadata, never secret serialization.
    let mut out = Vec::with_capacity(512);
    append(&mut out, DOMAIN)?;
    out.extend_from_slice(header);
    append(&mut out, binding.account.as_bytes())?;
    append(&mut out, binding.reference.as_bytes())?;
    Ok(out)
}

pub(super) struct Plaintext {
    bytes: Secret<MAX_PLAINTEXT>,
    len: usize,
}
impl Plaintext {
    pub(super) fn new(input: &[u8]) -> Result<Self, Error> {
        if !(1..=MAX_PLAINTEXT).contains(&input.len()) {
            return Err(Error::Length);
        }
        let mut bytes = Secret::new("p02-input");
        bytes.bytes_mut()[..input.len()].copy_from_slice(input);
        Ok(Self { bytes, len: input.len() })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes.bytes()[..self.len]
    }
}

pub(super) fn seal(
    binding: Binding<'_>,
    key: &Secret<32>,
    input: &Plaintext,
) -> Result<Vec<u8>, Error> {
    seal_random(binding, key, input, |nonce| getrandom::fill(nonce).map_err(|_| Error::Random))
}
fn seal_random(
    binding: Binding<'_>,
    key: &Secret<32>,
    input: &Plaintext,
    random: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    binding.validate(input.len)?;
    let mut nonce = Secret::<24>::new("p02-nonce");
    random(nonce.bytes_mut())?;
    seal_nonce(binding, key, input, nonce.bytes().try_into().map_err(|_| Error::Length)?)
}
fn seal_nonce(
    binding: Binding<'_>,
    key: &Secret<32>,
    input: &Plaintext,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, Error> {
    binding.validate(input.len)?;
    let header = Header {
        realm: binding.realm,
        kind: binding.kind,
        vault_id: binding.vault_id,
        generation: binding.generation,
        key_id: binding.key_id,
        nonce: *nonce,
        len: u32::try_from(input.len).map_err(|_| Error::Length)?,
    }
    .encode();
    let mut work = Secret::<MAX_PLAINTEXT>::new("p02-aead");
    work.bytes_mut()[..input.len].copy_from_slice(input.bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| Error::Length)?;
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(nonce),
            &aad(&header, binding)?,
            &mut work.bytes_mut()[..input.len],
        )
        .map_err(|_| Error::Authentication)?;
    let mut record = Vec::with_capacity(HEADER_LEN + input.len + 16);
    record.extend_from_slice(&header);
    record.extend_from_slice(&work.bytes()[..input.len]);
    record.extend_from_slice(&tag);
    Ok(record)
}
pub(super) fn open(
    binding: Binding<'_>,
    key: &Secret<32>,
    record: &[u8],
) -> Result<Plaintext, Error> {
    // All serialized format and context checks precede secret allocation/decryption.
    let header = Header::decode(record)?;
    binding.validate(header.len as usize)?;
    if !header.matches(binding) {
        return Err(Error::Authentication);
    }
    let mut bytes = Secret::<MAX_PLAINTEXT>::new("p02-readback");
    let len = header.len as usize;
    bytes.bytes_mut()[..len].copy_from_slice(&record[HEADER_LEN..HEADER_LEN + len]);
    XChaCha20Poly1305::new_from_slice(key.bytes())
        .map_err(|_| Error::Length)?
        .decrypt_in_place_detached(
            XNonce::from_slice(&header.nonce),
            &aad(&header.encode(), binding)?,
            &mut bytes.bytes_mut()[..len],
            Tag::from_slice(&record[HEADER_LEN + len..]),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Plaintext { bytes, len })
}

#[cfg(test)]
mod tests;
