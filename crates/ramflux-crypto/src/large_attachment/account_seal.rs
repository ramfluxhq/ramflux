// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-key seal for one prepare generation. The nonce is caller-supplied.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroize;

use super::SegmentError;

const AAD: &[u8] = b"ramflux.attachment.prepare.seal.v1";

/// # Errors
/// Returns `Authentication` when the key or the AEAD rejects the record.
pub fn seal_prepare_record(
    key: &[u8; 32],
    file_key: &[u8; 32],
    object_id: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, SegmentError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SegmentError::Authentication)?;
    let mut plain = [0_u8; 64];
    plain[..32].copy_from_slice(file_key);
    plain[32..].copy_from_slice(object_id);
    let sealed = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: &plain, aad: AAD })
        .map_err(|_| SegmentError::Authentication)?;
    plain.zeroize();
    let mut out = Vec::with_capacity(12 + sealed.len());
    out.extend_from_slice(nonce);
    out.extend(sealed);
    Ok(out)
}

/// # Errors
/// Returns `Authentication` when the record does not open.
pub fn open_prepare_record(
    key: &[u8; 32],
    blob: &[u8],
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), SegmentError> {
    let (nonce, body) = blob.split_at_checked(12).ok_or(SegmentError::Authentication)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SegmentError::Authentication)?;
    let mut plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad: AAD })
        .map_err(|_| SegmentError::Authentication)?;
    if plain.len() != 64 {
        plain.zeroize();
        return Err(SegmentError::Authentication);
    }
    let mut file_key = zeroize::Zeroizing::new([0_u8; 32]);
    file_key.copy_from_slice(&plain[..32]);
    let mut object_id = [0_u8; 32];
    object_id.copy_from_slice(&plain[32..]);
    plain.zeroize();
    Ok((file_key, object_id))
}
