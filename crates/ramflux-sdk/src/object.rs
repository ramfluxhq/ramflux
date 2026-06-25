// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkObjectKeySlot {
    pub schema: String,
    pub version: u32,
    pub object_id: String,
    pub conversation_id: String,
    pub recipient_device_id: String,
    pub x3dh: Option<SdkDmX3dhHeader>,
    pub ciphertext: ramflux_crypto::DmCiphertext,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkObjectSharePackage {
    pub schema: String,
    pub version: u32,
    pub object: EncryptedObject,
    pub ciphertext_base64: String,
    pub key_slot: SdkObjectKeySlot,
}
pub(crate) fn object_key_slot_associated_data(
    object_id: &str,
    conversation_id: &str,
    recipient_device_id: &str,
) -> Vec<u8> {
    format!("ramflux.object_key_slot.v1|{object_id}|{conversation_id}|{recipient_device_id}")
        .into_bytes()
}
pub(crate) fn object_chunks(object: &EncryptedObject, chunk_size: usize) -> Vec<serde_json::Value> {
    let chunk_size = chunk_size.max(1);
    object
        .ciphertext
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            serde_json::json!({
                "index": index,
                "ciphertext_base64": ramflux_protocol::encode_base64url(chunk),
                "chunk_cipher_hash": ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::OBJECT,
                    chunk,
                ),
            })
        })
        .collect()
}
