// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wire contract of the native attachment plane: the gateway session frame a client sends.
//! The mesh body the gateway forwards to the home relay lives in `ramflux-node-core`. The gateway fills `requester`
//! from the authenticated session; a client never supplies it. Byte fields travel as
//! base64url strings so a 512 KiB chunk stays inside the 1 MiB session frame.

use crate::{decode_base64url, encode_base64url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Largest decoded body one call carries: one network chunk plus transcript fields.
pub const ATTACHMENT_CALL_BODY_MAX: usize = 524_288 + 4096;

/// Raw bytes that serialize as an unpadded base64url string.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireBytes(pub Vec<u8>);

impl Serialize for WireBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_base64url(&self.0))
    }
}

impl<'de> Deserialize<'de> for WireBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode_base64url(&text).map(Self).map_err(serde::de::Error::custom)
    }
}

impl From<Vec<u8>> for WireBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// One call to the home relay's attachment plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum AttachmentCall {
    /// The relay's source authority: source name, generation, public key, home node.
    Authority,
    /// Owner Reserve, Bind, PUT, Commit, or pending Retire. `signature` is the 64-byte
    /// requester proof signature over `proof`.
    Owner { operation: WireBytes, body: WireBytes, proof: WireBytes, signature: WireBytes },
    /// Register one owner-signed grant against the committed upload.
    Register { upload_id: WireBytes, manifest: WireBytes, grant: WireBytes },
    /// One ciphertext range for the grantee named by the capability.
    Read {
        capability: WireBytes,
        object_id: WireBytes,
        manifest_hash: WireBytes,
        index: u64,
        offset: u64,
        length: u64,
    },
    /// One signed `AttachmentRetirement` (RFR1 canonical bytes plus signature).
    Retire { retirement: WireBytes, signature: WireBytes },
}

/// Client to gateway, on an authenticated session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentFrame {
    /// Echoed in the reply so a late reply is never matched to another call.
    pub request_id: String,
    pub call: AttachmentCall,
}

/// Gateway to client. `code` is a stable attachment code; `None` means success.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentReplyFrame {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default)]
    pub body: WireBytes,
}

/// Body of the `Authority` reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentAuthorityReply {
    pub source: String,
    pub generation: u64,
    pub signing_public_key: String,
    pub home_node_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_as_base64url_text() -> Result<(), Box<dyn std::error::Error>> {
        let call = AttachmentCall::Owner {
            operation: vec![1, 2, 3].into(),
            body: vec![255; 40].into(),
            proof: vec![9].into(),
            signature: vec![7; 64].into(),
        };
        let text = serde_json::to_string(&call)?;
        assert!(text.contains("\"call\":\"owner\""), "{text}");
        assert!(!text.contains("[1,2,3]"), "bytes must not travel as a number array: {text}");
        assert_eq!(serde_json::from_str::<AttachmentCall>(&text)?, call);
        Ok(())
    }

    #[test]
    fn a_full_chunk_fits_one_session_frame() -> Result<(), Box<dyn std::error::Error>> {
        let call = AttachmentCall::Owner {
            operation: vec![0; 512].into(),
            body: vec![0xAB; 524_288].into(),
            proof: vec![0; 256].into(),
            signature: vec![1; 64].into(),
        };
        let text = serde_json::to_vec(&AttachmentFrame { request_id: "r".repeat(64), call })?;
        assert!(text.len() < 1_048_576 - 4096, "frame {} bytes", text.len());
        Ok(())
    }

    #[test]
    fn invalid_base64_is_refused() {
        let text = r#"{"call":"register","upload_id":"***","manifest":"","grant":""}"#;
        assert!(serde_json::from_str::<AttachmentCall>(text).is_err());
    }
}
