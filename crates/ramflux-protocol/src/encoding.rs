use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

pub fn encode_base64url(input: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(input)
}
