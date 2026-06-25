#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("core error: {0}")]
    Core(#[from] ramflux_core::CoreError),
    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("value is not a JSON object")]
    NotObject,
    #[error("unknown critical extension: {0}")]
    UnknownCriticalExtension(String),
    #[error("fixture path has no parent")]
    MissingFixtureParent,
    #[error("fixture replay key is missing")]
    MissingReplayKey,
    #[error("signature field is missing: {0}")]
    MissingSignatureField(&'static str),
    #[error("nonce replay detected for {0}")]
    Replay(String),
    #[error("invalid domain: expected {expected}, got {actual}")]
    InvalidDomain { expected: &'static str, actual: String },
    #[error("invalid base64url field {field}: {source}")]
    InvalidBase64Url {
        field: &'static str,
        #[source]
        source: base64::DecodeError,
    },
    #[error("invalid ed25519 signature length: {0}")]
    InvalidSignatureLength(usize),
    #[error("invalid ed25519 public key length: {0}")]
    InvalidPublicKeyLength(usize),
    #[error("ed25519 verification failed")]
    SignatureVerificationFailed,
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("signed request expired")]
    SignedRequestExpired,
    #[error("signed request created too far in the future")]
    SignedRequestFromFuture,
    #[error("signed request outside replay window")]
    SignedRequestOutsideReplayWindow,
    #[error("signed request expiry exceeds maximum accepted validity")]
    SignedRequestExpiryTooLong,
    #[error("canonical header has too many fields")]
    HeaderFieldCountOverflow,
    #[error("canonical header field value is too long")]
    HeaderFieldValueTooLong,
}
