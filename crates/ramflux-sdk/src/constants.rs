use std::time::Duration;
pub const CRATE_NAME: &str = "ramflux-sdk";
pub const GATEWAY_SESSION_PROTOCOL_VERSION: &str = "ramflux.gateway_session.v1";
pub(crate) const GATEWAY_OPEN_HASH_DOMAIN: &str = "ramflux.gateway.open.v1";
pub(crate) const GATEWAY_DEVICE_PROOF_HASH_DOMAIN: &str = "ramflux.gateway.device_proof.v1";
pub(crate) const GATEWAY_NONCE_DOMAIN: &str = "ramflux.sdk.gateway.nonce.v1";
pub(crate) const GATEWAY_SESSION_NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}
