// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A2 pre-body credential projection. No Debug/serde or credential-bearing diagnostics.
use super::{FullRoute, PAIRING_MAX_HEADER_BYTES, PairingRelayError, is_pairing_path};
use ramflux_protocol::custody::pairing::full_transfer::relay::BorrowedSendFull;
use zeroize::Zeroizing;

pub struct FullAuthorization<'a> {
    lease_id: &'a str,
    epoch: &'a str,
    role: &'a str,
    token: Zeroizing<[u8; 32]>,
}
fn b32(value: &str) -> Result<Zeroizing<[u8; 32]>, PairingRelayError> {
    if value.len() != 43 {
        return Err(PairingRelayError::WrongContext);
    }
    let bytes = Zeroizing::new(
        ramflux_protocol::decode_base64url(value).map_err(|_| PairingRelayError::WrongContext)?,
    );
    if bytes.len() != 32
        || Zeroizing::new(ramflux_protocol::encode_base64url(bytes.as_slice())).as_str() != value
    {
        return Err(PairingRelayError::WrongContext);
    }
    let mut output = Zeroizing::new([0; 32]);
    output.copy_from_slice(&bytes);
    Ok(output)
}
impl<'a> FullAuthorization<'a> {
    /// Parse only after the trusted listener/proxy owner has established TLS.
    /// The raw header stays within the original pre-authentication window.
    /// # Errors
    /// Returns fixed `WrongContext` for absent/duplicate/malformed credentials or another route.
    pub fn parse(
        method: &str,
        path: &str,
        trusted_tls: bool,
        header: &'a str,
    ) -> Result<Self, PairingRelayError> {
        if !trusted_tls
            || method != "POST"
            || !is_pairing_path(path)
            || header.len() > PAIRING_MAX_HEADER_BYTES
        {
            return Err(PairingRelayError::WrongContext);
        }
        let mut authorization = None;
        for line in header.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
            if line.starts_with([' ', '\t']) {
                return Err(PairingRelayError::WrongContext);
            }
            let (name, value) = line.split_once(':').ok_or(PairingRelayError::WrongContext)?;
            if name.trim() != name {
                return Err(PairingRelayError::WrongContext);
            }
            if name.eq_ignore_ascii_case("authorization") {
                if authorization.is_some() {
                    return Err(PairingRelayError::WrongContext);
                }
                authorization = Some(value.trim_matches([' ', '\t']));
            }
        }
        let value = authorization
            .and_then(|value| value.strip_prefix("PairingFull "))
            .ok_or(PairingRelayError::WrongContext)?;
        let mut parts = value.split('.');
        let lease_id = parts.next().ok_or(PairingRelayError::WrongContext)?;
        let epoch = parts.next().ok_or(PairingRelayError::WrongContext)?;
        let role = parts.next().ok_or(PairingRelayError::WrongContext)?;
        let token = parts.next().ok_or(PairingRelayError::WrongContext)?;
        if parts.next().is_some() || !matches!(role, "initiator" | "responder") {
            return Err(PairingRelayError::WrongContext);
        }
        b32(lease_id)?;
        b32(epoch)?;
        Ok(Self { lease_id, epoch, role, token: b32(token)? })
    }
    #[must_use]
    pub fn route(&self) -> FullRoute<'_> {
        FullRoute {
            lease_id: self.lease_id,
            epoch: self.epoch,
            role: self.role,
            token: &self.token,
        }
    }
    /// Match original body scope, including a constant-time decoded bearer comparison.
    /// # Errors
    /// All mismatches return fixed `WrongContext`, never a credential or peer-supplied text.
    pub fn verify_send(&self, body: &BorrowedSendFull<'_>) -> Result<(), PairingRelayError> {
        self.verify_scope(body.packet.lease_id, body.packet.epoch, body.packet.role, body.token)
    }
    pub(super) fn verify_scope(
        &self,
        lease_id: &str,
        epoch: &str,
        role: &str,
        token: &str,
    ) -> Result<(), PairingRelayError> {
        let token = b32(token)?;
        let token_matches = super::limits::constant_time_eq(self.token.as_ref(), token.as_ref());
        if self.lease_id != lease_id || self.epoch != epoch || self.role != role || !token_matches {
            return Err(PairingRelayError::WrongContext);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
