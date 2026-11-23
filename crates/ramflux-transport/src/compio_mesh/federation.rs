// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accept ownership and bounded handshake work are separate so a slow peer cannot serialize ingress.
use super::{CompioMeshQuicConnection, CompioMeshQuicServer};
use crate::TransportError;
use std::{
    future::{Future, IntoFuture},
    net::IpAddr,
    time::Duration,
};

impl CompioMeshQuicServer {
    /// Reserve source-fair handshake admission before spawning the returned bounded future.
    /// The permit remains owned by the handshake through cancellation or completion.
    /// # Errors
    /// Closed listener, source/capacity refusal, or address validation failure.
    pub async fn accept_federation_handshake<P, F>(
        &self,
        admit: F,
    ) -> Result<
        impl Future<Output = Result<CompioMeshQuicConnection, TransportError>> + use<P, F>,
        TransportError,
    >
    where
        F: FnOnce(IpAddr) -> Result<P, TransportError>,
    {
        let incoming = self
            .endpoint
            .wait_incoming()
            .await
            .ok_or_else(|| TransportError::Quic("federation listener closed".into()))?;
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                error.into_incoming().refuse();
            }
            return Err(TransportError::NotAuthenticated);
        }
        let permit = match admit(incoming.remote_address().ip()) {
            Ok(permit) => permit,
            Err(error) => {
                incoming.refuse();
                return Err(error);
            }
        };
        Ok(async move {
            let _permit = permit;
            let connection = compio::time::timeout(Duration::from_secs(5), incoming.into_future())
                .await
                .map_err(|_| TransportError::Quic("federation handshake deadline".into()))?
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            let peer_spiffe_uri = super::compio_peer_spiffe_uri(&connection)?;
            Ok(CompioMeshQuicConnection { connection, peer_spiffe_uri })
        })
    }
}
