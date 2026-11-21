// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed full-profile transport port shared by the actor and the actual HTTPS relay.
use super::{HttpRelay, SdkError};
use ramflux_protocol::custody::pairing::full_transfer::relay::{
    CloseFull, ClosedFull, FullDiscovery, FullProofReply, HelloFull, PollFull, PollFullControl,
    PollFullDiscovery, PolledFull, PolledFullControl, ProveFull, SendFull, SendFullControl,
    SentFull, SentFullControl,
};
use std::{future::Future, pin::Pin};

pub type FullPortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send + 'a>>;

/// Each request/reply arm retains its compiled codec, A2 bearer scope and size bound.
/// Implementations confer no account session, semantic acknowledgement or publication right.
pub trait FullPairingTransport: Send + Sync {
    fn hello_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a HelloFull,
    ) -> FullPortFuture<'a, FullDiscovery>;
    fn discover_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a PollFullDiscovery,
    ) -> FullPortFuture<'a, FullDiscovery>;
    fn prove_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a ProveFull,
    ) -> FullPortFuture<'a, FullProofReply>;
    fn send_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a SendFull,
    ) -> FullPortFuture<'a, SentFull>;
    fn poll_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a PollFull,
    ) -> FullPortFuture<'a, PolledFull>;
    fn send_full_control<'a>(
        &'a self,
        origin: &'a str,
        request: &'a SendFullControl,
    ) -> FullPortFuture<'a, SentFullControl>;
    fn poll_full_control<'a>(
        &'a self,
        origin: &'a str,
        request: &'a PollFullControl,
    ) -> FullPortFuture<'a, PolledFullControl>;
    fn close_full<'a>(
        &'a self,
        origin: &'a str,
        request: &'a CloseFull,
    ) -> FullPortFuture<'a, ClosedFull>;
}
macro_rules! round {
    ($name:ident, $request:ty, $reply:ty, $method:ident) => {
        fn $name<'a>(
            &'a self,
            origin: &'a str,
            request: &'a $request,
        ) -> FullPortFuture<'a, $reply> {
            Box::pin(self.$method(origin, request))
        }
    };
}
impl FullPairingTransport for HttpRelay {
    round!(hello_full, HelloFull, FullDiscovery, full_claim);
    round!(discover_full, PollFullDiscovery, FullDiscovery, full_claim);
    round!(prove_full, ProveFull, FullProofReply, full_prove);
    round!(send_full, SendFull, SentFull, full_round);
    round!(poll_full, PollFull, PolledFull, full_round);
    round!(send_full_control, SendFullControl, SentFullControl, full_round);
    round!(poll_full_control, PollFullControl, PolledFullControl, full_round);
    round!(close_full, CloseFull, ClosedFull, full_round);
}
