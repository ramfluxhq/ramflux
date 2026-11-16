// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A recording gateway transport for real-send tests: the account seals and submits for real, and
//! the test inspects exactly which recipient copies were sealed and handed to the gateway.
use crate::{GatewayClientFrame, GatewayCursor, GatewayInboxEntry, GatewayServerFrame};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

type Frame<'a, T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// One sealed submission as the gateway saw it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    pub(crate) target_delivery_id: String,
    pub(crate) payload_bytes: usize,
}

pub(crate) struct Recorder {
    last: Option<GatewayClientFrame>,
    sealed: Arc<Mutex<Vec<Sealed>>>,
    prekey: Option<(String, ramflux_crypto::PrekeyBundle)>,
}

impl Recorder {
    /// `prekey` is the peer's (principal commitment, current bundle) served to prekey fetches.
    pub(crate) fn new(
        prekey: Option<(String, ramflux_crypto::PrekeyBundle)>,
    ) -> (Self, Arc<Mutex<Vec<Sealed>>>) {
        let sealed = Arc::new(Mutex::new(Vec::new()));
        (Self { last: None, sealed: Arc::clone(&sealed), prekey }, sealed)
    }
}

impl GatewaySessionFrameSink for Recorder {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> Frame<'a, ()> {
        Box::pin(async move {
            let decoded: GatewayClientFrame = serde_json::from_slice(frame)
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            if let GatewayClientFrame::Submit { submit } = &decoded {
                self.sealed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(
                    Sealed {
                        target_delivery_id: submit.envelope.target_delivery_id.clone(),
                        payload_bytes: submit.envelope.encrypted_payload.len(),
                    },
                );
            }
            self.last = Some(decoded);
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Recorder {
    fn recv_idle_frame(&mut self) -> Frame<'_, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn recv_frame(&mut self) -> Frame<'_, Vec<u8>> {
        Box::pin(async move {
            let response = match self.last.take() {
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: Vec::new() }
                }
                Some(GatewayClientFrame::Ack { ack }) => GatewayServerFrame::Ack {
                    cursor: GatewayCursor {
                        target_delivery_id: "target".into(),
                        inbox_seq: 1,
                        last_envelope_id: Some(ack.envelope_id.clone()),
                        acked_envelope_ids: vec![ack.envelope_id],
                        nacked_envelope_ids: BTreeMap::new(),
                    },
                },
                Some(GatewayClientFrame::PrekeyFetch { device_id }) => {
                    let (principal_commitment, bundle) = self
                        .prekey
                        .clone()
                        .map_or((String::new(), None), |(root, bundle)| (root, Some(bundle)));
                    GatewayServerFrame::Prekey {
                        response: crate::prekey::SdkPrekeyResponse {
                            device_id,
                            bundle,
                            principal_commitment,
                            target_delivery_id: None,
                        },
                    }
                }
                Some(GatewayClientFrame::Submit { submit }) => GatewayServerFrame::Deliver {
                    entry: GatewayInboxEntry {
                        forwarded: false,
                        inbox_seq: 1,
                        target_delivery_id: submit.envelope.target_delivery_id.clone(),
                        envelope: submit.envelope,
                    },
                },
                None => return std::future::pending().await,
                _ => {
                    GatewayServerFrame::Nack { reason: "unexpected recording gateway frame".into() }
                }
            };
            serde_json::to_vec(&response).map_err(|error| TransportError::Quic(error.to_string()))
        })
    }
}
