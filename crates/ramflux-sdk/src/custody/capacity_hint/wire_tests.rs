// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real refusal decoding rejects past daily resets before constructing a hinted error.
use super::*;
use ramflux_protocol::custody::{CustodyClientFrame, CustodyRefusal, CustodyServerFrame};
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError,
};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct RefusalTransport {
    response: Vec<u8>,
    sent: Vec<u8>,
}
impl GatewaySessionFrameSink for RefusalTransport {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.sent = frame.to_vec();
        Box::pin(async { Ok(()) })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for RefusalTransport {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        let response = std::mem::take(&mut self.response);
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test]
async fn custody_capacity_wire_ingestion_rejects_past_and_equal_resets() -> TestResult {
    let now = unix_now();
    for reset in [0, now - 1, now, now + 3600, now + MAX_RESET_AHEAD_SECS + 3600] {
        let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: reset };
        let mut stream = RefusalTransport {
            response: serde_json::to_vec(&CustodyServerFrame::Refused {
                code: CustodyRefusal::Capacity,
                capacity: Some(hint),
            })?,
            sent: Vec::new(),
        };
        let error = crate::custody::network::exchange(
            &mut stream,
            &CustodyClientFrame::NodeIdentity { record_hash: None },
            Duration::from_secs(5),
        )
        .await
        .err()
        .ok_or("refusal unexpectedly accepted")?;
        assert!(matches!(
            serde_json::from_slice::<CustodyClientFrame>(&stream.sent)?,
            CustodyClientFrame::NodeIdentity { record_hash: None }
        ));
        assert_eq!(error.custody_refusal(), Some(CustodyRefusal::Capacity));
        if reset == now + 3600 {
            assert_eq!(error.capacity_hint(), Some(hint));
            assert!(error.to_string().contains("resets at"));
        } else {
            assert!(matches!(error, SdkError::CustodyNetwork(CustodyRefusal::Capacity)));
            assert_eq!(error.capacity_hint(), None);
            assert!(!error.to_string().contains("resets at"));
        }
    }
    Ok(())
}
