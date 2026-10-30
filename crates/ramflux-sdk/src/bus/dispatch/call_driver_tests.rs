// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Record effect completion so lease release cannot overtake terminal control delivery.
use super::*;

struct RecordingDriver {
    events: Vec<&'static str>,
    offline: bool,
}
impl ControlDriver for RecordingDriver {
    async fn deliver(&mut self, _: &str, _: i64) -> Result<usize, SdkError> {
        self.events.push("hangup delivery started");
        tokio::task::yield_now().await;
        self.events.push("hangup delivery completed");
        if self.offline { Err(SdkError::InboundPending("peer offline".into())) } else { Ok(1) }
    }
    fn release(&mut self, _: &str, _: i64) -> impl Future<Output = Result<(), SdkError>> {
        self.events.push("lease released");
        std::future::ready(Ok(()))
    }
}

#[tokio::test]
async fn hangup_delivery_completes_before_release_even_when_peer_is_offline() {
    for offline in [false, true] {
        let mut driver = RecordingDriver { events: Vec::new(), offline };
        assert_eq!(drive_controls(&mut driver, "call", 100).await.is_err(), offline);
        assert_eq!(
            driver.events,
            ["hangup delivery started", "hangup delivery completed", "lease released"]
        );
    }
}
