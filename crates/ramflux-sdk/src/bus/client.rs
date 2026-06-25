#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub struct LocalBusClient {
    stream: UnixStream,
    next_frame_id: u64,
    queued_events: VecDeque<LocalBusFrame>,
}
impl LocalBusClient {
    /// # Errors
    /// Returns an error when the Unix socket cannot be opened.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self { stream, next_frame_id: 1, queued_events: VecDeque::new() })
    }

    /// # Errors
    /// Returns an error when the request cannot be serialized or the daemon returns an error.
    pub async fn request<T>(
        &mut self,
        account_id: Option<String>,
        sdk_api: &str,
        method: &str,
        body: &T,
    ) -> Result<serde_json::Value, SdkError>
    where
        T: serde::Serialize,
    {
        let request_id = format!("req_{}", self.next_frame_id);
        self.next_frame_id = self.next_frame_id.saturating_add(1);
        let frame = LocalBusFrame::request(
            &request_id,
            account_id,
            sdk_api,
            method,
            serde_json::to_value(body)?,
        );
        local_bus_trace(
            "BUS-CLIENT-TX-IN",
            format!("method={} request_id={request_id}", frame.method),
        );
        write_local_bus_frame(&mut self.stream, &frame).await?;
        local_bus_trace(
            "BUS-CLIENT-TX-OUT",
            format!("method={} request_id={request_id}", frame.method),
        );
        loop {
            let response = read_local_bus_frame(&mut self.stream).await?;
            local_bus_trace(
                "BUS-CLIENT-RX",
                format!(
                    "kind={:?} method={} request_id={}",
                    response.kind, response.method, response.request_id
                ),
            );
            match response.kind {
                LocalBusFrameKind::Event => self.queued_events.push_back(response),
                LocalBusFrameKind::Response if response.request_id == request_id => {
                    return Ok(response.body);
                }
                LocalBusFrameKind::Error if response.request_id == request_id => {
                    let message = response.error.map_or_else(
                        || "unknown local bus error".to_owned(),
                        |error| format!("{}: {}", error.code, error.message),
                    );
                    return Err(SdkError::LocalBus(message));
                }
                _ => {
                    return Err(SdkError::LocalBus(format!(
                        "unexpected local bus frame while waiting for {request_id}: {response:?}"
                    )));
                }
            }
        }
    }

    /// # Errors
    /// Returns an error when the next frame cannot be decoded or is not an event.
    pub async fn next_event(&mut self) -> Result<LocalBusFrame, SdkError> {
        if let Some(event) = self.queued_events.pop_front() {
            local_bus_trace(
                "BUS-CLIENT-NEXT-EVENT-QUEUED",
                format!("method={} request_id={}", event.method, event.request_id),
            );
            return Ok(event);
        }
        let event = read_local_bus_frame(&mut self.stream).await?;
        local_bus_trace(
            "BUS-CLIENT-NEXT-EVENT-RX",
            format!(
                "kind={:?} method={} request_id={}",
                event.kind, event.method, event.request_id
            ),
        );
        if event.kind == LocalBusFrameKind::Event {
            Ok(event)
        } else {
            Err(SdkError::LocalBus(format!("expected event frame, got {event:?}")))
        }
    }
}
