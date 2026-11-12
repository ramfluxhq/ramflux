// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The WebSocket to the web listener, exactly as the wire contract requires: the fixed
//! subprotocol, binary messages only, one message per frame, no cookies, no credentials.

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use super::js;
use crate::WebError;
use crate::close::{CLIENT_CLOSE_CODE, CLIENT_CLOSE_REASON};
use crate::wire::{
    MAX_GATEWAY_FRAME_BYTES, WEB_SEND_BUFFER_HIGH_WATER_BYTES, WEB_SESSION_SUBPROTOCOL,
};

/// What the socket reports to its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketEvent {
    /// `open`, with `ws.protocol` and `ws.extensions` for the contract check.
    Open { protocol: String, extensions: String },
    /// One binary message, already below the 1 MiB cap.
    Message(Vec<u8>),
    /// A text message or a message above the cap: a contract violation by the peer.
    Violation(&'static str),
    /// The socket closed. `code` is the close code the browser reports.
    Closed { code: u16 },
}

type Handler = Closure<dyn FnMut(JsValue)>;
type Sink = Rc<RefCell<Box<dyn FnMut(SocketEvent)>>>;

/// One connection attempt. Dropping it closes the socket and detaches the handlers.
pub struct GatewaySocket {
    socket: JsValue,
    _handlers: [Handler; 4],
}

impl GatewaySocket {
    /// `new WebSocket(listener_url, ["ramflux.gateway_session.v1"])` with
    /// `binaryType = "arraybuffer"`.
    ///
    /// # Errors
    /// Returns [`WebError::Browser`] when the constructor is missing or throws.
    pub fn connect(
        listener_url: &str,
        on_event: impl FnMut(SocketEvent) + 'static,
    ) -> Result<Self, WebError> {
        let protocols = js_sys::Array::of1(&JsValue::from_str(WEB_SESSION_SUBPROTOCOL));
        let socket = js::construct("WebSocket", &[JsValue::from_str(listener_url), protocols.into()])?;
        js::set(&socket, "binaryType", &JsValue::from_str("arraybuffer"))?;
        let sink: Sink = Rc::new(RefCell::new(Box::new(on_event)));

        let open = handler(&sink, {
            let socket = socket.clone();
            move |_| SocketEvent::Open {
                protocol: string_property(&socket, "protocol"),
                extensions: string_property(&socket, "extensions"),
            }
        });
        let message = handler(&sink, |event| {
            let Some(data) = js::get_optional(&event, "data") else {
                return SocketEvent::Violation("message without data");
            };
            if data.is_string() {
                return SocketEvent::Violation("text message");
            }
            js::copy_bounded(&data, MAX_GATEWAY_FRAME_BYTES)
                .map_or(SocketEvent::Violation("message above the frame cap"), SocketEvent::Message)
        });
        let close = handler(&sink, |event| {
            let code = js::get_optional(&event, "code").and_then(|code| code.as_f64()).map_or(
                1006,
                |code| {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let code = code as u16;
                    code
                },
            );
            SocketEvent::Closed { code }
        });
        // `error` carries no detail by design and is always followed by `close`.
        let error = Closure::wrap(Box::new(|_: JsValue| {}) as Box<dyn FnMut(JsValue)>);

        js::set(&socket, "onopen", open.as_ref())?;
        js::set(&socket, "onmessage", message.as_ref())?;
        js::set(&socket, "onclose", close.as_ref())?;
        js::set(&socket, "onerror", error.as_ref())?;
        Ok(Self { socket, _handlers: [open, message, close, error] })
    }

    /// Write one frame body as one binary message.
    ///
    /// # Errors
    /// Returns [`WebError::Protocol`] above the cap and [`WebError::Browser`] when `send` throws.
    pub fn send(&self, frame: &[u8]) -> Result<(), WebError> {
        if frame.len() > MAX_GATEWAY_FRAME_BYTES {
            return Err(WebError::Protocol("outbound frame exceeds the frame cap"));
        }
        js::call(&self.socket, "send", &[js::bytes(frame).into()]).map(|_| ())
    }

    /// Whether a new `submit` may be written: `bufferedAmount` is at most 1 MiB.
    #[must_use]
    pub fn may_submit(&self) -> bool {
        js::get_optional(&self.socket, "bufferedAmount")
            .and_then(|amount| amount.as_f64())
            .is_some_and(|amount| amount <= f64::from(WEB_SEND_BUFFER_HIGH_WATER_BYTES))
    }

    /// Close with 1000, the only code a browser sends.
    pub fn close(&self) {
        let _ = js::call(
            &self.socket,
            "close",
            &[JsValue::from_f64(f64::from(CLIENT_CLOSE_CODE)), JsValue::from_str(CLIENT_CLOSE_REASON)],
        );
    }
}

impl Drop for GatewaySocket {
    fn drop(&mut self) {
        for name in ["onopen", "onmessage", "onclose", "onerror"] {
            let _ = js_sys::Reflect::set(&self.socket, &JsValue::from_str(name), &JsValue::NULL);
        }
        self.close();
    }
}

fn handler(sink: &Sink, mut map: impl FnMut(JsValue) -> SocketEvent + 'static) -> Handler {
    let sink = Rc::clone(sink);
    Closure::wrap(Box::new(move |event: JsValue| {
        let event = map(event);
        // A handler that re-enters while the owner is still running is dropped, not queued:
        // the browser delivers socket events one task at a time.
        if let Ok(mut sink) = sink.try_borrow_mut() {
            sink(event);
        }
    }) as Box<dyn FnMut(JsValue)>)
}

fn string_property(target: &JsValue, key: &str) -> String {
    js::get_optional(target, key).and_then(|value| value.as_string()).unwrap_or_default()
}

/// Keeps `JsCast` in scope for `as_ref` conversions of closures on every toolchain.
#[must_use]
pub fn is_function(value: &JsValue) -> bool {
    value.is_instance_of::<js_sys::Function>()
}
