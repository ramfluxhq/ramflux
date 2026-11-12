// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owns one gateway session: the socket, the `web_origin_bound` exchange, heartbeats and the
//! reconnect decision. Only the leader worker constructs it.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

use serde_json::Value;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;

use super::js;
use super::socket::{GatewaySocket, SocketEvent};
use crate::WebError;
use crate::close::{CloseAction, ReconnectPolicy};
use crate::session::{
    HandshakePhase, HandshakeStep, SessionAuthority, WebHandshake, WebLinkPins,
};
use crate::wire::{MAX_GATEWAY_FRAME_BYTES, WEB_HEARTBEAT_INTERVAL_MS, WebClientFrame};

/// Close code reported when the browser gives none or the client itself gave up.
const ABNORMAL_CLOSE: u16 = 1006;

/// What the driver reports to the core.
#[derive(Clone, Debug, PartialEq)]
pub enum DriverEvent {
    /// The gateway session exists; `session` is the gateway `session_established` body. The
    /// resume token inside it stays in worker memory only.
    Established { session: Value },
    /// One gateway frame body for the core.
    Frame(Vec<u8>),
    /// The session is gone. `error` is set when this client ended it after a failed check.
    Down { action: CloseAction, error: Option<WebError> },
}

type Events = Rc<RefCell<Box<dyn FnMut(DriverEvent)>>>;

struct Inner {
    pins: WebLinkPins,
    authority: Rc<dyn SessionAuthority>,
    first_registration: Option<Value>,
    handshake: Option<WebHandshake>,
    socket: Option<GatewaySocket>,
    /// Sockets that ended. They are dropped on the next connect, never inside their own handler.
    ended: Vec<GatewaySocket>,
    policy: ReconnectPolicy,
    established_at_ms: Option<u64>,
    down_reported: bool,
    heartbeat: Option<(Closure<dyn FnMut()>, JsValue)>,
}

/// One web gateway session and its reconnect policy.
pub struct SessionDriver {
    inner: Rc<RefCell<Inner>>,
    events: Events,
}

impl SessionDriver {
    pub fn new(
        pins: WebLinkPins,
        authority: Rc<dyn SessionAuthority>,
        on_event: impl FnMut(DriverEvent) + 'static,
    ) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Inner {
                pins,
                authority,
                first_registration: None,
                handshake: None,
                socket: None,
                ended: Vec::new(),
                policy: ReconnectPolicy::default(),
                established_at_ms: None,
                down_reported: false,
                heartbeat: None,
            })),
            events: Rc::new(RefCell::new(Box::new(on_event))),
        }
    }

    /// Register this device's own prekey bundle on the next connection, before `open_session`.
    pub fn register_on_next_connect(&self, prekey_bundle: Value) {
        self.inner.borrow_mut().first_registration = Some(prekey_bundle);
    }

    /// Dial the pinned listener and start the exchange.
    ///
    /// # Errors
    /// Returns an error when the pins are not canonical or the socket cannot be created.
    pub fn connect(&self) -> Result<(), WebError> {
        let mut inner = self.inner.borrow_mut();
        inner.ended.clear();
        inner.stop_heartbeat();
        if let Some(previous) = inner.socket.take() {
            drop(previous);
        }
        let mut handshake = WebHandshake::new(inner.pins.clone())?;
        if let Some(prekey_bundle) = inner.first_registration.take() {
            handshake = handshake.with_first_registration(prekey_bundle);
        }
        let weak = Rc::downgrade(&self.inner);
        let events = Rc::clone(&self.events);
        let socket = GatewaySocket::connect(&inner.pins.listener_url, move |event| {
            on_socket_event(&weak, &events, event);
        })?;
        inner.handshake = Some(handshake);
        inner.socket = Some(socket);
        inner.established_at_ms = None;
        inner.down_reported = false;
        Ok(())
    }

    /// Write one gateway frame on the established session.
    ///
    /// # Errors
    /// Returns [`WebError::Protocol`] before the session exists or above the frame cap.
    pub fn send_frame(&self, frame: &[u8]) -> Result<(), WebError> {
        let inner = self.inner.borrow();
        if !inner.is_established() {
            return Err(WebError::Protocol("the gateway session is not established"));
        }
        inner.socket.as_ref().ok_or(WebError::Protocol("no socket"))?.send(frame)
    }

    /// Whether a new `submit` may be written now (`bufferedAmount` at most 1 MiB).
    #[must_use]
    pub fn may_submit(&self) -> bool {
        let inner = self.inner.borrow();
        inner.is_established() && inner.socket.as_ref().is_some_and(GatewaySocket::may_submit)
    }

    /// Send one application heartbeat now, for example when the page becomes visible.
    pub fn heartbeat_now(&self) {
        self.inner.borrow().send_heartbeat();
    }

    /// Close with 1000 and stop. No reconnect follows a local close.
    pub fn close(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.stop_heartbeat();
        inner.down_reported = true;
        if let Some(socket) = inner.socket.take() {
            socket.close();
            inner.ended.push(socket);
        }
        inner.handshake = None;
    }
}

impl Inner {
    fn is_established(&self) -> bool {
        self.handshake.as_ref().is_some_and(|h| h.phase() == HandshakePhase::Established)
    }

    fn send_heartbeat(&self) {
        if !self.is_established() {
            return;
        }
        let frame = WebClientFrame::Heartbeat { now: js::now_secs() };
        if let (Ok(bytes), Some(socket)) = (frame.encode(MAX_GATEWAY_FRAME_BYTES), self.socket.as_ref()) {
            let _ = socket.send(&bytes);
        }
    }

    fn stop_heartbeat(&mut self) {
        if let Some((_closure, id)) = self.heartbeat.take() {
            let _ = js::call(&js::global(), "clearInterval", &[id]);
        }
    }

    /// End the session from this side after a failed check: close 1000, report once.
    fn give_up(&mut self, error: WebError, out: &mut Vec<DriverEvent>) {
        self.stop_heartbeat();
        if let Some(socket) = self.socket.take() {
            socket.close();
            self.ended.push(socket);
        }
        self.handshake = None;
        if !self.down_reported {
            self.down_reported = true;
            let action = self.policy.on_close(ABNORMAL_CLOSE, false, 0, jitter());
            out.push(DriverEvent::Down { action, error: Some(error) });
        }
    }

    fn handle(&mut self, weak: &Weak<RefCell<Self>>, event: SocketEvent, out: &mut Vec<DriverEvent>) {
        match event {
            SocketEvent::Open { protocol, extensions } => {
                let first = match self.handshake.as_mut() {
                    Some(handshake) => handshake.on_open(&protocol, &extensions),
                    None => return,
                };
                match first {
                    Ok(frame) => self.write_all(&[frame], out),
                    Err(error) => self.give_up(error, out),
                }
            }
            SocketEvent::Message(bytes) => {
                if self.is_established() {
                    out.push(DriverEvent::Frame(bytes));
                    return;
                }
                let mut proof_id = [0_u8; 32];
                if getrandom::fill(&mut proof_id).is_err() {
                    self.give_up(WebError::Browser("random source"), out);
                    return;
                }
                let authority = Rc::clone(&self.authority);
                let step = match self.handshake.as_mut() {
                    Some(handshake) => {
                        handshake.on_message(&bytes, js::now_secs(), proof_id, authority.as_ref())
                    }
                    None => return,
                };
                match step {
                    Ok(HandshakeStep::Send(frames)) => self.write_all(&frames, out),
                    Ok(HandshakeStep::Established { session }) => {
                        self.established_at_ms = Some(js::now_millis());
                        self.start_heartbeat(weak);
                        out.push(DriverEvent::Established { session });
                    }
                    Err(error) => self.give_up(error, out),
                }
            }
            SocketEvent::Violation(what) => self.give_up(WebError::Protocol(what), out),
            SocketEvent::Closed { code } => {
                self.stop_heartbeat();
                let lived = self
                    .established_at_ms
                    .take()
                    .map_or(0, |since| js::now_millis().saturating_sub(since));
                if let Some(socket) = self.socket.take() {
                    self.ended.push(socket);
                }
                self.handshake = None;
                if !self.down_reported {
                    self.down_reported = true;
                    let action = self.policy.on_close(code, false, lived, jitter());
                    out.push(DriverEvent::Down { action, error: None });
                }
            }
        }
    }

    fn write_all(&mut self, frames: &[Vec<u8>], out: &mut Vec<DriverEvent>) {
        for frame in frames {
            let sent = self.socket.as_ref().map(|socket| socket.send(frame));
            if let Some(Err(error)) = sent {
                self.give_up(error, out);
                return;
            }
        }
    }

    /// The worker sends `heartbeat` every 25 s whenever it runs, visible or hidden. A frozen
    /// worker stops, and the gateway's idle rule ends the session.
    fn start_heartbeat(&mut self, weak: &Weak<RefCell<Self>>) {
        self.stop_heartbeat();
        let weak = weak.clone();
        let tick = Closure::wrap(Box::new(move || {
            if let Some(inner) = weak.upgrade()
                && let Ok(inner) = inner.try_borrow()
            {
                inner.send_heartbeat();
            }
        }) as Box<dyn FnMut()>);
        let id = js::call(
            &js::global(),
            "setInterval",
            &[tick.as_ref().clone(), JsValue::from_f64(f64::from(WEB_HEARTBEAT_INTERVAL_MS))],
        );
        if let Ok(id) = id {
            self.heartbeat = Some((tick, id));
        }
    }
}

fn on_socket_event(weak: &Weak<RefCell<Inner>>, events: &Events, event: SocketEvent) {
    let Some(inner) = weak.upgrade() else { return };
    let mut out = Vec::new();
    if let Ok(mut inner) = inner.try_borrow_mut() {
        inner.handle(weak, event, &mut out);
    }
    // The core is called after the borrow ends, so it may call back into the driver.
    for event in out {
        if let Ok(mut sink) = events.try_borrow_mut() {
            sink(event);
        }
    }
}

fn jitter() -> u32 {
    let mut bytes = [0_u8; 4];
    // Jitter only spreads reconnects; a failed read falls back to no spread.
    let _ = getrandom::fill(&mut bytes);
    u32::from_le_bytes(bytes)
}
