// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `MessagePort` side of the tab carrier, inside the leader worker.
//!
//! A port carries local-bus frame bodies as `ArrayBuffer` messages and small control objects.
//! Every request passes `carrier::PortAdmission` before the core sees it.

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;

use super::js;
use crate::WebError;
use crate::carrier::{
    CARRIER_VERSION, FrameHead, MAX_CARRIER_FRAME_BYTES, PortAdmission, PortControl,
    TRANSFER_LIST_THRESHOLD_BYTES, port_origin_allowed, refusal_frame,
};

/// What a port delivers to the core.
pub enum PortEvent {
    /// An admitted request. The core answers with [`AttachedPort::respond`].
    Request { head: FrameHead, frame: Vec<u8> },
    Control(PortControl),
}

struct PortState {
    port: JsValue,
    admission: PortAdmission,
}

/// One attached page.
pub struct AttachedPort {
    state: Rc<RefCell<PortState>>,
    _on_message: Closure<dyn FnMut(JsValue)>,
}

impl AttachedPort {
    /// Attach a transferred port. `event_origin` is the `origin` of the `message` event that
    /// delivered it; a port from another origin is refused and closed.
    ///
    /// # Errors
    /// Returns [`WebError::Carrier`] for a foreign origin and [`WebError::Browser`] when the
    /// port cannot be used.
    pub fn attach(
        port: JsValue,
        event_origin: &str,
        mut on_event: impl FnMut(PortEvent) + 'static,
    ) -> Result<Self, WebError> {
        if !port_origin_allowed(event_origin, &js::own_origin()?) {
            let _ = js::call(&port, "close", &[]);
            return Err(WebError::Carrier("port from another origin"));
        }
        let state = Rc::new(RefCell::new(PortState { port: port.clone(), admission: PortAdmission::default() }));
        let shared = Rc::clone(&state);
        let on_message = Closure::wrap(Box::new(move |event: JsValue| {
            let Some(data) = js::get_optional(&event, "data") else { return };
            if let Some(event) = receive(&shared, &data) {
                on_event(event);
            }
        }) as Box<dyn FnMut(JsValue)>);
        js::set(&port, "onmessage", on_message.as_ref())?;
        let attached = Self { state, _on_message: on_message };
        attached.control(&PortControl::Hello { carrier: CARRIER_VERSION });
        Ok(attached)
    }

    /// Post the response or error frame of an admitted request.
    pub fn respond(&self, frame: &[u8]) {
        let mut state = self.state.borrow_mut();
        state.admission.complete_request();
        post_frame(&state.port, frame);
    }

    /// Post an update if the page has credit left. Returns false when the update must wait.
    #[must_use]
    pub fn update(&self, frame: &[u8]) -> bool {
        let mut state = self.state.borrow_mut();
        if !state.admission.take_update_credit() {
            return false;
        }
        post_frame(&state.port, frame);
        true
    }

    /// Post a control object.
    pub fn control(&self, control: &PortControl) {
        if let Ok(text) = serde_json::to_string(control)
            && let Ok(value) = js_sys::JSON::parse(&text)
        {
            let _ = js::call(&self.state.borrow().port, "postMessage", &[value]);
        }
    }

    /// Stop admitting requests on this port; the leader is handing over.
    pub fn drain(&self) {
        self.state.borrow_mut().admission.drain();
        self.control(&PortControl::Draining);
    }

    /// Requests admitted and not yet answered.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.state.borrow().admission.in_flight()
    }
}

impl Drop for AttachedPort {
    fn drop(&mut self) {
        let port = self.state.borrow().port.clone();
        let _ = js_sys::Reflect::set(&port, &JsValue::from_str("onmessage"), &JsValue::NULL);
        let _ = js::call(&port, "close", &[]);
    }
}

fn receive(state: &Rc<RefCell<PortState>>, data: &JsValue) -> Option<PortEvent> {
    let mut state = state.try_borrow_mut().ok()?;
    if js::byte_length(data).is_some() {
        // The length is checked before the buffer is copied into wasm memory.
        let Some(frame) = js::copy_bounded(data, MAX_CARRIER_FRAME_BYTES) else {
            post_frame(&state.port, &refusal_frame(None, "frame_too_large", "frame exceeds 1 MiB"));
            return None;
        };
        return match state.admission.admit_request(&frame) {
            Ok(head) => Some(PortEvent::Request { head, frame }),
            Err(refusal) => {
                let head = serde_json::from_slice::<FrameHead>(&frame).ok();
                post_frame(
                    &state.port,
                    &refusal_frame(head.as_ref(), refusal.code(), "refused before dispatch"),
                );
                None
            }
        };
    }
    let text = js_sys::JSON::stringify(data).ok()?.as_string()?;
    if text.len() > 1024 {
        return None;
    }
    let control: PortControl = serde_json::from_str(&text).ok()?;
    if let PortControl::Credit { updates } = control {
        state.admission.add_update_credit(updates);
    }
    Some(PortEvent::Control(control))
}

/// Post one frame body. Large bodies are transferred, not copied.
fn post_frame(port: &JsValue, frame: &[u8]) {
    let buffer: JsValue = js::bytes(frame).buffer().into();
    let _ = if frame.len() > TRANSFER_LIST_THRESHOLD_BYTES {
        let transfer = js_sys::Array::of1(&buffer);
        js::call(port, "postMessage", &[buffer, transfer.into()])
    } else {
        js::call(port, "postMessage", &[buffer])
    };
}
