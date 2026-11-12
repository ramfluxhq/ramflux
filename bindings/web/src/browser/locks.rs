// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The single-writer lock among tabs: `navigator.locks` with an ordinary exclusive request.
//! Nothing here passes `steal`.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Function, Promise};
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;

use super::js;
use crate::WebError;
use crate::carrier::WRITER_LOCK_NAME;

fn lock_manager() -> Result<JsValue, WebError> {
    js::get(&js::get(&js::global(), "navigator")?, "locks")
}

/// A queued or held request for the writer lock. The lock is held from the moment `on_granted`
/// runs until [`WriterLock::release`] is called or the worker ends.
pub struct WriterLock {
    release: Rc<RefCell<Option<Function>>>,
    _callback: Closure<dyn FnMut(JsValue) -> JsValue>,
}

impl WriterLock {
    /// Queue `navigator.locks.request("ramflux.writer.v1", { mode: "exclusive" }, callback)`.
    ///
    /// # Errors
    /// Returns [`WebError::Browser`] where the Web Locks API is missing.
    pub fn request(mut on_granted: impl FnMut() + 'static) -> Result<Self, WebError> {
        let release: Rc<RefCell<Option<Function>>> = Rc::new(RefCell::new(None));
        let slot = Rc::clone(&release);
        let callback = Closure::wrap(Box::new(move |_lock: JsValue| -> JsValue {
            let slot = Rc::clone(&slot);
            // The lock is held until this promise resolves.
            let held = Promise::new(&mut |resolve: Function, _reject: Function| {
                *slot.borrow_mut() = Some(resolve);
            });
            on_granted();
            held.into()
        }) as Box<dyn FnMut(JsValue) -> JsValue>);
        let options = js::object(&[("mode", JsValue::from_str("exclusive"))]);
        js::call(
            &lock_manager()?,
            "request",
            &[JsValue::from_str(WRITER_LOCK_NAME), options, callback.as_ref().clone()],
        )?;
        Ok(Self { release, _callback: callback })
    }

    /// Release the lock. The caller has already closed every database connection, every OPFS
    /// handle and the gateway socket.
    pub fn release(&self) {
        if let Some(resolve) = self.release.borrow_mut().take() {
            let _ = resolve.call0(&JsValue::NULL);
        }
    }

    /// Whether the lock is currently held by this context.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.release.borrow().is_some()
    }
}

/// Whether some context currently holds the writer lock. Uses `ifAvailable`, releases at once
/// when the lock was free, and never waits.
///
/// # Errors
/// Returns [`WebError::Browser`] where the Web Locks API is missing.
pub async fn leader_exists() -> Result<bool, WebError> {
    let probe = Closure::once_into_js(|lock: JsValue| -> JsValue { JsValue::from_bool(lock.is_null()) });
    let options = js::object(&[
        ("mode", JsValue::from_str("exclusive")),
        ("ifAvailable", JsValue::TRUE),
    ]);
    let taken = js::call_async(
        &lock_manager()?,
        "request",
        &[JsValue::from_str(WRITER_LOCK_NAME), options, probe],
    )
    .await?;
    Ok(taken.as_bool() == Some(true))
}
