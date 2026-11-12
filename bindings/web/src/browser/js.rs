// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Small dynamic helpers over `js-sys`. Browser objects are reached by name so that the crate
//! depends on no generated API surface, and a missing API is an ordinary error.

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::WebError;

/// The worker global scope.
#[must_use]
pub fn global() -> JsValue {
    js_sys::global().into()
}

/// `target[key]`.
///
/// # Errors
/// Returns [`WebError::Browser`] when the property read throws or the value is absent.
pub fn get(target: &JsValue, key: &'static str) -> Result<JsValue, WebError> {
    let value = Reflect::get(target, &JsValue::from_str(key)).map_err(|_| WebError::Browser(key))?;
    if value.is_undefined() || value.is_null() {
        return Err(WebError::Browser(key));
    }
    Ok(value)
}

/// `target[key]`, where absence is a normal answer.
#[must_use]
pub fn get_optional(target: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(target, &JsValue::from_str(key))
        .ok()
        .filter(|value| !value.is_undefined() && !value.is_null())
}

/// `target[key] = value`.
///
/// # Errors
/// Returns [`WebError::Browser`] when the assignment throws.
pub fn set(target: &JsValue, key: &'static str, value: &JsValue) -> Result<(), WebError> {
    Reflect::set(target, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|_| WebError::Browser(key))
}

/// `target[method](...args)`.
///
/// # Errors
/// Returns [`WebError::Browser`] when the method is absent or throws.
pub fn call(target: &JsValue, method: &'static str, args: &[JsValue]) -> Result<JsValue, WebError> {
    let function: Function =
        get(target, method)?.dyn_into().map_err(|_| WebError::Browser(method))?;
    let list = Array::new();
    for arg in args {
        list.push(arg);
    }
    function.apply(target, &list).map_err(|_| WebError::Browser(method))
}

/// `new global[constructor](...args)`.
///
/// # Errors
/// Returns [`WebError::Browser`] when the constructor is absent or throws.
pub fn construct(constructor: &'static str, args: &[JsValue]) -> Result<JsValue, WebError> {
    let function: Function =
        get(&global(), constructor)?.dyn_into().map_err(|_| WebError::Browser(constructor))?;
    let list = Array::new();
    for arg in args {
        list.push(arg);
    }
    Reflect::construct(&function, &list).map_err(|_| WebError::Browser(constructor))
}

/// Await a value that may be a promise.
///
/// # Errors
/// Returns [`WebError::Browser`] with `what` when the promise rejects.
pub async fn settle(value: JsValue, what: &'static str) -> Result<JsValue, WebError> {
    JsFuture::from(Promise::resolve(&value)).await.map_err(|_| WebError::Browser(what))
}

/// Await `target[method](...args)`.
///
/// # Errors
/// Returns [`WebError::Browser`] when the call throws or the promise rejects.
pub async fn call_async(
    target: &JsValue,
    method: &'static str,
    args: &[JsValue],
) -> Result<JsValue, WebError> {
    settle(call(target, method, args)?, method).await
}

/// Await `navigator.storage[method]()`, where a missing Storage API is a normal answer.
pub async fn call_async_optional(method: &'static str) -> Option<JsValue> {
    let navigator = get_optional(&global(), "navigator")?;
    let storage = get_optional(&navigator, "storage")?;
    call_async(&storage, method, &[]).await.ok()
}

/// A plain object from key and value pairs.
#[must_use]
pub fn object(entries: &[(&str, JsValue)]) -> JsValue {
    let target = Object::new();
    for (key, value) in entries {
        // Setting a data property on a fresh plain object cannot throw.
        let _ = Reflect::set(&target, &JsValue::from_str(key), value);
    }
    target.into()
}

/// Copy bytes into a fresh `Uint8Array`.
#[must_use]
pub fn bytes(data: &[u8]) -> Uint8Array {
    Uint8Array::from(data)
}

/// Byte length of an `ArrayBuffer` or a view, read before anything is copied.
#[must_use]
pub fn byte_length(value: &JsValue) -> Option<usize> {
    let length = get_optional(value, "byteLength")?.as_f64()?;
    if length.is_finite() && length >= 0.0 {
        // Lengths of browser buffers are integers far below `u32::MAX` on wasm32.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        return Some(length as usize);
    }
    None
}

/// Copy an `ArrayBuffer` or a view into wasm memory once its length passed `cap`.
#[must_use]
pub fn copy_bounded(value: &JsValue, cap: usize) -> Option<Vec<u8>> {
    if byte_length(value)? > cap {
        return None;
    }
    Some(Uint8Array::new(value).to_vec())
}

/// Unix time in whole seconds.
#[must_use]
pub fn now_secs() -> u64 {
    let millis = js_sys::Date::now();
    if millis.is_finite() && millis > 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        return (millis / 1000.0) as u64;
    }
    0
}

/// Milliseconds since the epoch, for durations.
#[must_use]
pub fn now_millis() -> u64 {
    let millis = js_sys::Date::now();
    if millis.is_finite() && millis > 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        return millis as u64;
    }
    0
}

/// `self.origin` of this worker.
///
/// # Errors
/// Returns [`WebError::Browser`] outside a browser context.
pub fn own_origin() -> Result<String, WebError> {
    get(&global(), "origin")?.as_string().ok_or(WebError::Browser("origin"))
}
