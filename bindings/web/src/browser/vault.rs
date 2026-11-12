// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The browser vault: one non-extractable AES-GCM `CryptoKey` kept in IndexedDB by structured
//! clone, and one blob it encrypts.
//!
//! Honest limits: the wrap protects the blob when it is copied alone. Any script running in the
//! origin can ask the key to decrypt, a copied browser profile contains everything, and nothing
//! is hardware-bound. Copies of the plaintext that pass through JavaScript buffers cannot be
//! zeroized from here.

use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use zeroize::Zeroizing;

use super::js;
use crate::WebError;
use crate::store_policy::SENTINEL_KEY;
use crate::vault_format::{
    LINK_PINS_ID, MAX_WRAPPED_BLOB_BYTES, STATE_STORE, VAULT_DATABASE, VAULT_DATABASE_VERSION,
    VaultSecrets, WRAP_ALGORITHM, WRAP_IV_BYTES, WRAP_KEY_BITS, WRAP_KEY_EXTRACTABLE, WRAP_KEY_ID,
    WRAP_KEY_USAGES, WRAP_STORE, WRAP_TAG_BITS, WRAPPED_BLOB_ID, WrappedBlob, wrap_additional_data,
};

const UNAVAILABLE: WebError = WebError::VaultUnavailable("IndexedDB or WebCrypto is unavailable");

/// An open handle on the vault database.
pub struct BrowserVault {
    database: JsValue,
}

/// Turn an `IDBRequest` into a promise of its result.
fn request_promise(request: &JsValue) -> Promise {
    let request = request.clone();
    Promise::new(&mut |resolve: Function, reject: Function| {
        let source = request.clone();
        let on_success = Closure::once_into_js(move |_: JsValue| {
            let result = Reflect::get(&source, &JsValue::from_str("result")).unwrap_or(JsValue::UNDEFINED);
            let _ = resolve.call1(&JsValue::NULL, &result);
        });
        let on_error = Closure::once_into_js(move |_: JsValue| {
            let _ = reject.call0(&JsValue::NULL);
        });
        let _ = Reflect::set(&request, &JsValue::from_str("onsuccess"), &on_success);
        let _ = Reflect::set(&request, &JsValue::from_str("onerror"), &on_error);
    })
}

fn subtle() -> Result<JsValue, WebError> {
    js::get(&js::get(&js::global(), "crypto").map_err(|_| UNAVAILABLE)?, "subtle")
        .map_err(|_| UNAVAILABLE)
}

fn algorithm(iv: &[u8], additional_data: &[u8]) -> JsValue {
    js::object(&[
        ("name", JsValue::from_str(WRAP_ALGORITHM)),
        ("iv", js::bytes(iv).into()),
        ("additionalData", js::bytes(additional_data).into()),
        ("tagLength", JsValue::from_f64(f64::from(WRAP_TAG_BITS))),
    ])
}

impl BrowserVault {
    /// Open (and on first use create) the vault database.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] where IndexedDB is missing or refuses.
    pub async fn open() -> Result<Self, WebError> {
        let factory = js::get(&js::global(), "indexedDB").map_err(|_| UNAVAILABLE)?;
        let request = js::call(
            &factory,
            "open",
            &[JsValue::from_str(VAULT_DATABASE), JsValue::from_f64(f64::from(VAULT_DATABASE_VERSION))],
        )
        .map_err(|_| UNAVAILABLE)?;
        let upgrading = request.clone();
        let on_upgrade = Closure::once_into_js(move |_: JsValue| {
            if let Ok(database) = Reflect::get(&upgrading, &JsValue::from_str("result")) {
                for store in [WRAP_STORE, STATE_STORE] {
                    let _ = js::call(&database, "createObjectStore", &[JsValue::from_str(store)]);
                }
            }
        });
        js::set(&request, "onupgradeneeded", &on_upgrade).map_err(|_| UNAVAILABLE)?;
        let database =
            js::settle(request_promise(&request).into(), "indexedDB.open").await.map_err(|_| UNAVAILABLE)?;
        Ok(Self { database })
    }

    fn store(&self, name: &'static str, mode: &str) -> Result<JsValue, WebError> {
        let transaction =
            js::call(&self.database, "transaction", &[JsValue::from_str(name), JsValue::from_str(mode)])
                .map_err(|_| UNAVAILABLE)?;
        js::call(&transaction, "objectStore", &[JsValue::from_str(name)]).map_err(|_| UNAVAILABLE)
    }

    async fn read(&self, store: &'static str, key: &str) -> Result<Option<JsValue>, WebError> {
        let request =
            js::call(&self.store(store, "readonly")?, "get", &[JsValue::from_str(key)]).map_err(|_| UNAVAILABLE)?;
        let value =
            js::settle(request_promise(&request).into(), "IDBObjectStore.get").await.map_err(|_| UNAVAILABLE)?;
        Ok((!value.is_undefined() && !value.is_null()).then_some(value))
    }

    async fn write(&self, store: &'static str, key: &str, value: &JsValue) -> Result<(), WebError> {
        let request =
            js::call(&self.store(store, "readwrite")?, "put", &[value.clone(), JsValue::from_str(key)])
                .map_err(|_| UNAVAILABLE)?;
        js::settle(request_promise(&request).into(), "IDBObjectStore.put").await.map(|_| ()).map_err(|_| UNAVAILABLE)
    }

    /// Whether the "this origin was linked" sentinel exists.
    pub async fn is_marked_linked(&self) -> bool {
        matches!(self.read(STATE_STORE, SENTINEL_KEY).await, Ok(Some(_)))
    }

    /// Write the sentinel at first link.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] when the write fails.
    pub async fn mark_linked(&self) -> Result<(), WebError> {
        self.write(STATE_STORE, SENTINEL_KEY, &JsValue::TRUE).await
    }

    /// Whether both the wrapping key and the wrapped blob exist.
    pub async fn has_secrets(&self) -> bool {
        matches!(self.read(WRAP_STORE, WRAP_KEY_ID).await, Ok(Some(_)))
            && matches!(self.read(STATE_STORE, WRAPPED_BLOB_ID).await, Ok(Some(_)))
    }

    /// Public link pins (node id, listener, device reference, hashes) as a JSON string.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] when the read fails.
    pub async fn link_pins(&self) -> Result<Option<String>, WebError> {
        Ok(self.read(STATE_STORE, LINK_PINS_ID).await?.and_then(|value| value.as_string()))
    }

    /// Store the public link pins.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] when the write fails.
    pub async fn store_link_pins(&self, pins_json: &str) -> Result<(), WebError> {
        self.write(STATE_STORE, LINK_PINS_ID, &JsValue::from_str(pins_json)).await
    }

    /// The wrapping key, generated on first use with `extractable: false` and the usages
    /// `encrypt` and `decrypt` only, then stored by structured clone.
    async fn wrapping_key(&self, create: bool) -> Result<JsValue, WebError> {
        if let Some(key) = self.read(WRAP_STORE, WRAP_KEY_ID).await? {
            return Ok(key);
        }
        if !create {
            return Err(WebError::VaultUnavailable("the wrapping key is missing"));
        }
        let usages = js_sys::Array::new();
        for usage in WRAP_KEY_USAGES {
            usages.push(&JsValue::from_str(usage));
        }
        let parameters = js::object(&[
            ("name", JsValue::from_str(WRAP_ALGORITHM)),
            ("length", JsValue::from_f64(f64::from(WRAP_KEY_BITS))),
        ]);
        let key = js::call_async(
            &subtle()?,
            "generateKey",
            &[parameters, JsValue::from_bool(WRAP_KEY_EXTRACTABLE), usages.into()],
        )
        .await
        .map_err(|_| UNAVAILABLE)?;
        // Fail closed unless the user agent really produced a non-extractable key.
        if js::get_optional(&key, "extractable").and_then(|flag| flag.as_bool()) != Some(false) {
            return Err(WebError::VaultUnavailable("the user agent returned an extractable key"));
        }
        self.write(WRAP_STORE, WRAP_KEY_ID, &key).await?;
        Ok(key)
    }

    /// Encrypt the secrets under the wrapping key with a fresh nonce and store the blob.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] when WebCrypto or IndexedDB refuses.
    pub async fn seal(&self, secrets: &VaultSecrets, device_id: &str, origin: &str) -> Result<(), WebError> {
        let key = self.wrapping_key(true).await?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(secrets).map_err(|_| WebError::Encoding)?);
        let mut iv = [0_u8; WRAP_IV_BYTES];
        getrandom::fill(&mut iv).map_err(|_| WebError::VaultUnavailable("random source"))?;
        let parameters = algorithm(&iv, &wrap_additional_data(device_id, origin));
        let sealed = js::call_async(&subtle()?, "encrypt", &[parameters, key, js::bytes(&plaintext).into()])
            .await
            .map_err(|_| UNAVAILABLE)?;
        let ciphertext = js::copy_bounded(&sealed, MAX_WRAPPED_BLOB_BYTES)
            .ok_or(WebError::VaultUnavailable("wrapped blob has an impossible length"))?;
        let blob = WrappedBlob::new(&iv, &ciphertext)?;
        let record = serde_json::to_string(&blob).map_err(|_| WebError::Encoding)?;
        self.write(STATE_STORE, WRAPPED_BLOB_ID, &JsValue::from_str(&record)).await
    }

    /// Decrypt the secrets. They exist in wasm memory only inside the leader worker.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] when the blob or key is missing, was moved to
    /// another device record or origin, or was modified.
    pub async fn unseal(&self, device_id: &str, origin: &str) -> Result<VaultSecrets, WebError> {
        let key = self.wrapping_key(false).await?;
        let record = self
            .read(STATE_STORE, WRAPPED_BLOB_ID)
            .await?
            .and_then(|value| value.as_string())
            .ok_or(WebError::VaultUnavailable("the wrapped blob is missing"))?;
        let blob: WrappedBlob =
            serde_json::from_str(&record).map_err(|_| WebError::VaultUnavailable("wrapped blob is malformed"))?;
        let (iv, ciphertext) = blob.parts()?;
        let parameters = algorithm(&iv, &wrap_additional_data(device_id, origin));
        let opened = js::call_async(&subtle()?, "decrypt", &[parameters, key, js::bytes(&ciphertext).into()])
            .await
            .map_err(|_| WebError::VaultUnavailable("the wrapped blob does not decrypt"))?;
        let plaintext = Zeroizing::new(
            js::copy_bounded(&opened, MAX_WRAPPED_BLOB_BYTES)
                .ok_or(WebError::VaultUnavailable("wrapped blob has an impossible length"))?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| WebError::VaultUnavailable("wrapped blob is malformed"))
    }

    /// Delete the whole vault database. Part of unlink and of loss handling.
    pub async fn wipe(self) {
        let _ = js::call(&self.database, "close", &[]);
        if let Ok(factory) = js::get(&js::global(), "indexedDB")
            && let Ok(request) = js::call(&factory, "deleteDatabase", &[JsValue::from_str(VAULT_DATABASE)])
        {
            let _ = js::settle(request_promise(&request).into(), "indexedDB.deleteDatabase").await;
        }
    }
}

/// Whether a value is a `CryptoKey` handle rather than key bytes.
#[must_use]
pub fn is_key_handle(value: &JsValue) -> bool {
    !value.is_string() && !value.is_instance_of::<js_sys::Uint8Array>()
}
