// SPDX-License-Identifier: BSD-3-Clause
//! Single-worker facade. Only selected JSON and public release material cross it.
use crate::{AcceptancePolicy, CardSession, CardSpec, Event, SignedPackage};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CardWorker {
    package: SignedPackage,
    session: Option<CardSession>,
}
#[derive(Serialize)]
struct Reply<T: Serialize> {
    session: u64,
    version: u64,
    value: T,
}
fn error(value: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&value.to_string())
}
impl CardWorker {
    fn active(&mut self) -> Result<&mut CardSession, JsValue> {
        self.session.as_mut().ok_or_else(|| error("inactive card"))
    }
    fn reply<T: Serialize>(&self, value: T) -> Result<String, JsValue> {
        let session = self.session.as_ref().ok_or_else(|| error("inactive card"))?;
        serde_json::to_string(&Reply { session: session.id(), version: session.version(), value })
            .map_err(error)
    }
}
#[wasm_bindgen]
impl CardWorker {
    /// Public release material must come from the app bundle, never a peer message.
    /// # Errors
    /// Rejects invalid signature, descriptor bindings and independently pinned policy.
    #[wasm_bindgen(constructor)]
    pub fn new(
        bytecode: &[u8],
        descriptor: &[u8],
        signature: &[u8],
        public_key: &[u8],
        policy: &str,
    ) -> Result<CardWorker, JsValue> {
        crate::spec::preflight(policy.as_bytes(), crate::package::MAX_DESCRIPTOR).map_err(error)?;
        let policy: AcceptancePolicy = serde_json::from_str(policy).map_err(error)?;
        let signature = signature.try_into().map_err(|_| error("signature size"))?;
        let public_key = public_key.try_into().map_err(|_| error("public key size"))?;
        let package = SignedPackage::verify(bytecode, descriptor, signature, public_key, &policy)
            .map_err(error)?;
        Ok(Self { package, session: None })
    }
    /// # Errors
    /// Rejects invalid selected JSON, active sessions, or resource exhaustion.
    pub fn open(&mut self, selected_json: &str) -> Result<String, JsValue> {
        if self.session.is_some() {
            return Err(error("card already open"));
        }
        let (session, batch) = CardSession::open(
            CardSpec::parse(selected_json.as_bytes()).map_err(error)?,
            self.package.clone(),
        )
        .map_err(error)?;
        self.session = Some(session);
        self.reply(batch)
    }
    /// # Errors
    /// Rejects invalid selected JSON, inactive sessions, or execution failure.
    pub fn update(&mut self, selected_json: &str) -> Result<String, JsValue> {
        let spec = CardSpec::parse(selected_json.as_bytes()).map_err(error)?;
        let batch = self.active()?.update(spec).map_err(error)?;
        self.reply(batch)
    }
    /// # Errors
    /// Rejects malformed/oversized events; stale tokens are returned as dropped.
    pub fn event(&mut self, event_json: &str) -> Result<String, JsValue> {
        crate::spec::preflight(event_json.as_bytes(), 8192).map_err(error)?;
        let event: Event = serde_json::from_str(event_json).map_err(error)?;
        let session = self.active()?;
        session.enqueue(event).map_err(error)?;
        let outcome = session.next_event().map_err(error)?;
        self.reply(outcome)
    }
    /// # Errors
    /// Rejects inactive sessions or exhausted version space.
    pub fn suspend(&mut self) -> Result<String, JsValue> {
        let batch = self.active()?.suspend().map_err(error)?;
        self.reply(batch)
    }
    /// # Errors
    /// Rejects active sessions, exhausted limits, or failed execution.
    pub fn resume(&mut self) -> Result<String, JsValue> {
        let batch = self.active()?.resume().map_err(error)?;
        self.reply(batch)
    }
    pub fn dispose(&mut self) {
        self.session.take();
    }
}
