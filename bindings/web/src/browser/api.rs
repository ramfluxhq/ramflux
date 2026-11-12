// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The surface exported to the dedicated worker. It is two calls, `execute` and `subscribe`,
//! plus what the worker bootstrap needs to attach pages and report state.
//!
//! No export accepts, derives or stores a primary seed or a recovery secret, and none creates
//! or recovers an account: those functions do not exist in this crate.

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;
use wasm_bindgen::prelude::*;

use super::ports::{AttachedPort, PortEvent};
use super::{js, locks, storage, vault::BrowserVault};
use crate::carrier::{FrameHead, PortAdmission, PortControl, refusal_frame, response_frame};
use crate::leader::{LeaderAction, LeaderEvent, LeaderState, may_own_store, step};
use crate::link::{EnrolmentBundle, LinkPayload, LinkState, import_bundle};
use crate::role::WEB_DEVICE_ROLE;
use crate::store_policy::{StoreAction, classify, durability_claim};

struct Core {
    build: String,
    leader: LeaderState,
    link: LinkState,
    direct: PortAdmission,
    ports: Vec<Rc<AttachedPort>>,
    subscribers: Vec<(u32, js_sys::Function)>,
    next_subscriber: u32,
    writer_lock: Option<locks::WriterLock>,
    visible_follower: bool,
}

/// The web core inside the leader worker.
#[wasm_bindgen]
pub struct WebCore {
    core: Rc<RefCell<Core>>,
}

fn js_error(error: &crate::WebError) -> JsError {
    JsError::new(&error.to_string())
}

fn status(core: &Core) -> serde_json::Value {
    json!({
        "role": WEB_DEVICE_ROLE,
        "build": core.build,
        "link_state": core.link,
        "leader": may_own_store(core.leader),
        "ports": core.ports.len(),
    })
}

/// Answer the requests the web host implements itself. Every other method is refused with a
/// typed error frame; the carrier never invents a method.
fn dispatch(core: &Core, head: &FrameHead) -> Vec<u8> {
    match head.method.as_str() {
        "web.status" => response_frame(head, &status(core)),
        _ => refusal_frame(Some(head), "unsupported_on_web", "the method is not available in the web build"),
    }
}

fn publish(core: &Rc<RefCell<Core>>, update: &serde_json::Value) {
    let Ok(text) = serde_json::to_string(update) else { return };
    let bytes: JsValue = js::bytes(text.as_bytes()).into();
    let subscribers: Vec<js_sys::Function> =
        core.borrow().subscribers.iter().map(|(_, callback)| callback.clone()).collect();
    for callback in subscribers {
        let _ = callback.call1(&JsValue::NULL, &bytes);
    }
}

fn apply(core: &Rc<RefCell<Core>>, event: LeaderEvent) {
    let actions = {
        let mut this = core.borrow_mut();
        let (next, actions) = step(this.leader, event);
        this.leader = next;
        actions
    };
    for action in actions {
        match action {
            LeaderAction::RequestLock => {
                let weak = Rc::downgrade(core);
                let lock = locks::WriterLock::request(move || {
                    if let Some(core) = weak.upgrade() {
                        apply(&core, LeaderEvent::LockGranted);
                    }
                });
                core.borrow_mut().writer_lock = lock.ok();
            }
            LeaderAction::StopAdmitting => {
                let ports = core.borrow().ports.clone();
                for port in &ports {
                    port.drain();
                }
                core.borrow_mut().direct.drain();
            }
            LeaderAction::ReleaseLock => {
                if let Some(lock) = core.borrow_mut().writer_lock.take() {
                    lock.release();
                }
            }
            // The store and the gateway session are opened and closed by the worker bootstrap,
            // which reports back with `store_opened`, `store_open_failed`, `drained`, `closed`.
            LeaderAction::OpenStore
            | LeaderAction::OpenGatewaySession
            | LeaderAction::FailInFlight
            | LeaderAction::CloseStoreAndSocket
            | LeaderAction::ReportLeaderUnavailable
            | LeaderAction::RetryLater => {}
        }
        publish(core, &json!({ "t": "leader_action", "action": format!("{action:?}") }));
    }
}

#[wasm_bindgen]
impl WebCore {
    /// `build` is the release id; a page from another build does not attach.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(build: String) -> Self {
        Self {
            core: Rc::new(RefCell::new(Core {
                build,
                leader: LeaderState::Follower,
                link: LinkState::NotLinked,
                direct: PortAdmission::default(),
                ports: Vec::new(),
                subscribers: Vec::new(),
                next_subscriber: 1,
                writer_lock: None,
                visible_follower: false,
            })),
        }
    }

    /// One request frame in, one response or error frame out.
    #[must_use]
    pub fn execute(&self, request: &[u8]) -> Vec<u8> {
        let mut core = self.core.borrow_mut();
        match core.direct.admit_request(request) {
            Ok(head) => {
                let reply = dispatch(&core, &head);
                core.direct.complete_request();
                reply
            }
            Err(refusal) => {
                let head = serde_json::from_slice::<FrameHead>(request).ok();
                refusal_frame(head.as_ref(), refusal.code(), "refused before dispatch")
            }
        }
    }

    /// Register a callback for updates. Each update is one `Uint8Array` frame body.
    pub fn subscribe(&self, callback: js_sys::Function) -> u32 {
        let mut core = self.core.borrow_mut();
        let id = core.next_subscriber;
        core.next_subscriber = core.next_subscriber.wrapping_add(1);
        core.subscribers.push((id, callback));
        id
    }

    pub fn unsubscribe(&self, id: u32) {
        self.core.borrow_mut().subscribers.retain(|(candidate, _)| *candidate != id);
    }

    /// Attach a page's `MessagePort`. `event_origin` is the origin of the delivering event.
    ///
    /// # Errors
    /// Fails for a port from another origin.
    pub fn attach_port(&self, port: JsValue, event_origin: &str) -> Result<(), JsError> {
        let weak = Rc::downgrade(&self.core);
        let slot: Rc<RefCell<Option<Rc<AttachedPort>>>> = Rc::new(RefCell::new(None));
        let own = Rc::clone(&slot);
        let attached = AttachedPort::attach(port, event_origin, move |event| {
            let (Some(core), Some(port)) = (weak.upgrade(), own.borrow().clone()) else { return };
            match event {
                PortEvent::Request { head, .. } => {
                    let reply = dispatch(&core.borrow(), &head);
                    port.respond(&reply);
                }
                PortEvent::Control(PortControl::Visibility { visible }) => {
                    core.borrow_mut().visible_follower = visible;
                }
                PortEvent::Control(PortControl::Ping { id }) => port.control(&PortControl::Pong { id }),
                PortEvent::Control(_) => {}
            }
        })
        .map_err(|error| js_error(&error))?;
        let attached = Rc::new(attached);
        *slot.borrow_mut() = Some(Rc::clone(&attached));
        self.core.borrow_mut().ports.push(attached);
        Ok(())
    }

    /// Queue for the writer lock. The lock, the store and the session belong to one context.
    pub fn start(&self) {
        apply(&self.core, LeaderEvent::Start);
    }

    /// The worker bootstrap reports leader progress: `store_opened`, `store_open_failed`,
    /// `drained`, `closed`, `shutdown`, `leader_ping_timed_out`.
    pub fn report(&self, event: &str) {
        let event = match event {
            "store_opened" => LeaderEvent::StoreOpened,
            "store_open_failed" => LeaderEvent::StoreOpenFailed,
            "drained" => LeaderEvent::Drained,
            "closed" => LeaderEvent::Closed,
            "shutdown" => LeaderEvent::Shutdown,
            "leader_ping_timed_out" => LeaderEvent::LeaderPingTimedOut,
            _ => return,
        };
        apply(&self.core, event);
    }

    /// The leader page reports its visibility. A hidden leader hands over when a follower is
    /// visible.
    pub fn set_visible(&self, visible: bool) {
        let hand_over = !visible && self.core.borrow().visible_follower;
        if hand_over {
            apply(&self.core, LeaderEvent::HiddenWithVisibleFollower);
        }
    }

    /// Current state as a JSON string.
    #[must_use]
    pub fn status(&self) -> String {
        status(&self.core.borrow()).to_string()
    }

    /// Whether some context holds the writer lock.
    ///
    /// # Errors
    /// Fails where the Web Locks API is missing.
    pub async fn leader_exists() -> Result<bool, JsError> {
        locks::leader_exists().await.map_err(|error| js_error(&error))
    }

    /// Storage facts as a JSON string: persistence, the durability wording, quota, and what was
    /// found at start. `page_persist` is the answer of `navigator.storage.persist()` when the
    /// page just asked (that method does not exist in workers); without it the worker reads
    /// `persisted()`.
    ///
    /// # Errors
    /// Fails where IndexedDB is missing.
    pub async fn storage_status(&self, page_persist: Option<bool>) -> Result<String, JsError> {
        let persistence = match page_persist {
            Some(_) => storage::persistence_from_page(page_persist),
            None => storage::persistence().await,
        };
        let opfs = storage::opfs_root().await.is_ok();
        let vault = BrowserVault::open().await.map_err(|error| js_error(&error))?;
        let (condition, action) = classify(storage::inventory(&vault).await);
        if action == StoreAction::WipeReportAndRelink {
            self.core.borrow_mut().link = LinkState::LocalStateLost;
        }
        let estimate = storage::estimate().await;
        Ok(json!({
            "persistence": format!("{persistence:?}"),
            "claim": format!("{:?}", durability_claim(persistence, opfs)),
            "opfs": opfs,
            "condition": format!("{condition:?}"),
            "action": format!("{action:?}"),
            "usage": estimate.map(|(usage, _)| usage),
            "quota": estimate.map(|(_, quota)| quota),
        })
        .to_string())
    }

    /// Import the enrolment bundle exported by a native device for the payload this browser
    /// showed. Stores the public pins and the sentinel; returns the account fingerprint to show.
    ///
    /// # Errors
    /// Fails when the bundle is not for exactly this browser, origin and node.
    pub async fn import_enrolment_bundle(&self, payload: &str, bundle: &str) -> Result<String, JsError> {
        let payload: LinkPayload = serde_json::from_str(payload).map_err(|e| JsError::new(&e.to_string()))?;
        let bundle: EnrolmentBundle = serde_json::from_str(bundle).map_err(|e| JsError::new(&e.to_string()))?;
        let own_origin = js::own_origin().map_err(|error| js_error(&error))?;
        if payload.origin != own_origin {
            return Err(JsError::new("the payload is for another origin"));
        }
        let imported = import_bundle(&payload, &bundle, js::now_secs()).map_err(|error| js_error(&error))?;
        let pins = json!({
            "listener_url": imported.pins.listener_url,
            "origin": imported.pins.origin,
            "node_id": imported.pins.node_id,
            "node_signing_public_key": imported.pins.node_signing_public_key,
            "device_ref": imported.pins.device_ref,
            "certificate_hash": imported.pins.certificate_hash,
            "record_hash": imported.pins.record_hash,
            "certificate_expires_at": imported.certificate_expires_at,
        });
        let vault = BrowserVault::open().await.map_err(|error| js_error(&error))?;
        vault.store_link_pins(&pins.to_string()).await.map_err(|error| js_error(&error))?;
        vault.mark_linked().await.map_err(|error| js_error(&error))?;
        self.core.borrow_mut().link = LinkState::Linked;
        Ok(imported.account_fingerprint)
    }

    /// Unlink: delete the vault database and the OPFS directories. The page then clears Cache
    /// Storage, unsubscribes push, unregisters the service worker and reloads.
    pub async fn wipe_local_state(&self) {
        if let Ok(vault) = BrowserVault::open().await {
            vault.wipe().await;
        }
        storage::wipe_files().await;
        self.core.borrow_mut().link = LinkState::NotLinked;
    }
}

/// The six-digit link code for a payload, shown beside the QR code.
///
/// # Errors
/// Fails for a malformed payload.
#[wasm_bindgen]
pub fn link_code(payload: &str) -> Result<String, JsError> {
    let payload: LinkPayload = serde_json::from_str(payload).map_err(|e| JsError::new(&e.to_string()))?;
    payload.link_code().map_err(|error| js_error(&error))
}
