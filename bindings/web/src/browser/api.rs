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

use super::driver::{DriverEvent, SessionDriver};
use super::ports::{AttachedPort, PortEvent};
use super::{js, locks, storage, vault::BrowserVault};
use crate::carrier::{FrameHead, PortAdmission, PortControl, refusal_frame, response_frame};
use crate::leader::{LeaderAction, LeaderEvent, LeaderState, may_own_store, step};
use crate::close::CloseAction;
use crate::link::{
    EnrolmentBundle, LinkEntropy, LinkPayload, LinkState, import_bundle, new_web_device,
};
use crate::session::{SessionAuthority, SessionAuthorityKey, WebLinkPins};
use crate::wire::WebOpenFrame;
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
    driver: Option<Rc<SessionDriver>>,
    gateway_frames: u64,
}

/// Signs with the branch key unsealed from the vault. The key exists only in this worker.
struct VaultAuthority {
    branch_key: ed25519_dalek::SigningKey,
}

impl SessionAuthority for VaultAuthority {
    fn sign_branch_proof(&self, transcript: &[u8]) -> Result<[u8; 64], crate::WebError> {
        Ok(self.branch_key.sign_transcript(transcript))
    }

    fn open_and_auth(
        &self,
        _: &serde_json::Value,
        _: u64,
    ) -> Result<(WebOpenFrame, serde_json::Value), crate::WebError> {
        // The `Open`/`Auth` builder still lives in the daemon SDK, which does not build for this
        // target. Until it moves to a platform-neutral crate the exchange stops here, after the
        // custody session, and the socket is closed with 1000.
        Err(crate::WebError::Protocol("gateway Open and Auth signing is not available in the web build"))
    }
}

fn random<const N: usize>() -> Result<[u8; N], JsError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| JsError::new("random source unavailable"))?;
    Ok(bytes)
}

fn on_driver_event(core: &Rc<RefCell<Core>>, event: DriverEvent) {
    let update = match event {
        // The session body holds the resume token; it stays in worker memory and is not published.
        DriverEvent::Established { .. } => json!({ "t": "session", "state": "established" }),
        DriverEvent::Frame(_) => {
            let mut core = core.borrow_mut();
            core.gateway_frames = core.gateway_frames.saturating_add(1);
            return;
        }
        DriverEvent::Down { action, error } => {
            let reconnect_after = match action {
                CloseAction::StopUnlinked => {
                    core.borrow_mut().link = LinkState::Unlinked;
                    None
                }
                CloseAction::StopReplaced => {
                    core.borrow_mut().link = LinkState::Replaced;
                    None
                }
                CloseAction::ReconnectAndWarnUnlinked { delay_ms } => {
                    core.borrow_mut().link = LinkState::NeedsFreshBundle;
                    Some(delay_ms)
                }
                CloseAction::Reconnect { delay_ms } => Some(delay_ms),
                CloseAction::Idle => None,
            };
            if let Some(delay_ms) = reconnect_after {
                schedule_reconnect(core, delay_ms);
            }
            json!({
                "t": "session",
                "state": "down",
                "action": format!("{action:?}"),
                "error": error.map(|error| error.to_string()),
                "link_state": core.borrow().link,
            })
        }
    };
    publish(core, &update);
}

fn schedule_reconnect(core: &Rc<RefCell<Core>>, delay_ms: u64) {
    let weak = Rc::downgrade(core);
    let retry = Closure::once_into_js(move || {
        let Some(core) = weak.upgrade() else { return };
        // Only the context that still holds the writer lock reconnects.
        let driver = {
            let core = core.borrow();
            if may_own_store(core.leader) { core.driver.clone() } else { None }
        };
        if let Some(driver) = driver {
            let _ = driver.connect();
        }
    });
    #[allow(clippy::cast_precision_loss)]
    let delay = JsValue::from_f64(delay_ms as f64);
    let _ = js::call(&js::global(), "setTimeout", &[retry, delay]);
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
        "session": core.driver.as_ref().is_some_and(|driver| driver.may_submit()),
        "gateway_frames": core.gateway_frames,
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
            LeaderAction::CloseStoreAndSocket => {
                if let Some(driver) = core.borrow_mut().driver.take() {
                    driver.close();
                }
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
                driver: None,
                gateway_frames: 0,
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
        let stored = serde_json::to_string(&imported.pins).map_err(|e| JsError::new(&e.to_string()))?;
        let vault = BrowserVault::open().await.map_err(|error| js_error(&error))?;
        vault.store_link_pins(&stored).await.map_err(|error| js_error(&error))?;
        vault.mark_linked().await.map_err(|error| js_error(&error))?;
        self.core.borrow_mut().link = LinkState::Linked;
        Ok(imported.account_fingerprint)
    }

    /// Generate this browser's device keys, seal them in the vault and return
    /// `{ "payload": …, "link_code": "NNNNNN" }` for the QR code and the text block. Only public
    /// keys leave the worker. Linking is finished by `import_enrolment_bundle`.
    ///
    /// # Errors
    /// Fails when the listener URL is not canonical or the vault is unavailable.
    pub async fn begin_link(&self, node_id: &str, listener_url: &str) -> Result<String, JsError> {
        let origin = js::own_origin().map_err(|error| js_error(&error))?;
        let entropy = LinkEntropy {
            branch_signing_seed: random()?,
            agreement_identity_seed: random()?,
            database_key: random()?,
            device_id: random()?,
            link_nonce: random()?,
        };
        let device = new_web_device(node_id, listener_url, &origin, js::now_secs(), &entropy)
            .map_err(|error| js_error(&error))?;
        let vault = BrowserVault::open().await.map_err(|error| js_error(&error))?;
        vault
            .seal(&device.secrets, &device.payload.device_id, &origin)
            .await
            .map_err(|error| js_error(&error))?;
        let link_code = device.payload.link_code().map_err(|error| js_error(&error))?;
        self.core.borrow_mut().link = LinkState::AwaitingBundle;
        Ok(json!({ "payload": device.payload, "link_code": link_code }).to_string())
    }

    /// Open the gateway session of this linked device. Only the context that holds the writer
    /// lock may call it. Progress arrives through `subscribe` as `{"t":"session",…}` updates.
    ///
    /// # Errors
    /// Fails when this context is not the leader, the browser is not linked, or the vault does
    /// not open.
    pub async fn connect(&self) -> Result<(), JsError> {
        if !may_own_store(self.core.borrow().leader) {
            return Err(JsError::new("only the leader opens a gateway session"));
        }
        let vault = BrowserVault::open().await.map_err(|error| js_error(&error))?;
        let stored = vault
            .link_pins()
            .await
            .map_err(|error| js_error(&error))?
            .ok_or_else(|| JsError::new("this browser is not linked"))?;
        let pins: WebLinkPins = serde_json::from_str(&stored).map_err(|e| JsError::new(&e.to_string()))?;
        let secrets = vault
            .unseal(&pins.device_ref.device_id, &pins.origin)
            .await
            .map_err(|error| js_error(&error))?;
        let mut seed: [u8; 32] = ramflux_protocol::decode_base64url(&secrets.branch_signing_seed)
            .ok()
            .and_then(|seed| seed.try_into().ok())
            .ok_or_else(|| JsError::new("the vault holds a malformed branch seed"))?;
        let authority = Rc::new(VaultAuthority { branch_key: ed25519_dalek::SigningKey::from_bytes(&seed) });
        zeroize::Zeroize::zeroize(&mut seed);
        let weak = Rc::downgrade(&self.core);
        let driver = Rc::new(SessionDriver::new(pins, authority, move |event| {
            if let Some(core) = weak.upgrade() {
                on_driver_event(&core, event);
            }
        }));
        // The leader may have handed over while the vault was being read.
        if !may_own_store(self.core.borrow().leader) {
            return Err(JsError::new("only the leader opens a gateway session"));
        }
        driver.connect().map_err(|error| js_error(&error))?;
        self.core.borrow_mut().driver = Some(driver);
        self.core.borrow_mut().link = LinkState::Linked;
        Ok(())
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
