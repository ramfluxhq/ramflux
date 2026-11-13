// SPDX-License-Identifier: BSD-3-Clause
//! Isolated C pointer boundary. Handles and VMs remain on their creating thread.
#![allow(unsafe_code)]
use crate::{
    CardError, CardSession, CardSpec, Event, SignedPackage,
    package::MAX_PACKAGE,
    spec::{MAX_INPUT, preflight},
};
use serde::Serialize;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::c_void,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RamfluxCardBytes {
    pub data: *const u8,
    pub len: usize,
}
#[repr(C)]
pub struct RamfluxCardOpen {
    pub spec: RamfluxCardBytes,
    pub bytecode: RamfluxCardBytes,
    pub signature: RamfluxCardBytes,
    /// Application-pinned release key; must never be populated from peer JSON.
    pub trusted_key: RamfluxCardBytes,
}
pub type RamfluxCardCallback = Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>;
thread_local! {
    static SESSIONS: RefCell<BTreeMap<u64, CardSession>> = const { RefCell::new(BTreeMap::new()) };
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
}
const OK: i32 = 0;
const INVALID_HANDLE: i32 = 7;
const BUSY: i32 = 8;
fn code(error: &CardError) -> i32 {
    match error {
        CardError::Invalid(_) | CardError::Json(_) => 1,
        CardError::Limit(_) => 2,
        CardError::Signature => 3,
        CardError::Engine => 4,
        CardError::Budget => 5,
        CardError::Inactive => 6,
    }
}
fn bytes(input: RamfluxCardBytes, max: usize) -> Result<Vec<u8>, CardError> {
    if input.len > max {
        return Err(CardError::Limit("C input bytes"));
    }
    if input.len == 0 {
        return Ok(Vec::new());
    }
    if input.data.is_null() {
        return Err(CardError::Invalid("null input"));
    }
    // SAFETY: each exported entry documents that nonempty buffers are readable for
    // the call. Length is capped before creating the slice; we immediately copy it.
    Ok(unsafe { std::slice::from_raw_parts(input.data, input.len) }.to_vec())
}
fn emit<T: Serialize>(id: u64, value: &T, callback: RamfluxCardCallback, user: *mut c_void) -> i32 {
    let Some(callback) = callback else {
        return 1;
    };
    let output = match serde_json::to_vec(&serde_json::json!({"session": id, "payload": value})) {
        Ok(output) => output,
        Err(error) => return code(&error.into()),
    };
    if output.len() > 128 * 1024 {
        return 2;
    }
    IN_CALLBACK.with(|active| active.set(true));
    // SAFETY: caller supplies a valid callback/user context. Borrowed output lives
    // through this call. No registry borrow or engine value is held during callback.
    unsafe { callback(user, output.as_ptr(), output.len()) };
    IN_CALLBACK.with(|active| active.set(false));
    OK
}
fn apply<T: Serialize>(
    id: u64,
    callback: RamfluxCardCallback,
    user: *mut c_void,
    op: impl FnOnce(&mut CardSession) -> Result<T, CardError>,
) -> i32 {
    if callback.is_none() {
        return 1;
    }
    if IN_CALLBACK.with(Cell::get) {
        return BUSY;
    }
    let result = SESSIONS.with(|sessions| {
        let mut sessions = sessions.try_borrow_mut().map_err(|_| BUSY)?;
        let session = sessions.get_mut(&id).ok_or(INVALID_HANDLE)?;
        op(session).map_err(|error| code(&error))
    });
    match result {
        Ok(value) => emit(id, &value, callback, user),
        Err(code) => code,
    }
}

/// Standalone renderer ABI major, independent of the SDK ABI major.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_card_abi_version() -> u32 {
    1
}

/// Open a standalone card renderer, never an SDK client or authority context.
/// # Safety
/// `input` and `out` must be aligned valid pointers; every input buffer must be
/// readable for its stated length. Callback and user context must remain valid
/// through the synchronous call. Calls/callbacks must not unwind across C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_open(
    input: *const RamfluxCardOpen,
    callback: RamfluxCardCallback,
    user: *mut c_void,
    out: *mut u64,
) -> i32 {
    if out.is_null() {
        return 1;
    }
    // SAFETY: caller provides a writable aligned output slot.
    unsafe { out.write(0) };
    if input.is_null() || callback.is_none() {
        return 1;
    }
    if IN_CALLBACK.with(Cell::get) {
        return BUSY;
    }
    // SAFETY: caller provides a valid aligned input structure for the call.
    let input = unsafe { &*input };
    let create = || -> Result<_, CardError> {
        let spec = CardSpec::parse(&bytes(input.spec, MAX_INPUT)?)?;
        let bytecode = bytes(input.bytecode, MAX_PACKAGE)?;
        let signature: [u8; 64] =
            bytes(input.signature, 64)?.try_into().map_err(|_| CardError::Signature)?;
        let key: [u8; 32] =
            bytes(input.trusted_key, 32)?.try_into().map_err(|_| CardError::Signature)?;
        CardSession::open(spec, SignedPackage::verify(&bytecode, &signature, &key)?)
    };
    let capacity = SESSIONS.with(|sessions| sessions.borrow().len() < 32);
    if !capacity {
        return 2;
    }
    let (session, batch) = match create() {
        Ok(result) => result,
        Err(error) => return code(&error),
    };
    let id = session.id();
    SESSIONS.with(|sessions| sessions.borrow_mut().insert(id, session));
    // SAFETY: out is valid for the whole call by the entry contract.
    unsafe { out.write(id) };
    emit(id, &batch, callback, user)
}

/// Replace a complete declarative snapshot on the creating thread.
/// # Safety
/// Buffer and callback/user context must be valid for the synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_update(
    id: u64,
    input: RamfluxCardBytes,
    callback: RamfluxCardCallback,
    user: *mut c_void,
) -> i32 {
    if IN_CALLBACK.with(Cell::get) {
        return BUSY;
    }
    let spec = match bytes(input, MAX_INPUT).and_then(|b| CardSpec::parse(&b)) {
        Ok(spec) => spec,
        Err(error) => return code(&error),
    };
    apply(id, callback, user, |session| session.update(spec))
}
/// Deliver a versioned text edit or submit. Submit output is an intent, not a send.
/// # Safety
/// Buffer and callback/user context must be valid for the synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_event(
    id: u64,
    input: RamfluxCardBytes,
    callback: RamfluxCardCallback,
    user: *mut c_void,
) -> i32 {
    if IN_CALLBACK.with(Cell::get) {
        return BUSY;
    }
    let event = bytes(input, 8192).and_then(|b| {
        preflight(&b, 8192)?;
        Ok(serde_json::from_slice::<Event>(&b)?)
    });
    match event {
        Ok(event) => apply(id, callback, user, |session| {
            session.enqueue(event)?;
            session.next_event()?.ok_or(CardError::Invalid("missing event"))
        }),
        Err(error) => code(&error),
    }
}
/// Suspend and emit a removal batch, releasing VM capacity.
/// # Safety
/// Callback/user context must be valid for the synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_suspend(
    id: u64,
    callback: RamfluxCardCallback,
    user: *mut c_void,
) -> i32 {
    apply(id, callback, user, CardSession::suspend)
}
/// Resume and emit a full tree with a fresh version.
/// # Safety
/// Callback/user context must be valid for the synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_resume(
    id: u64,
    callback: RamfluxCardCallback,
    user: *mut c_void,
) -> i32 {
    apply(id, callback, user, CardSession::resume)
}
/// Dispose on the creating thread. Foreign/stale handles return 7.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_card_dispose(id: u64) -> i32 {
    if IN_CALLBACK.with(Cell::get) {
        return BUSY;
    }
    SESSIONS.with(|sessions| match sessions.try_borrow_mut() {
        Ok(mut sessions) => {
            if sessions.remove(&id).is_some() {
                OK
            } else {
                INVALID_HANDLE
            }
        }
        Err(_) => BUSY,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::{TEST_LOCK, library};
    use ed25519_dalek::{Signer, SigningKey};
    struct Output {
        values: Vec<serde_json::Value>,
        reentry: i32,
    }
    unsafe extern "C" fn callback(user: *mut c_void, json: *const u8, len: usize) {
        assert!(len <= 128 * 1024, "bridge output must stay bounded");
        // SAFETY: test passes a live Output and the implementation borrows this buffer.
        let output = unsafe { &mut *user.cast::<Output>() };
        // SAFETY: callback owns a borrowed readable span for this invocation.
        let value: serde_json::Value =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(json, len) })
                .expect("test: callback JSON");
        let id = value
            .get("session")
            .and_then(serde_json::Value::as_u64)
            .expect("test: session envelope");
        output.reentry = ramflux_card_dispose(id);
        output.values.push(value);
    }
    fn span(value: &[u8]) -> RamfluxCardBytes {
        RamfluxCardBytes { data: value.as_ptr(), len: value.len() }
    }
    #[test]
    fn c_abi_owns_handles_callbacks_and_lifecycle() {
        let _guard = TEST_LOCK.lock().expect("test: serial VM capacity");
        let p = library();
        let key = SigningKey::from_bytes(&[7; 32]);
        let sig = key.sign(&crate::package::signing_message(&p.bytecode)).to_bytes();
        let public = key.verifying_key().to_bytes();
        let input = RamfluxCardOpen {
            spec: span(include_bytes!("../fixtures/form.json")),
            bytecode: span(&p.bytecode),
            signature: span(&sig),
            trusted_key: span(&public),
        };
        let mut output = Output { values: Vec::new(), reentry: 0 };
        let user = std::ptr::from_mut(&mut output).cast();
        let mut id = 0;
        // SAFETY: all buffers, structures and callback context are live and valid.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) },
            OK,
            "C open must mount signed form"
        );
        assert_ne!(id, 0, "C session handles must be nonzero");
        assert_eq!(output.reentry, BUSY, "callbacks cannot reenter lifecycle calls");
        let edit = serde_json::to_vec(&serde_json::json!({"token":{"session":id,"version":1,"key":"profile:field"},"event":{"kind":"text","value":"Grace"}})).expect("test: event JSON");
        // SAFETY: borrowed event and callback context are live.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_event(id, span(&edit), Some(callback), user) },
            OK,
            "C event must use runtime edit path"
        );
        let stale = serde_json::to_vec(&serde_json::json!({"token":{"session":id,"version":1,"key":"profile:submit"},"event":{"kind":"submit"}})).expect("test: stale event");
        // SAFETY: all input spans remain live.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_event(id, span(&stale), Some(callback), user) },
            OK,
            "stale event must return a successful drop"
        );
        assert_eq!(
            output
                .values
                .last()
                .and_then(|v| v.pointer("/payload/result"))
                .and_then(serde_json::Value::as_str),
            Some("stale_dropped"),
            "C bridge must preserve stale-event semantics"
        );
        // SAFETY: fixture and callback context are live.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_update(id, input.spec, Some(callback), user) },
            OK,
            "C update must advance snapshot"
        );
        // SAFETY: callback/context are valid for both lifecycle calls.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_suspend(id, Some(callback), user) },
            OK,
            "suspend must release engine"
        );
        // SAFETY: callback/context are valid for the call.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_resume(id, Some(callback), user) },
            OK,
            "resume must remount a fresh tree"
        );
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            tx.send(ramflux_card_dispose(id)).expect("test: foreign-thread status");
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(2))
                .expect("test: bounded thread response"),
            INVALID_HANDLE,
            "foreign thread must not access session"
        );
        thread.join().expect("test: completed foreign thread");
        assert_eq!(ramflux_card_dispose(id), OK, "owner disposes session");
        assert_eq!(
            ramflux_card_dispose(id),
            INVALID_HANDLE,
            "disposed handles cannot alias a new session"
        );
        // SAFETY: null input is rejected before dereference; out is writable.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_open(std::ptr::null(), Some(callback), user, &raw mut id) },
            1,
            "null input must reject"
        );
        let oversized = RamfluxCardBytes { data: std::ptr::null(), len: MAX_INPUT + 1 };
        // SAFETY: the oversized span must be rejected by length without reading it.
        assert_eq!(
            // SAFETY: test inputs and callback context are live; invalid spans are rejected before use.
            unsafe { ramflux_card_update(id, oversized, Some(callback), user) },
            2,
            "length is checked before pointer use"
        );
    }
}
