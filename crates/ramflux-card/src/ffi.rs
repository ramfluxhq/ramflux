// SPDX-License-Identifier: BSD-3-Clause
//! Isolated C pointer boundary. Handles and VMs remain on their creating thread.
#![allow(unsafe_code)]
#[cfg(panic = "abort")]
compile_error!("Card C ABI requires panic=unwind; use --profile ffi-release");
mod boundary;
use crate::{AcceptancePolicy, HOST_ABI};
use crate::{
    CardError, CardSession, CardSpec, Event, SignedPackage,
    package::{MAX_DESCRIPTOR, MAX_PACKAGE},
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
    pub descriptor: RamfluxCardBytes,
    /// Pinned by the embedding release; never derived from the received package.
    pub policy: RamfluxCardBytes,
    pub presentation: RamfluxCardBytes,
}
pub type RamfluxCardCallback = Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>;
thread_local! {
    static SESSIONS: RefCell<BTreeMap<u64, CardSession>> = const { RefCell::new(BTreeMap::new()) };
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
}
const OK: i32 = 0;
const MAX_OUTPUT: usize = 128 * 1024;
#[cfg(test)]
thread_local! { static TEST_OUTPUT_LIMIT:Cell<usize>=const { Cell::new(MAX_OUTPUT) }; }
fn output_limit() -> usize {
    #[cfg(test)]
    {
        TEST_OUTPUT_LIMIT.with(Cell::get)
    }
    #[cfg(not(test))]
    {
        MAX_OUTPUT
    }
}
const INVALID_HANDLE: i32 = 7;
const BUSY: i32 = 8;
fn code(error: &CardError) -> i32 {
    match error {
        CardError::Invalid(_) | CardError::Json(_) => 1,
        CardError::Limit(_) | CardError::Memory | CardError::Stack => 2,
        CardError::Signature | CardError::Admission(_) => 3,
        CardError::Engine | CardError::Script | CardError::Hardening => 4,
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
    if output.len() > output_limit() {
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
        Ok(value) => {
            let status = emit(id, &value, callback, user);
            if status != OK {
                SESSIONS.with(|sessions| sessions.borrow_mut().remove(&id));
            }
            status
        }
        Err(code) => code,
    }
}

/// Standalone renderer ABI major, independent of the SDK ABI major.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_card_abi_version() -> u32 {
    HOST_ABI
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
    boundary::status(|| {
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
            let presentation = crate::Presentation::parse(&bytes(
                input.presentation,
                crate::presentation::MAX_PRESENTATION,
            )?)?;
            let spec =
                CardSpec::parse(&bytes(input.spec, MAX_INPUT)?)?.with_presentation(presentation)?;
            let bytecode = bytes(input.bytecode, MAX_PACKAGE)?;
            let signature: [u8; 64] =
                bytes(input.signature, 64)?.try_into().map_err(|_| CardError::Signature)?;
            let key: [u8; 32] =
                bytes(input.trusted_key, 32)?.try_into().map_err(|_| CardError::Signature)?;
            let descriptor = bytes(input.descriptor, MAX_DESCRIPTOR)?;
            let policy_bytes = bytes(input.policy, MAX_DESCRIPTOR)?;
            crate::spec::preflight(&policy_bytes, MAX_DESCRIPTOR)?;
            let policy: AcceptancePolicy = serde_json::from_slice(&policy_bytes)?;
            CardSession::open(
                spec,
                SignedPackage::verify(&bytecode, &descriptor, &signature, &key, &policy)?,
            )
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
        let status = emit(id, &batch, callback, user);
        if status != OK {
            SESSIONS.with(|sessions| sessions.borrow_mut().remove(&id));
            // SAFETY: the output pointer remains writable until this synchronous call returns.
            unsafe { out.write(0) };
        }
        status
    })
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
    boundary::status(|| {
        if IN_CALLBACK.with(Cell::get) {
            return BUSY;
        }
        let spec = match bytes(input, MAX_INPUT).and_then(|b| CardSpec::parse(&b)) {
            Ok(spec) => spec,
            Err(error) => return code(&error),
        };
        apply(id, callback, user, |session| session.update(spec))
    })
}
/// Replace host-selected locale and tokens on the creating thread.
/// # Safety
/// Input and callback must be valid for the synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ramflux_card_present(
    id: u64,
    input: RamfluxCardBytes,
    callback: RamfluxCardCallback,
    user: *mut c_void,
) -> i32 {
    boundary::status(|| {
        if IN_CALLBACK.with(Cell::get) {
            return BUSY;
        }
        match bytes(input, crate::presentation::MAX_PRESENTATION)
            .and_then(|b| crate::Presentation::parse(&b))
        {
            Ok(presentation) => apply(id, callback, user, |session| session.present(presentation)),
            Err(error) => code(&error),
        }
    })
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
    boundary::status(|| {
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
    })
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
    boundary::status(|| apply(id, callback, user, CardSession::suspend))
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
    boundary::status(|| apply(id, callback, user, CardSession::resume))
}
/// Dispose on the creating thread. Foreign/stale handles return 7.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_card_dispose(id: u64) -> i32 {
    boundary::status(|| {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::{artifact, guard, release};
    struct Output {
        values: Vec<serde_json::Value>,
        reentry: i32,
        failures: Vec<String>,
    }
    unsafe extern "C" fn callback(user: *mut c_void, json: *const u8, len: usize) {
        // SAFETY: tests pass a live Output for the complete callback invocation.
        let output = unsafe { &mut *user.cast::<Output>() };
        if len > MAX_OUTPUT || json.is_null() {
            output.failures.push("invalid callback span".into());
            return;
        }
        // SAFETY: implementation borrows a readable buffer until the callback returns.
        let bytes = unsafe { std::slice::from_raw_parts(json, len) };
        let value = match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(value) => value,
            Err(error) => {
                output.failures.push(error.to_string());
                return;
            }
        };
        let Some(id) = value.get("session").and_then(serde_json::Value::as_u64) else {
            output.failures.push("missing session envelope".into());
            return;
        };
        output.reentry = ramflux_card_dispose(id);
        output.values.push(value);
    }
    fn span(value: &[u8]) -> RamfluxCardBytes {
        RamfluxCardBytes { data: value.as_ptr(), len: value.len() }
    }
    pub(super) fn host_presentation() -> Vec<u8> {
        serde_json::to_vec(&crate::Presentation::bundled("en", false).expect("test: host catalog"))
            .expect("test: catalog JSON")
    }
    #[test]
    fn c_abi_owns_handles_callbacks_and_lifecycle() {
        let _guard = guard();
        let p = artifact(include_str!("../library/form.js"));
        let sig = p.signature;
        let public = p.public_key;
        let policy = serde_json::to_vec(&release().policy()).expect("test: pinned policy");
        let presentation = host_presentation();
        let input = RamfluxCardOpen {
            spec: span(include_bytes!("../fixtures/form.json")),
            bytecode: span(&p.bytecode),
            signature: span(&sig),
            trusted_key: span(&public),
            descriptor: span(&p.descriptor),
            policy: span(&policy),
            presentation: span(&presentation),
        };
        let mut output = Output { values: Vec::new(), reentry: 0, failures: Vec::new() };
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
        assert!(
            output.failures.is_empty(),
            "callback must report valid JSON: {:?}",
            output.failures
        );
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
        assert!(
            output.failures.is_empty(),
            "callbacks must return normally and report valid JSON: {:?}",
            output.failures
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

#[cfg(test)]
mod error_tests {
    use super::*;
    use crate::{
        compiler::compile_and_sign,
        runtime::tests::{artifact, guard, release},
    };
    use ed25519_dalek::SigningKey;
    const HANDLES: usize = 32;
    #[derive(Default)]
    struct Output {
        count: usize,
        value: Option<serde_json::Value>,
        invalid: bool,
    }
    unsafe extern "C" fn callback(user: *mut c_void, ptr: *const u8, len: usize) {
        // SAFETY: test passes a live Output for the complete synchronous call.
        let output = unsafe { &mut *user.cast::<Output>() };
        if ptr.is_null() || len > MAX_OUTPUT {
            output.invalid = true;
            return;
        }
        // SAFETY: the implementation borrows a readable bounded span during the callback.
        let parsed = serde_json::from_slice(unsafe { std::slice::from_raw_parts(ptr, len) });
        match parsed {
            Ok(value) => {
                output.count += 1;
                output.value = Some(value);
            }
            Err(_) => output.invalid = true,
        }
    }
    fn span(bytes: &[u8]) -> RamfluxCardBytes {
        RamfluxCardBytes { data: bytes.as_ptr(), len: bytes.len() }
    }
    struct SmallOutput;
    impl SmallOutput {
        fn new() -> Self {
            TEST_OUTPUT_LIMIT.with(|limit| limit.set(4));
            Self
        }
    }
    impl Drop for SmallOutput {
        fn drop(&mut self) {
            TEST_OUTPUT_LIMIT.with(|limit| limit.set(MAX_OUTPUT));
        }
    }
    #[test]
    fn c_open_policy_submit_and_error_paths_are_fail_closed() {
        let _guard = guard();
        let p = artifact(include_str!("../library/form.js"));
        let policy = serde_json::to_vec(&release().policy()).expect("test: host policy");
        let presentation = serde_json::to_vec(
            &crate::Presentation::bundled("en", false).expect("test: host catalog"),
        )
        .expect("test: JSON");
        let mut input = RamfluxCardOpen {
            spec: span(include_bytes!("../fixtures/form.json")),
            bytecode: span(&p.bytecode),
            signature: span(&p.signature),
            trusted_key: span(&p.public_key),
            descriptor: span(&p.descriptor),
            policy: span(&policy),
            presentation: span(&presentation),
        };
        let mut output = Output::default();
        let user = std::ptr::from_mut(&mut output).cast();
        let mut id = 99;
        let bad_signature = [0_u8; 64];
        input.signature = span(&bad_signature);
        // SAFETY: all input spans and output/context slots are valid and live.
        let status =
            unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) };
        assert_eq!(
            (status, id, output.count),
            (3, 0, 0),
            "bad signatures must return no handle or callback"
        );
        let mut old_release = release();
        old_release.version = 1;
        let old = compile_and_sign(
            include_bytes!("../library/form.js"),
            &SigningKey::from_bytes(&[7; 32]),
            &old_release,
        )
        .expect("test: genuine older package");
        input.bytecode = span(&old.bytecode);
        input.signature = span(&old.signature);
        input.descriptor = span(&old.descriptor);
        // SAFETY: the genuine old package and host policy remain live for this call.
        let status =
            unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) };
        assert_eq!(
            (status, id, output.count),
            (3, 0, 0),
            "C admission must enforce the pinned release floor"
        );
        input.bytecode = span(&p.bytecode);
        input.signature = span(&p.signature);
        input.descriptor = span(&p.descriptor);
        {
            let _limit = SmallOutput::new();
            // SAFETY: all buffers/context remain valid; output cap is injected only by this test.
            let status =
                unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) };
            assert_eq!(
                (status, id, output.count),
                (2, 0, 0),
                "failed open emission must roll back handle and output slot"
            );
        }
        // SAFETY: valid live card release and caller-owned output/context.
        let status =
            unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) };
        assert_eq!(status, OK, "valid package must still open after failed emission");
        let invalid = b"{}";
        let before = output.count;
        // SAFETY: bounded invalid JSON is readable; callback context remains live.
        let status = unsafe { ramflux_card_update(id, span(invalid), Some(callback), user) };
        assert_eq!((status, output.count), (1, before), "invalid update must not emit a callback");
        let submit=serde_json::to_vec(&serde_json::json!({"token":{"session":id,"version":1,"key":"profile:submit"},"event":{"kind":"submit"}})).expect("test: C submit");
        // SAFETY: bounded event buffer and callback/context remain live.
        let status = unsafe { ramflux_card_event(id, span(&submit), Some(callback), user) };
        assert_eq!(status, OK, "C submit must produce a declarative intent");
        let value = output.value.as_ref().expect("test: callback value");
        assert_eq!(
            value.pointer("/payload/result").and_then(serde_json::Value::as_str),
            Some("submit"),
            "C must preserve typed submit result"
        );
        assert_eq!(
            value.pointer("/payload/fields/name").and_then(serde_json::Value::as_str),
            Some("Ada"),
            "C submit includes only the owned field"
        );
        {
            let _limit = SmallOutput::new();
            let before = output.count;
            // SAFETY: valid update inputs, with a small output cap injected by this test.
            let status = unsafe { ramflux_card_update(id, input.spec, Some(callback), user) };
            assert_eq!(
                (status, output.count),
                (2, before),
                "output failure must not call into host"
            );
        }
        assert_eq!(
            ramflux_card_dispose(id),
            INVALID_HANDLE,
            "terminal output failure must dispose the mutated session"
        );
        assert!(!output.invalid, "extern callbacks must record errors without unwinding");
    }
    #[test]
    fn thirty_third_logical_c_handle_is_rejected_without_callback() {
        let _guard = guard();
        let p = artifact(include_str!("../library/form.js"));
        let policy = serde_json::to_vec(&release().policy()).expect("test: host policy");
        let presentation = super::tests::host_presentation();
        let input = RamfluxCardOpen {
            spec: span(include_bytes!("../fixtures/form.json")),
            bytecode: span(&p.bytecode),
            signature: span(&p.signature),
            trusted_key: span(&p.public_key),
            descriptor: span(&p.descriptor),
            policy: span(&policy),
            presentation: span(&presentation),
        };
        let mut handles = Vec::new();
        let mut output = Output::default();
        let user = std::ptr::from_mut(&mut output).cast();
        for _ in 0..HANDLES {
            let mut id = 0;
            // SAFETY: all input, output and callback/context allocations are live.
            let status =
                unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut id) };
            assert_eq!(status, OK, "bounded logical handle admission");
            // SAFETY: valid callback context and owned thread-affine handle.
            let status = unsafe { ramflux_card_suspend(id, Some(callback), user) };
            assert_eq!(status, OK, "suspension releases resident VM capacity");
            handles.push(id);
        }
        let before = output.count;
        let mut extra = 99;
        // SAFETY: all spans and slots remain valid; handle limit rejects before evaluation.
        let status =
            unsafe { ramflux_card_open(&raw const input, Some(callback), user, &raw mut extra) };
        assert_eq!(
            (status, extra, output.count),
            (2, 0, before),
            "33rd logical handle must return no callback or handle"
        );
        for id in handles {
            assert_eq!(ramflux_card_dispose(id), OK, "owner must dispose every logical handle");
        }
        assert!(!output.invalid, "callbacks must stay valid and bounded");
    }
}
