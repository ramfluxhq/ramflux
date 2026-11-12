// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `repr(C)` layouts of C ABI major 2 and the size-prefixed read that guards them.

use super::super::{CAbiError, CAbiResult, RamfluxErrorCode};
use std::os::raw::c_uchar;

pub const RAMFLUX_V2_ABI_MAJOR: u32 = 2;
pub const RAMFLUX_V2_ABI_MINOR: u32 = 0;

/// Largest request or response body, the local-bus frame cap.
pub(super) const MAX_FRAME_BYTES: u32 = 1 << 20;
/// Default and largest number of undelivered events one subscription may hold.
pub(super) const DEFAULT_QUEUE_EVENTS: u32 = 64;
pub(super) const MAX_QUEUE_EVENTS: u32 = 1024;
/// Largest number of undelivered event bytes one subscription may hold.
pub(super) const MAX_QUEUE_BYTES: usize = 4 << 20;

/// Opaque supervisor handle.
#[repr(C)]
pub struct RamfluxV2Core {
    _private: [u8; 0],
}

/// Opaque subscription handle.
#[repr(C)]
pub struct RamfluxV2Subscription {
    _private: [u8; 0],
}

/// Opaque cancel handle. One handle cancels every request that names it.
#[repr(C)]
pub struct RamfluxV2Cancel {
    _private: [u8; 0],
}

/// Opaque account-creation ceremony handle.
#[repr(C)]
pub struct RamfluxV2AccountCreation {
    _private: [u8; 0],
}

/// Passed to `ramflux_v2_account_creation_begin`.
#[repr(C)]
pub struct RamfluxV2CreateOptions {
    pub struct_size: u32,
    /// Reserved, must be zero.
    pub flags: u32,
    /// UTF-8 display name of the new account.
    pub display_name: *const c_uchar,
    pub display_name_len: usize,
    /// UTF-8 node id, or null for the default node.
    pub node_id: *const c_uchar,
    pub node_id_len: usize,
}

/// Passed to `ramflux_v2_account_creation_confirm`. Every pointer is borrowed for the call;
/// the core copies the bytes into erasing buffers and the host erases its own copies.
#[repr(C)]
pub struct RamfluxV2CreateConfirm {
    pub struct_size: u32,
    /// Reserved, must be zero.
    pub flags: u32,
    /// The three words at the challenged positions, in challenge order. UTF-8.
    pub words: [*const c_uchar; 3],
    pub word_lens: [usize; 3],
    /// UTF-8 passphrase of the new account.
    pub passphrase: *const c_uchar,
    pub passphrase_len: usize,
}

/// Filled by `ramflux_v2_abi_version`.
#[repr(C)]
pub struct RamfluxV2Version {
    /// Set by the host to `sizeof(RamfluxV2Version)` before the call.
    pub struct_size: u32,
    pub abi_major: u32,
    pub abi_minor: u32,
    pub protocol_version: u32,
    pub max_frame_bytes: u32,
    pub max_queue_events: u32,
    /// Descriptor fingerprint. All zero while no generated descriptor is compiled in.
    pub descriptor_fingerprint: [u8; 32],
}

/// Passed to `ramflux_v2_core_new`.
#[repr(C)]
pub struct RamfluxV2Config {
    pub struct_size: u32,
    /// ABI the host was built against. The core refuses another major or a newer minor.
    pub host_abi_major: u32,
    pub host_abi_minor: u32,
    /// Reserved, must be zero.
    pub flags: u32,
    /// UTF-8 path of the data root chosen by the host. Not NUL terminated.
    pub data_root: *const c_uchar,
    pub data_root_len: usize,
    /// Longest time suspend and stop may take. Zero selects the supervisor default.
    pub suspend_deadline_ms: u32,
    /// Deadline of a request that names none. Zero selects the default.
    pub request_deadline_ms: u32,
}

/// Passed to `ramflux_v2_execute`.
#[repr(C)]
pub struct RamfluxV2Request {
    pub struct_size: u32,
    /// Reserved, must be zero.
    pub flags: u32,
    /// UTF-8 local-bus method, for example `message.submit`.
    pub method: *const c_uchar,
    pub method_len: usize,
    /// UTF-8 SDK API group of the method, for example `message`.
    pub sdk_api: *const c_uchar,
    pub sdk_api_len: usize,
    /// UTF-8 account id, or null for a request outside an account.
    pub account_id: *const c_uchar,
    pub account_id_len: usize,
    /// UTF-8 operation id of a mutating request, or null. Chosen by the host, never here.
    pub operation_id: *const c_uchar,
    pub operation_id_len: usize,
    /// JSON request body. Null or empty means `{}`.
    pub body_json: *const c_uchar,
    pub body_json_len: usize,
    /// Absolute Unix deadline in milliseconds. Zero selects the configured default.
    pub deadline_unix_ms: u64,
    /// Optional cancel handle, borrowed for the call.
    pub cancel: *const RamfluxV2Cancel,
}

/// Passed to `ramflux_v2_subscribe`.
#[repr(C)]
pub struct RamfluxV2SubscribeOptions {
    pub struct_size: u32,
    /// Undelivered events the queue may hold. Zero selects the default.
    pub queue_capacity: u32,
    /// UTF-8 account id, or null.
    pub account_id: *const c_uchar,
    pub account_id_len: usize,
    /// JSON body of `subscription.open`, for example `{"topics":["message.received"]}`.
    pub body_json: *const c_uchar,
    pub body_json_len: usize,
}

/// A size-prefixed struct. `MIN_SIZE` is the 2.0 layout and never changes; a later minor
/// appends fields and the read zero-fills what an older host did not send.
pub(super) trait Versioned: Sized {
    const MIN_SIZE: usize;
    fn zeroed() -> Self;
}

macro_rules! versioned {
    ($name:ident) => {
        impl Versioned for $name {
            const MIN_SIZE: usize = std::mem::size_of::<$name>();
            fn zeroed() -> Self {
                // Every field is an integer, an array of integers or a raw pointer, for
                // which the all-zero pattern is a valid value.
                unsafe { std::mem::zeroed() }
            }
        }
    };
}

versioned!(RamfluxV2Version);
versioned!(RamfluxV2Config);
versioned!(RamfluxV2Request);
versioned!(RamfluxV2SubscribeOptions);
versioned!(RamfluxV2CreateOptions);
versioned!(RamfluxV2CreateConfirm);

/// Size the host declared, after the bounds every versioned struct shares.
pub(super) fn declared_size<T: Versioned>(pointer: *const T) -> CAbiResult<usize> {
    if pointer.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "struct pointer is null"));
    }
    let declared = unsafe { pointer.cast::<u32>().read_unaligned() };
    let declared = usize::try_from(declared)
        .map_err(|_| CAbiError::new(RamfluxErrorCode::InvalidArgument, "struct size overflow"))?;
    if declared < T::MIN_SIZE {
        return Err(CAbiError::new(
            RamfluxErrorCode::InvalidArgument,
            "struct_size is smaller than the ABI 2.0 layout",
        ));
    }
    if declared > std::mem::size_of::<T>() {
        return Err(CAbiError::new(
            RamfluxErrorCode::UnsupportedVersion,
            "struct_size is larger than this core knows; negotiate with ramflux_v2_abi_version",
        ));
    }
    Ok(declared)
}

/// Copy a host struct, reading no byte past the size the host declared.
pub(super) fn read_versioned<T: Versioned>(pointer: *const T) -> CAbiResult<T> {
    let declared = declared_size(pointer)?;
    let mut value = T::zeroed();
    unsafe {
        std::ptr::copy_nonoverlapping(
            pointer.cast::<u8>(),
            (&raw mut value).cast::<u8>(),
            declared,
        );
    }
    Ok(value)
}

/// Borrowed UTF-8 input copied into an owned string. A null pointer with length zero is
/// `None`.
pub(super) fn optional_text(
    pointer: *const c_uchar,
    len: usize,
    what: &'static str,
) -> CAbiResult<Option<String>> {
    if pointer.is_null() && len == 0 {
        return Ok(None);
    }
    let bytes = bounded_bytes(pointer, len, what)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| CAbiError::new(RamfluxErrorCode::InvalidArgument, what))
}

pub(super) fn required_text(
    pointer: *const c_uchar,
    len: usize,
    what: &'static str,
) -> CAbiResult<String> {
    match optional_text(pointer, len, what)? {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, what)),
    }
}

/// Borrowed bytes copied after the frame-size bound, so an oversize input is refused
/// before it is allocated.
pub(super) fn bounded_bytes(
    pointer: *const c_uchar,
    len: usize,
    what: &'static str,
) -> CAbiResult<Vec<u8>> {
    if len > MAX_FRAME_BYTES as usize {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, what));
    }
    super::super::input_bytes(pointer, len)
}
