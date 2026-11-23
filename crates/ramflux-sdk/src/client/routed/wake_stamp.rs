// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decide whether a sealed send may mint a message wake.
//!
//! Receipts, typing, presence, and call invites opt out. Call invites still
//! ring when the gateway holds a call grant. Every other kind stays visible.

use prost::Message as _;
use ramflux_protocol::message::{Control, ControlOperation, Inner, KindId};

use super::{Kind, SealedRouted};

pub(super) fn apply(mut sealed: SealedRouted, kind: &Kind, body: &[u8]) -> SealedRouted {
    sealed.suppress_wake = !visible(kind, body);
    sealed
}

fn visible(kind: &Kind, body: &[u8]) -> bool {
    if kind == &Kind::Receipt {
        return false;
    }
    let Ok(inner) = Inner::decode(body) else {
        return true;
    };
    match decoded_kind(inner.kind) {
        Some(KindId::KindReceipt | KindId::KindTyping | KindId::KindCall) => false,
        Some(KindId::KindControl) => !live_presence(&inner.body),
        _ => true,
    }
}

fn decoded_kind(kind: u32) -> Option<KindId> {
    let value = i32::try_from(kind).ok()?;
    KindId::try_from(value).ok()
}

fn live_presence(body: &[u8]) -> bool {
    let Ok(control) = Control::decode(body) else {
        return false;
    };
    ControlOperation::try_from(control.operation).ok()
        == Some(ControlOperation::ControlLivePresence)
}
