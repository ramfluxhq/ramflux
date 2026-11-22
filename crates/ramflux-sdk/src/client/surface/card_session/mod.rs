// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK card session. The runtime renders; this module admits, signs and dispatches.
//! Approval decisions stay on the SDK task APIs. Image bytes stay on the native callback.

#[cfg_attr(not(feature = "card-runtime"), allow(dead_code))]
mod body;
#[cfg_attr(not(feature = "card-runtime"), allow(dead_code))]
mod gate;
#[cfg_attr(not(feature = "card-runtime"), allow(dead_code))]
mod respond;

#[cfg(feature = "card-runtime")]
mod event;
#[cfg(feature = "card-runtime")]
mod guard;
#[cfg(feature = "card-runtime")]
mod lifecycle;
#[cfg(feature = "card-runtime")]
mod open;
#[cfg(feature = "card-runtime")]
mod package;
#[cfg(feature = "card-runtime")]
mod sign;
#[cfg(feature = "card-runtime")]
mod slot;
#[cfg(feature = "card-runtime")]
mod spec_build;
#[cfg(feature = "card-runtime")]
mod store;
#[cfg(feature = "card-runtime")]
mod submit;

use crate::{RamfluxClient, SdkError};
use serde_json::Value;

use super::Carrier;

#[cfg_attr(not(feature = "card-runtime"), allow(dead_code))]
pub(crate) enum SubmitPrep {
    Done(Value),
    Send {
        session: u64,
        message_id: String,
        carrier: Box<Carrier>,
        surface_version: u64,
        surface_hash: String,
        fallback: String,
    },
}

pub(crate) fn open(client: &RamfluxClient, account: &str, body: &Value) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        open::open(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn update(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        lifecycle::update(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn present(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        lifecycle::present(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn event(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        event::apply(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn suspend(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        lifecycle::suspend(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn resume(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        lifecycle::resume(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn dispose(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        lifecycle::dispose(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn slot(client: &RamfluxClient, account: &str, body: &Value) -> Result<Value, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        slot::apply(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    unavailable(client, account, body)
}

pub(crate) fn prepare_submit(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<SubmitPrep, SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        submit::prepare(client, account, body)
    }
    #[cfg(not(feature = "card-runtime"))]
    {
        let _ = (client, account, body);
        Err(super::invalid("card runtime unavailable"))
    }
}

pub(crate) fn commit_submit(account: &str, session: u64, message_id: &str) -> Result<(), SdkError> {
    #[cfg(feature = "card-runtime")]
    {
        store::clear_pending(account, session, message_id)
    }
    #[cfg(not(feature = "card-runtime"))]
    {
        let _ = (account, session, message_id);
        Err(super::invalid("card runtime unavailable"))
    }
}

pub(crate) fn submitted(
    session: u64,
    message_id: &str,
    surface_version: u64,
    surface_hash: &str,
    fallback: &str,
) -> Value {
    respond::submitted(session, message_id, surface_version, surface_hash, fallback)
}

#[cfg(not(feature = "card-runtime"))]
fn unavailable(client: &RamfluxClient, account: &str, body: &Value) -> Result<Value, SdkError> {
    let _ = (client, account, body);
    Err(super::invalid("card runtime unavailable"))
}
