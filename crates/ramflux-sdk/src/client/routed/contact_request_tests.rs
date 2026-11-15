// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact-request helpers used by the born transport tests and the decline selector.
use super::*;

async fn contact(
    state: &mut LocalBusDaemonState,
    who: &str,
    method: &str,
    body: Value,
) -> Result<Value, SdkError> {
    Ok(crate::bus::dispatch::contact::dispatch_contact_bus_request(
        &request(who, method, body),
        state,
    )
    .await?
    .response_body)
}

pub(super) fn account<'a>(
    state: &'a LocalBusDaemonState,
    who: &str,
) -> Result<&'a RamfluxClient, SdkError> {
    Ok(&state.accounts.get(who).ok_or_else(|| invalid("account"))?.client)
}

#[path = "contact_request_r2_tests.rs"]
mod r2;
