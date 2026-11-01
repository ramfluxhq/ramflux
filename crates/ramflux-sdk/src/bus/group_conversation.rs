// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The signed native group thread is shared by dispatch and read-model capture.
use crate::prelude::*;

pub(crate) fn resolve(
    client: &RamfluxClient,
    group: &str,
    requested: &str,
) -> Result<String, SdkError> {
    if client.born_v3_account.is_some()
        && let Some(state) = client.account_db()?.shared_group_state(group)?
    {
        return Ok(state.view().conversation_id.clone());
    }
    Ok(requested.to_owned())
}
