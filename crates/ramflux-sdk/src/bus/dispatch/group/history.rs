// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stored group history uses the generated durable reader without receive or authority work.
use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn read(client: &RamfluxClient, request: &LocalBusFrame) -> Result<Value, SdkError> {
    let body: LocalBusGroupReceiveRequest = serde_json::from_value(request.body.clone())?;
    let conversation =
        crate::bus::group_conversation::resolve(client, &body.group_id, &body.conversation_id)?;
    let mut page = crate::bus::readers::generated_page(
        client,
        &json!({
            "conversation_id": conversation, "limit": body.limit, "read_model": true,
        }),
    )?;
    page["group_id"] = json!(body.group_id);
    page["metadata"] = match client.shared_group_metadata(&body.group_id)? {
        Some(metadata) => metadata,
        None => serde_json::to_value(client.group_state(&body.group_id)?)?,
    };
    Ok(page)
}
