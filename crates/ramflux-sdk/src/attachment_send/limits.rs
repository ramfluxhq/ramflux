// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only `attachment.limits`. Publishes the device cap and the encoded
//! ceiling that `preflight::measure` already enforces. No object is reserved.

use ramflux_protocol::message::outer::{
    FRAME_PREFIX_BYTES, MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES, REPORT_OPENING_BYTES,
};
use serde_json::{Value, json};

use crate::SdkError;
use crate::bus::io::request_account_id;
use crate::bus::protocol::LocalBusFrame;

/// Prefix plus reporting opening that `measure` adds before the unpadded cap.
const ENCODED_FRAME_BYTES: usize = FRAME_PREFIX_BYTES + REPORT_OPENING_BYTES;

/// Maximum Inner length that passes both size checks in `preflight::measure`.
const fn encoded_ceiling_bytes() -> usize {
    let framed = MAX_UNPADDED_PLAINTEXT_BYTES.saturating_sub(ENCODED_FRAME_BYTES);
    if framed < MAX_INNER_BYTES { framed } else { MAX_INNER_BYTES }
}

/// `attachment.limits` for an open account.
///
/// # Errors
/// Returns a local-bus error when `account_id` is missing or a cap does not fit `u64`.
pub(crate) fn limits(request: &LocalBusFrame) -> Result<Value, SdkError> {
    let _account_id = request_account_id(request)?;
    let max_devices = fit(super::meta::MAX_ENTRIES)?;
    let encoded_ceiling = fit(encoded_ceiling_bytes())?;
    Ok(json!({
        "max_devices": max_devices,
        "encoded_ceiling": encoded_ceiling,
    }))
}

fn fit(value: usize) -> Result<u64, SdkError> {
    u64::try_from(value)
        .map_err(|_| SdkError::LocalBus("attachment limit does not fit the reply".into()))
}
