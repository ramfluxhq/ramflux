// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Answers `agent.host.credential` inside the v2 client. The key stays in the callback buffer
//! and the 0xC1 reply; it is never copied into a JSON frame.

use super::state::{HostKeyFn, Shared};
use crate::SdkError;
use crate::custody::pairing::CredentialOutcome;
use crate::custody::pairing::private_credential::{
    encode_reply, host_outcome, host_prompt_generation,
};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

pub(super) async fn answer(
    frame: &Value,
    shared: &Shared,
    replies: &mpsc::Sender<Zeroizing<Vec<u8>>>,
) -> Result<bool, SdkError> {
    if frame.get("method").and_then(Value::as_str) != Some("agent.host.credential")
        || frame.get("kind").and_then(Value::as_str) != Some("request")
    {
        return Ok(false);
    }
    let generation = generation(frame).ok_or_else(|| {
        SdkError::LocalBus("host credential prompt is missing its generation".into())
    })?;
    let provider = frame
        .get("body")
        .and_then(|body| body.get("provider"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let bytes = encode(shared, generation, provider)?;
    tokio::time::timeout(Duration::from_secs(5), replies.send(bytes))
        .await
        .map_err(|_| SdkError::LocalBus("credential reply timed out".into()))?
        .map_err(|_| SdkError::LocalBus("credential reply closed".into()))?;
    Ok(true)
}

fn generation(frame: &Value) -> Option<u64> {
    host_prompt_generation(frame.get("frame_id").and_then(Value::as_str)?)
}

fn encode(
    shared: &Shared,
    generation: u64,
    provider: &str,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let callback = shared
        .host_key
        .lock()
        .map_err(|_| SdkError::LocalBus("host key lock poisoned".into()))?
        .as_ref()
        .copied();
    let outcome = match callback {
        Some(callback) if !provider.is_empty() => callback_outcome(callback, provider),
        _ => CredentialOutcome::Refused,
    };
    encode_reply(generation, "provider", &outcome)
}

fn callback_outcome(callback: HostKeyFn, provider: &str) -> CredentialOutcome {
    let mut out = Zeroizing::new(vec![0_u8; 1024]);
    let mut len = 0_usize;
    let code = (callback.call)(
        provider.as_ptr(),
        provider.len(),
        out.as_mut_ptr(),
        out.len(),
        &raw mut len,
        callback.user as *mut std::ffi::c_void,
    );
    let outcome = if code == 0 && (1..=out.len()).contains(&len) {
        host_outcome(out.get(..len))
    } else {
        CredentialOutcome::Refused
    };
    out.zeroize();
    outcome
}
