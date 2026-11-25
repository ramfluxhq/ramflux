// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Central push fields of the established frame (`push_mode`, `push_keyset`).
//! Without `[push_central]` the node is in direct mode and sends no key set.
//! A configured section with an unreadable config is central without a key set, so the SDK refuses
//! to seal (fail closed).
use std::sync::OnceLock;

use ramflux_node_core::NodePushConfig;
use ramflux_node_core::push_handoff::{KeysetDoc, read_push_central_state};
use serde_json::{Map, Value};

/// Largest key set document the established frame may carry (A3.1).
const MAX_KEYSET_DOC_LEN: usize = 6144;

type Fields = (Option<&'static str>, Option<KeysetDoc>);

static CONFIG: OnceLock<Result<Option<NodePushConfig>, String>> = OnceLock::new();

fn config() -> &'static Result<Option<NodePushConfig>, String> {
    CONFIG.get_or_init(|| {
        ramflux_node_core::load_node_push_config(std::env::args().skip(1))
            .map_err(|error| error.to_string())
    })
}

/// The push fields for the established frame of this session.
pub(crate) fn established_fields() -> Fields {
    match config() {
        Ok(None) => (Some("direct"), None),
        Ok(Some(push)) => {
            let ks = match read_push_central_state(&push.state_file) {
                Ok(state) => state.and_then(|state| state.ks).filter(|doc| {
                    serde_json::to_vec(doc).is_ok_and(|bytes| bytes.len() <= MAX_KEYSET_DOC_LEN)
                }),
                Err(error) => {
                    tracing::warn!(%error, "push state unreadable; established frame has no key set");
                    None
                }
            };
            (Some("central"), ks)
        }
        Err(error) => {
            tracing::error!(%error, "push_central config unreadable; sealing is refused by clients");
            (Some("central"), None)
        }
    }
}

/// Adds `push_mode` and `push_keyset` to the session object at `pointer` of the frame value.
pub(crate) fn insert_fields(
    frame: &mut Value,
    pointer: &str,
    fields: &Fields,
) -> anyhow::Result<()> {
    let session = frame
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("established frame has no session object"))?;
    let mut extra = Map::new();
    if let Some(mode) = fields.0 {
        extra.insert("push_mode".to_owned(), Value::from(mode));
    }
    if let Some(doc) = &fields.1 {
        extra.insert("push_keyset".to_owned(), serde_json::to_value(doc)?);
    }
    session.extend(extra);
    Ok(())
}
