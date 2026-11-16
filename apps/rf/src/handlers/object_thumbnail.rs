// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Prints inline thumbnail metadata from an existing message read.
//! Raw image bytes stay off stdout unless the caller names `--out`.

use crate::RfError;
use crate::cli::ObjectThumbnail;
use crate::utils::print_json;
use base64::Engine as _;
use ramflux_sdk::LocalBusClient;
use std::io::Write as _;

struct Thumbnail {
    object_id: String,
    mime: String,
    size: u64,
    width: u64,
    height: u64,
    bytes: Vec<u8>,
}

pub(super) async fn print(
    bus: &mut LocalBusClient,
    command: ObjectThumbnail,
) -> Result<(), RfError> {
    let body = bus
        .request(
            Some(command.account),
            "message",
            "message.read",
            serde_json::json!({
                "conversation_id": command.conversation,
                "message_id": command.message,
            }),
        )
        .await?;
    let mut found = Vec::new();
    collect(&body, "", &mut found)?;
    if let Some(path) = command.out.as_deref() {
        let [item] = found.as_slice() else {
            return Err(RfError::Message(
                "object thumbnail --out requires exactly one inline thumbnail".to_owned(),
            ));
        };
        write_private(path, &item.bytes)?;
    }
    let thumbnails = found
        .iter()
        .map(|item| {
            serde_json::json!({
                "object_id": item.object_id,
                "mime": item.mime,
                "size": item.size,
                "width": item.width,
                "height": item.height,
            })
        })
        .collect::<Vec<_>>();
    print_json(&serde_json::json!({ "thumbnails": thumbnails }))
}

fn collect(
    value: &serde_json::Value,
    object_id: &str,
    found: &mut Vec<Thumbnail>,
) -> Result<(), RfError> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect(item, object_id, found)?;
            }
        }
        serde_json::Value::Object(map) => {
            let object_id = map
                .get("objectId")
                .or_else(|| map.get("object_id"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(object_id);
            if let Some(thumbnail) =
                map.get("inlineThumbnail").or_else(|| map.get("inline_thumbnail"))
            {
                found.push(project(object_id, thumbnail)?);
            }
            for (key, child) in map {
                if key == "inlineThumbnail" || key == "inline_thumbnail" {
                    continue;
                }
                collect(child, object_id, found)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn project(object_id: &str, thumbnail: &serde_json::Value) -> Result<Thumbnail, RfError> {
    if object_id.is_empty() {
        return Err(RfError::Message("thumbnail has no object id".to_owned()));
    }
    let mime = thumbnail
        .get("mimeType")
        .or_else(|| thumbnail.get("mime_type"))
        .or_else(|| thumbnail.get("mime"))
        .and_then(serde_json::Value::as_str)
        .filter(|mime| !mime.is_empty())
        .ok_or_else(|| RfError::Message("thumbnail mime is missing".to_owned()))?
        .to_owned();
    let width = json_u64(thumbnail.get("width"), "width")?;
    let height = json_u64(thumbnail.get("height"), "height")?;
    let encoded = thumbnail
        .get("encodedImage")
        .or_else(|| thumbnail.get("encoded_image"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RfError::Message("thumbnail encoded image is missing".to_owned()))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| {
        RfError::Message("thumbnail encoded image is not standard base64".to_owned())
    })?;
    if bytes.is_empty() {
        return Err(RfError::Message("thumbnail encoded image is empty".to_owned()));
    }
    let size = u64::try_from(bytes.len())
        .map_err(|_| RfError::Message("thumbnail size exceeds u64".to_owned()))?;
    Ok(Thumbnail { object_id: object_id.to_owned(), mime, size, width, height, bytes })
}

fn json_u64(value: Option<&serde_json::Value>, name: &str) -> Result<u64, RfError> {
    let Some(value) = value else {
        return Err(RfError::Message(format!("thumbnail {name} is missing")));
    };
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_i64()
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| RfError::Message(format!("thumbnail {name} is not a number")))
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), RfError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(path);
            return Err(error.into());
        }
    }
    Ok(())
}
