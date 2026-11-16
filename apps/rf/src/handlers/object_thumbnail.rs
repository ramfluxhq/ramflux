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
    let found = collect(&body)?;
    if let Some(path) = command.out.as_deref() {
        let [item] = found.as_slice() else {
            return Err(refused(
                "ThumbnailCount",
                "object thumbnail --out requires exactly one inline thumbnail",
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

fn refused(code: &'static str, message: impl Into<String>) -> RfError {
    RfError::Refused { code, message: message.into() }
}

/// `message.read` renders one detail. Media is only at
/// `message.content.message.media`, and pbjson emits camelCase.
fn collect(body: &serde_json::Value) -> Result<Vec<Thumbnail>, RfError> {
    let Some(media) = body
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|content| content.get("message"))
        .and_then(|message| message.get("media"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for item in media {
        let Some(thumbnail) = item.get("inlineThumbnail") else {
            continue;
        };
        let object_id = item.get("objectId").and_then(serde_json::Value::as_str).unwrap_or("");
        found.push(project(object_id, thumbnail)?);
    }
    Ok(found)
}

fn project(object_id: &str, thumbnail: &serde_json::Value) -> Result<Thumbnail, RfError> {
    if object_id.is_empty() {
        return Err(refused("ThumbnailInvalid", "thumbnail has no object id"));
    }
    let mime = thumbnail
        .get("mimeType")
        .and_then(serde_json::Value::as_str)
        .filter(|mime| !mime.is_empty())
        .ok_or_else(|| refused("ThumbnailInvalid", "thumbnail mime is missing"))?
        .to_owned();
    let width = json_u64(thumbnail.get("width"), "width")?;
    let height = json_u64(thumbnail.get("height"), "height")?;
    let encoded = thumbnail
        .get("encodedImage")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refused("ThumbnailInvalid", "thumbnail encoded image is missing"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| {
        refused("ThumbnailInvalid", "thumbnail encoded image is not standard base64")
    })?;
    if bytes.is_empty() {
        return Err(refused("ThumbnailInvalid", "thumbnail encoded image is empty"));
    }
    let size = u64::try_from(bytes.len())
        .map_err(|_| refused("ThumbnailInvalid", "thumbnail size exceeds u64"))?;
    Ok(Thumbnail { object_id: object_id.to_owned(), mime, size, width, height, bytes })
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), RfError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| output_refused(&error))?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(path);
        return Err(output_refused(&error));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(path);
            return Err(output_refused(&error));
        }
    }
    Ok(())
}

fn output_refused(error: &std::io::Error) -> RfError {
    refused("ThumbnailOutput", format!("thumbnail output: {error}"))
}

fn json_u64(value: Option<&serde_json::Value>, name: &str) -> Result<u64, RfError> {
    let Some(value) = value else {
        return Err(refused("ThumbnailInvalid", format!("thumbnail {name} is missing")));
    };
    let number =
        value.as_u64().or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()));
    match number {
        Some(number) if number > 0 => Ok(number),
        Some(_) => Err(refused("ThumbnailInvalid", format!("thumbnail {name} is zero"))),
        None => Err(refused("ThumbnailInvalid", format!("thumbnail {name} is not a number"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(media: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema": "ramflux.message.read_model.v1",
            "message": { "content": { "message": { "media": media } } },
            "snapshot_sequence": 1
        })
    }

    #[test]
    fn reads_only_message_content_message_media() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"thumb-bytes");
        let body = detail(&serde_json::json!([{
            "objectId": "object-1",
            "inlineThumbnail": {
                "mimeType": "image/jpeg",
                "width": 8,
                "height": 4,
                "encodedImage": encoded
            }
        }]));
        let found = collect(&body).expect("thumbnail");
        assert_eq!(found.len(), 1, "one inline thumbnail");
        assert_eq!(found[0].object_id, "object-1", "object id");
        assert_eq!(found[0].mime, "image/jpeg", "mime");
        assert_eq!(found[0].size, b"thumb-bytes".len() as u64, "decoded byte length");
        let snake = serde_json::json!({
            "message": {
                "media": [{
                    "object_id": "object-1",
                    "inline_thumbnail": {
                        "mime_type": "image/jpeg",
                        "width": 8,
                        "height": 4,
                        "encoded_image": encoded
                    }
                }],
                "content": {
                    "message": {
                        "media": [{
                            "object_id": "object-1",
                            "inline_thumbnail": {
                                "mime_type": "image/jpeg",
                                "width": 8,
                                "height": 4,
                                "encoded_image": encoded
                            }
                        }]
                    }
                }
            }
        });
        let ignored = collect(&snake).expect("other shapes are empty");
        assert!(
            ignored.is_empty(),
            "snake_case and a short path must not match ({} items)",
            ignored.len()
        );
        assert!(collect(&detail(&serde_json::json!([]))).expect("empty").is_empty(), "empty media");
    }

    #[test]
    fn missing_thumbnail_fields_are_thumbnail_invalid() {
        let body = detail(&serde_json::json!([{
            "objectId": "object-1",
            "inlineThumbnail": { "width": 1, "height": 1 }
        }]));
        let Err(error) = collect(&body) else {
            panic!("missing mime and image");
        };
        assert!(
            matches!(error, RfError::Refused { code: "ThumbnailInvalid", .. }),
            "typed code, got {error}"
        );
    }

    #[test]
    fn existing_output_file_is_thumbnail_output() {
        let dir = tempfile::TempDir::new().expect("test: temp");
        let path = dir.path().join("thumb.bin");
        std::fs::write(&path, b"already").expect("test: seed");
        let error = write_private(&path, b"new").expect_err("existing output file");
        assert!(
            matches!(error, RfError::Refused { code: "ThumbnailOutput", .. }),
            "typed output refusal, got {error}"
        );
        assert_eq!(
            std::fs::read(&path).expect("test: read"),
            b"already",
            "an existing output file is left unchanged"
        );
    }
}
