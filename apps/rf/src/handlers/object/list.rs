// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Object listings consume bounded metadata pages, never encrypted payload arrays.
use crate::RfError;
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};

pub(super) async fn read(bus: &mut LocalBusClient, account: &str) -> Result<Value, RfError> {
    let mut cursor: Option<String> = None;
    let mut objects = Vec::new();
    loop {
        let page = bus
            .request(
                Some(account.to_owned()),
                "object",
                "object.directory",
                json!({"cursor":cursor,"limit":100}),
            )
            .await?;
        let rows = page["objects"]
            .as_array()
            .ok_or_else(|| RfError::Message("object directory is missing rows".into()))?;
        for row in rows {
            let mut row = row.clone();
            // Preserve the CLI's object_id selector while exposing the directory metadata.
            row["object_id"] = row["id"].clone();
            objects.push(row);
        }
        let Some(next) = page["next_cursor"].as_str() else {
            break;
        };
        if cursor.as_deref() == Some(next) {
            return Err(RfError::Message("object directory cursor did not advance".into()));
        }
        cursor = Some(next.to_owned());
    }
    Ok(json!({"objects":objects}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn cli_object_list_reads_every_bounded_metadata_page()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-list-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
            ));
        std::fs::create_dir_all(&root)?;
        let socket = root.join("bus.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            for (id, cursor, next) in
                [("first", None, Some("next")), ("second", Some("next"), None)]
            {
                let len = stream.read_u32().await?;
                let mut bytes = vec![0; usize::try_from(len)?];
                stream.read_exact(&mut bytes).await?;
                let mut request: ramflux_sdk::LocalBusFrame = serde_json::from_slice(&bytes)?;
                assert_eq!(request.method, "object.directory");
                assert_eq!(request.body["cursor"].as_str(), cursor);
                request.kind = ramflux_sdk::LocalBusFrameKind::Response;
                request.ok = Some(true);
                request.body = json!({"objects":[{"id":id,"size":300_000}],"next_cursor":next});
                let bytes = serde_json::to_vec(&request)?;
                stream.write_u32(u32::try_from(bytes.len())?).await?;
                stream.write_all(&bytes).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut bus = LocalBusClient::connect(&socket).await?;
        let value = read(&mut bus, "native-account").await?;
        assert_eq!(value["objects"].as_array().map(Vec::len), Some(2));
        assert_eq!(value["objects"][0]["object_id"], "first");
        assert_eq!(value["objects"][1]["object_id"], "second");
        server.await??;
        drop(bus);
        Ok(())
    }
}
