// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise proxy selection on real local sockets without mutating process environment.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn private_literal_discovery_bypasses_proxies_while_public_discovery_retains_them()
-> Result<(), Box<dyn std::error::Error>> {
    for (home, bypass) in [
        ("http://127.0.0.1", true),
        ("http://localhost", true),
        ("http://192.168.42.1", true),
        ("http://10.0.0.1", true),
        ("http://172.16.0.1", true),
        ("https://169.254.1.1", true),
        ("http://[fc00::1]", true),
        ("http://[fe80::1]", true),
        ("http://[::1]", true),
        ("https://[::ffff:192.168.42.1]", true),
        ("https://node.local", false),
        ("https://example.com", false),
        ("https://203.0.113.1", false),
        ("https://100.64.0.1", false),
        ("https://[2001:db8::1]", false),
    ] {
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/.well-known/ramflux/client", origin.local_addr()?);
        let client = discovery_builder(
            reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(format!("http://{}", proxy.local_addr()?))?),
            &reqwest::Url::parse(home)?,
        )
        .build()?;
        let server = async {
            let (mut socket, direct) = tokio::select! {
                accepted=origin.accept()=> (accepted?.0,true),
                accepted=proxy.accept()=> (accepted?.0,false),
            };
            let mut bytes = [0; 4096];
            let size = socket.read(&mut bytes).await?;
            assert_eq!(direct, bypass, "{home}");
            let request = std::str::from_utf8(&bytes[..size])?;
            if bypass {
                assert!(request.starts_with("GET /.well-known/ramflux/client "));
            } else {
                assert!(request.starts_with(&format!("GET {url} ")));
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let (received, response) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(server, client.get(&url).send())
        })
        .await?;
        received?;
        assert_eq!(response?.status(), reqwest::StatusCode::OK);
    }
    Ok(())
}
