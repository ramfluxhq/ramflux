// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! LAN locator import keeps profile pins, verified discovery, and typed bus refusals.
use super::*;

#[test]
fn cf02_lan_http_card_export_and_import_resolve_with_a_pinned_key_and_reject_a_fingerprint_change()
-> Result<(), SdkError> {
    const CHILD: &str = "RAMFLUX_CONTACT_LOCATOR_CHILD";
    if let Ok(bind) = std::env::var(CHILD) {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(lan_round_trip(&bind));
    }
    // A process-local HTTP proxy routes the advertised LAN literal to this test's loopback server.
    // Proxy variables are set only on the child process, never mutated in the parallel harness.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let bind = reservation.local_addr()?.to_string();
    drop(reservation);
    let name = "client::routed::tests::contact_resolution::cards::locator::cf02_lan_http_card_export_and_import_resolve_with_a_pinned_key_and_reject_a_fingerprint_change";
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, &bind)
        .env("HTTP_PROXY", format!("http://{bind}"))
        .env("http_proxy", format!("http://{bind}"))
        .env("ALL_PROXY", format!("http://{bind}"))
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()?;
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "the child must execute the exact regression"
    );
    Ok(())
}
async fn lan_round_trip(bind: &str) -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin = Origin::bound(&directory, "contact.test", bind, Some("192.168.42.7")).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let text = exported["card"].as_str().ok_or_else(|| invalid("card"))?;
    let card = crate::parse_contact_card(text, now_unix_timestamp())?;
    assert_eq!(card.node.url, origin.url);
    assert_eq!(
        card.node.key_fingerprint,
        crate::contact_node_fingerprint(&origin.record.node_public_key)?
    );
    let mut wrong = card.clone();
    wrong.node.key_fingerprint = "0".repeat(64);
    let root = s
        .accounts
        .get("alice")
        .ok_or_else(|| invalid("alice"))?
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?;
    let (wrong, _) = crate::contact_card::encode_contact_card(
        wrong,
        root.signing_key.to_bytes(),
        now_unix_timestamp(),
    )?;
    let error = call(&mut s, "bob", "contact.add", json!({"card":wrong}))
        .await
        .err()
        .ok_or_else(|| invalid("wrong fingerprint accepted"))?;
    assert_eq!(
        crate::bus::io::local_bus_error_body(&error).reason_code.as_deref(),
        Some("card_signature_invalid")
    );
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    let added = call(&mut s, "bob", "contact.add", json!({"card":text})).await?;
    assert_eq!(added["contact"]["principal_id"], "alice");
    assert_eq!(added["contact"]["reachable"], true);
    assert_eq!(added["contact"]["root_commitment"], card.root_commitment);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn cf02_export_and_import_refuse_public_http_with_a_distinct_bus_reason()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin = Origin::new(&directory).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let mut card = crate::parse_contact_card(
        exported["card"].as_str().ok_or_else(|| invalid("card"))?,
        now_unix_timestamp(),
    )?;
    card.node.url = "http://203.0.113.7".into();
    let root = s
        .accounts
        .get("alice")
        .ok_or_else(|| invalid("alice"))?
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::canonical_json_bytes(
            &json!({"domain":"ramflux.contact.card.v1","body":card}),
        )?,
        root.signing_key.to_bytes(),
    );
    let text = format!(
        "ramflux-card:v1:{}",
        ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(
            &json!({"body":card,"signature":signature})
        )?)
    );
    s.nodes.profiles.get_mut("contact.test").ok_or_else(|| invalid("profile"))?.discovery_url =
        "http://203.0.113.7".into();
    for (account, method, body) in
        [("alice", "contact.card.export", json!({})), ("bob", "contact.add", json!({"card":text}))]
    {
        let error = call(&mut s, account, method, body)
            .await
            .err()
            .ok_or_else(|| invalid("public HTTP accepted"))?;
        let wire = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(wire.code, "ValidationFailed");
        assert_eq!(wire.reason_code.as_deref(), Some("home_insecure_transport"));
    }
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cf02_missing_and_stale_home_profiles_have_distinct_export_and_import_bus_reasons()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin = Origin::new(&directory).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let profile = s.nodes.profiles.remove("contact.test").ok_or_else(|| invalid("profile"))?;
    for reason in ["home_profile_missing", "home_profile_stale"] {
        if reason == "home_profile_stale" {
            let mut stale = profile.clone();
            stale.expires_at = 1;
            s.nodes.profiles.insert(stale.node_id.clone(), stale);
        }
        for (id, method, body) in [
            ("alice", "contact.card.export", json!({})),
            ("bob", "contact.add", json!({"card":exported["card"]})),
        ] {
            let error = call(&mut s, id, method, body)
                .await
                .err()
                .ok_or_else(|| invalid("unusable home accepted"))?;
            assert_eq!(
                crate::bus::io::local_bus_error_body(&error).reason_code.as_deref(),
                Some(reason)
            );
        }
    }
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cf02_registration_rate_limit_keeps_its_typed_bus_reason_and_retry_hint()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    let account = s.accounts.get_mut("alice").ok_or_else(|| invalid("alice"))?;
    let request = account.client.mvp1_identity_registration_request(
        "alice",
        "alice",
        "test",
        &account.principal_commitment,
    )?;
    let mut engine = account.take_live_engine().await?;
    let error = engine
        .register_identity(request)
        .await
        .err()
        .ok_or_else(|| invalid("registration accepted"))?;
    account.put_engine(engine);
    let wire = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(wire.code, "Unavailable");
    assert_eq!(wire.reason_code.as_deref(), Some("rate_limited"));
    assert_eq!(wire.retry_after_ms, Some(60000));
    Ok(())
}
