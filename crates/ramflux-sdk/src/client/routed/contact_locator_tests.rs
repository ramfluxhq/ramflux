// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! LAN locator import keeps profile pins, verified discovery, and typed bus refusals.
use super::*;

#[tokio::test]
async fn cf02_lan_http_card_export_and_import_resolve_with_a_pinned_key_and_reject_a_fingerprint_change()
-> Result<(), SdkError> {
    // Explicit fixture transport maps the synthetic LAN literal to a local origin.
    // Production proxy policy is tested independently; environment proxies are never mutated.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let bind = reservation.local_addr()?.to_string();
    drop(reservation);
    let client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://{bind}"))
                .map_err(|error| SdkError::LocalBus(error.to_string()))?,
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    crate::node::DISCOVERY_CLIENT.scope(client, lan_round_trip(&bind)).await
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
        Some("node_fingerprint_mismatch")
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
