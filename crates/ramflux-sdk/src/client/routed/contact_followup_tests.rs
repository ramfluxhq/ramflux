// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact retry and consent-boundary regressions through the public local bus.
use super::*;
fn card(principal: &str, seed: [u8; 32]) -> Result<String, SdkError> {
    let public = ramflux_crypto::public_key_base64url_from_seed(seed);
    let now = now_unix_timestamp();
    let body = crate::ContactCardBody {
        version: 1,
        principal_id: principal.into(),
        root_commitment: crate::identity_root_public_key_commitment(&public)?,
        root_public_key: public,
        node: crate::ContactNode {
            url: "https://node.example".into(),
            key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::public_key_base64url_from_seed([91; 32]),
            )?,
        },
        display_name: None,
        kind_asserted: None,
        issued_at: now,
        expires_at: now + 3600,
    };
    Ok(crate::contact_card::encode_contact_card(body, seed, now)?.0)
}
#[tokio::test]
async fn contact_accept_retries_return_the_auto_accepted_contact_and_refuse_conflicting_keys()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 31)?;
    let mut b = Fixture::new("bob", 41)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    contact(
        &mut state,
        "bob",
        "contact.requests.policy.set",
        json!({"contact_requests":"auto_accept"}),
    )
    .await?;
    pending(&mut state, &directory).await?;
    let client = account(&state, "alice")?;
    let seed =
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?.signing_key.to_bytes();
    let valid = card("alice", seed)?;
    let original = account(&state, "bob")?.contact_entry("alice")?;
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    for _ in 0..2 {
        let retry = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
        assert_eq!(retry["contact"], original);
    }
    let conflicting = card("alice", [211; 32])?;
    assert!(matches!(
        contact(&mut state, "bob", "contact.accept", json!({"card":conflicting})).await,
        Err(SdkError::ContactInput(crate::ContactReason::RootConflict))
    ));
    assert_eq!(account(&state, "bob")?.contact_entry("alice")?, original);
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    let root = original["root_commitment"].as_str().ok_or_else(|| invalid("root"))?;
    let db = account(&state, "bob")?.account_db()?;
    let request = db.contact_request(root, "inbound")?.ok_or_else(|| invalid("request"))?;
    db.remove_contact_request(root, "inbound", &request.request_id)?;
    let retry =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(retry["contact"], original, "retry also survives request retirement");
    Ok(())
}
