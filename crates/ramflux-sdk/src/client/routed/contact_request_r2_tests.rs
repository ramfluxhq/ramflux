// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A decline selector names one stored request and leaves a different pending row alone.
use super::*;

fn root(state: &LocalBusDaemonState, who: &str) -> Result<String, SdkError> {
    Ok(account(state, who)?.owned_device_identity()?.root_commitment().into())
}

#[tokio::test]
async fn contact02_r2_root_selector_cannot_match_an_attackers_request_id() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 131)?;
    let mut b = Fixture::new("bob", 141)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let victim = root(&state, "alice")?;
    let own = root(&state, "bob")?;
    let attacker = ramflux_protocol::encode_base64url([42; 32]);
    for (root, id, name) in
        [(&victim, "victim-request", "victim"), (&attacker, victim.as_str(), "attacker")]
    {
        account(&state, "bob")?.account_db()?.persist_contact_request(
            &ramflux_storage::ContactRequestRecord {
                contact_identity_commitment: root.clone(),
                direction: "inbound".into(),
                request_id: id.into(),
                principal_id: name.into(),
                link_id: format!("link-{name}"),
                state: "pending".into(),
                request_json: serde_json::to_vec(&json!({
                    "note": null,
                    "nonce": ramflux_protocol::encode_base64url([1; 32]),
                    "issued_at": now_unix_timestamp()
                }))?,
                expires_at: now_unix_timestamp() + 604_800,
                updated_at: now_unix_timestamp(),
            },
        )?;
        account(&state, "bob")?.record_pending_friend_link(&format!("link-{name}"), root, &own)?;
    }
    let response =
        contact(&mut state, "bob", "contact.decline", json!({"root_commitment": victim})).await?;
    assert_eq!(response["principal_id"], "victim");
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .contact_request(&attacker, "inbound")?
            .ok_or_else(|| invalid("attacker"))?
            .state,
        "pending"
    );
    Ok(())
}
