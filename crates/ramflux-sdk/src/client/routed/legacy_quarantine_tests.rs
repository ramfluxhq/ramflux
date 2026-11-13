// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generation-zero immutable quarantine must not install authenticated transport state.
use super::*;

fn pair_rows(client: &RamfluxClient) -> Result<Vec<(String, Vec<u8>)>, SdkError> {
    let db = client.account_db()?;
    db.actor_state_keys("dm-pair/")?
        .into_iter()
        .map(|key| {
            let value = db
                .load_actor_state::<Box<serde_json::value::RawValue>>(&key)?
                .ok_or_else(|| invalid("test pair row missing"))?;
            Ok((key, value.get().as_bytes().to_vec()))
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_body_invalid_quarantine_preserves_pair_bootstrap_and_ratchet()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        legacy_body_invalid_quarantine_preserves_pair_bootstrap_and_ratchet_body(),
    )
    .await
    .map_err(|_| invalid("test: legacy quarantine component exceeded its watchdog"))?
}

async fn legacy_body_invalid_quarantine_preserves_pair_bootstrap_and_ratchet_body()
-> Result<(), SdkError> {
    let (a, mut b) = pair(201, 205)?;
    assert!(
        !crate::client::target_selection::schema_v1_selected(),
        "test requires generation zero"
    );
    review::trust(&b, &a)?;
    review::trust(&a, &b)?;
    let mut message = message("legacy-invalid-body", "thread");
    message.recipient_principal_commitment = Some(b.client.own_account_anchor()?);
    let bundle = b.client.load_x3dh_private_state(&b.client.owned_device_identity()?)?.bundle;
    let hash = prekey_bundle_hash(&bundle)?;
    let aad = associated_data(&message.envelope_id, &a.id, &b.id, &hash)?;
    let (mut session, header) =
        a.client.create_send_dm_session_with_aad(&message, &b.id, bundle, &a.id, Some(&aad))?;
    message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v2".into(),
        version: 2,
        x3dh: header,
        ciphertext: session.encrypt(b"{", &aad)?,
        collapse_tag: None,
        report_commitment: None,
    })?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: b.id.clone(),
        envelope: gateway_direct_message_envelope(&a.config()?, &message, None)?,
    };
    let before = pair_rows(&b.client)?;
    Box::pin(settle_through(&mut b, vec![entry])).await?;
    let failure = b
        .client
        .account_db()?
        .latest_journal_event("message.undeliverable")?
        .ok_or_else(|| invalid("test: immutable invalid body was not quarantined"))?;
    assert_eq!(
        failure.body["error_code"], "schema_invalid",
        "AEAD-valid malformed body must take ordinary legacy quarantine"
    );
    assert!(
        pair_rows(&b.client)? == before,
        "quarantine must leave pair/bootstrap/ratchet bytes identical"
    );
    assert_eq!(
        b.client.gateway_receive_cursor(&b.id)?,
        1,
        "quarantine must settle the real inbox entry"
    );
    Ok(())
}
