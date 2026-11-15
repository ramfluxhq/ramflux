// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retired crypto wrappers cannot install or advance authenticated transport state.
use super::*;

fn pair_rows(client: &RamfluxClient) -> Result<Vec<(String, Vec<u8>)>, SdkError> {
    const MAX_ROWS: u32 = 4096;
    let db = client.account_db()?;
    if db.actor_state_usage("dm-pair/")?.0 >= u64::from(MAX_ROWS) {
        return Err(SdkError::PayloadTooLarge);
    }
    db.actor_state_key_page("dm-pair/", MAX_ROWS)?
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
async fn retired_wrapper_quarantine_preserves_pair_bootstrap_and_ratchet() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(retired_wrapper_quarantine_body())
        .await
        .map_err(|_| invalid("test: retired-wrapper component exceeded its watchdog"))?
}

async fn retired_wrapper_quarantine_body() -> Result<(), SdkError> {
    let (a, mut b) = pair(201, 205).await?;
    let calibration = seal(&a, &b, message("native-calibration", "c"), b"native calibration")?;
    apply(&mut b, &calibration).await?;
    let before = pair_rows(&b.client)?;
    assert!(!before.is_empty(), "calibration must establish a real native pair");
    let mut entry = seal(&a, &b, message("retired-wrapper", "c"), b"never admitted")?;
    let retired = serde_json::to_vec(&serde_json::json!({
        "schema":"ramflux.sdk.dm_x3dh_envelope.v1", "version":1,
        "x3dh":null, "ciphertext":{},
    }))?;
    entry.inbox_seq = 2;
    entry.envelope.encrypted_payload = ramflux_protocol::encode_base64url(retired);
    entry.envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        entry.envelope.encrypted_payload.as_bytes(),
    );
    // A genuine native sender authenticates this malformed transport; it is still
    // not permission to select an obsolete decoder or mutate the live pair.
    resign(&a, &mut entry.envelope)?;
    assert!(
        ramflux_node_core::check_entry_bound(&entry.envelope).is_err(),
        "the node must reject a retired non-RF1C wrapper before inbox admission"
    );
    // Also exercise an already durable malformed entry: refusal cannot mutate the pair.
    Box::pin(settle_through(&mut b, vec![entry])).await?;
    let failure = b
        .client
        .account_db()?
        .latest_journal_event("message.undeliverable")?
        .ok_or_else(|| invalid("test: retired wrapper was not quarantined"))?;
    assert_eq!(
        failure.body["error_code"], "generated_content",
        "retired wire gets an immutable refusal"
    );
    assert_eq!(pair_rows(&b.client)?, before, "refusal must preserve pair/bootstrap/ratchet bytes");
    assert_eq!(
        b.client.gateway_receive_cursor(&b.config()?.target_delivery_id)?,
        2,
        "immutable refusal must settle the real inbox entry"
    );
    assert_eq!(projected(&b, "c")?, 1, "only the valid calibration may be rendered");
    Ok(())
}
