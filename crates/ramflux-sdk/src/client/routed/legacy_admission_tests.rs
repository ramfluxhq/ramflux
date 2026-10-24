// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy quarantine cannot starve a genuine first-contact routed deferral.
use super::*;
#[test]
fn forged_legacy_holds_release_admission_for_a_genuine_routed_first_contact() -> Result<(), SdkError>
{
    for expired in [false, true] {
        let alice = Fixture::new("alice", 21)?;
        let target = Fixture::new("bob", 31)?;
        let bob = Fixture::new("bob", 31)?;
        let genuine =
            seal(&alice, &target, message("genuine", "first-contact"), b"private genuine text")?;
        assert_eq!(
            target.client.open_routed(&genuine, "bob")?.body.as_slice(),
            b"private genuine text"
        );
        assert!(matches!(
            bob.client.authenticated_envelope_sender(&genuine),
            Err(SdkError::InboundPending(_))
        ));
        alice.client.create_group("g", "alice")?;
        let payload = alice.client.encrypt_group_message("g", "alice", b"legacy ciphertext")?;
        let now = now_unix_timestamp();
        let db = bob.client.account_db()?;
        for index in 0..16 {
            let mut forged = genuine.clone();
            forged.envelope.envelope_id = format!("forged-{index}");
            forged.envelope.source_device_id = format!("uncached-{index}");
            forged.envelope.encrypted_payload = ramflux_protocol::encode_base64url(&payload);
            forged.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
            let error = bob
                .client
                .authenticated_envelope_sender(&forged)
                .err()
                .ok_or_else(|| invalid("forged source unexpectedly trusted"))?;
            assert!(crate::client::inbox_failure::deterministic(&error).is_none());
            assert!(matches!(
                bob.client.isolate_legacy_group_delivery(&forged, Err(error))?,
                crate::client::group_quarantine::LegacyGroupDelivery::Held
            ));
            if !expired {
                db.park_legacy_inbox_retry(&crate::client::group_quarantine::legacy_key(&forged)?)?;
            }
        }
        let at = if expired { now + 31 } else { now + 1 };
        if expired {
            db.expire_inbox_holds(at)?;
        }
        let key = bob.client.inbox_admission_key(&genuine)?;
        assert!(
            crate::client::inbox_failure::defer_entry(
                &bob.client,
                "bob",
                &genuine,
                &key,
                &serde_json::to_vec(&genuine)?,
                at
            )?,
            "a genuine transient routed delivery must remain deferred, never ACK-dropped"
        );
        assert!(db.has_inbox_retry(&key)?);
        assert_eq!(db.unrouted_count()?, 16);
        assert!(!db.journal_after(0, 100)?.iter().any(|e| e.topic == "message.undeliverable"));
    }
    Ok(())
}
