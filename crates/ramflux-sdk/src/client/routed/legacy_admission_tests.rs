// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retained quarantines cannot starve authenticated-root first-contact admission.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture as Native, TestResult, watchdog};
#[tokio::test(flavor = "current_thread")]
async fn retained_quarantine_holds_leave_admission_for_a_genuine_native_first_contact() -> TestResult
{
    watchdog::within(async {
        for expired in [false, true] {
            let alice = Native::with_principal("hold-alice", "alice", "alice").await?;
            let bob = Native::with_principal("hold-bob", "bob", "bob").await?;
            alice.accept_peer(&bob)?;
            bob.client.establish_friend_link(
                "native-contact",
                &bob.client.own_account_anchor()?,
                &alice.client.own_account_anchor()?,
            )?;
            let genuine = super::native_pair_tests::entry(
                &alice,
                &bob,
                &super::native_pair_tests::text(&alice, &bob, "private genuine text")?,
            )?;
            assert!(
                bob.client
                    .authenticated_envelope_sender(HeadUse::NewAuthorization, &genuine)
                    .is_err(),
                "fixture must require real sender lookup"
            );
            let now = now_unix_timestamp();
            let db = bob.client.account_db()?;
            for index in 0..16 {
                let mut forged = genuine.clone();
                forged.envelope.envelope_id = format!("forged-{index}");
                forged.envelope.source_device_id = format!("uncached-{index}");
                forged.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
                let key = crate::client::group_quarantine::legacy_key(&forged)?;
                db.hold_unrouted(&key, forged.inbox_seq, &serde_json::to_vec(&forged)?, now)?;
                db.retain_legacy_inbox(&key)?;
                if !expired {
                    db.park_legacy_inbox_retry(&key)?;
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
                "retained quarantines exhausted genuine native admission"
            );
            assert!(db.has_inbox_retry(&key)?);
            assert_eq!(db.unrouted_count()?, 16);
            assert!(
                !db.journal_after(0, 100)?
                    .iter()
                    .any(|event| event.topic == "message.undeliverable")
            );
        }
        Ok(())
    })
    .await?
}
