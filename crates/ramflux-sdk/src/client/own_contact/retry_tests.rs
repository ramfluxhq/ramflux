// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable parked-contact scans wake on schedule and verified authority changes.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn parked_contact_retry_is_bounded_and_directory_or_roster_changes_wake_it() -> TestResult {
    for trigger in ["schedule", "directory", "roster", "upgrade"] {
        let root = std::env::temp_dir().join(format!(
            "rf-contact-retry-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        ));
        let own = super::tests::client(&root.join("own"), "bob", 1)?;
        let mut sibling = super::tests::client(&root.join("sibling"), "bob", 1)?;
        sibling.create_device_branch("bob", "second", 1, [8; 32]);
        let peer = super::tests::client(&root.join("peer"), "alice", 3)?;
        let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
        let mut roster = crate::client::identity_authority::test_support::public_manifest(&own)?;
        roster.devices.extend(
            crate::client::identity_authority::test_support::public_manifest(&sibling)?.devices,
        );
        crate::client::identity_authority::test_support::sign_manifest(
            own.identity_root.as_ref().ok_or("root")?,
            &mut roster,
            2,
        )?;
        own.persist_identity_directory(&roster)?;
        own.establish_friend_link(
            "missing",
            own.owned_device_identity()?.root_commitment(),
            &manifest.principal_commitment,
        )?;
        own.stage_contact_backfill_batch_at(100)?;
        own.stage_contact_backfill_batch_at(100)?;
        for at in [100, 105, 115, 135, 175] {
            assert_eq!(
                own.claim_contact_backfill_refresh(at)?,
                Some(manifest.principal_commitment.clone())
            );
        }
        assert_eq!(own.stage_contact_backfill_batch_at(175)?, 0);
        let db = own.account_db()?;
        assert_eq!(db.actor_state_usage("own-contact/parked/")?.0, 1);
        let complete =
            db.load_actor_state::<Backfill>("own-contact/backfill")?.ok_or("progress")?;
        assert!(complete.complete);
        assert_eq!(complete.retry_at, 475);
        // Identical own-directory refreshes must not defeat the parked retry delay.
        own.persist_identity_directory(&roster)?;
        assert_eq!(own.stage_contact_backfill_batch_at(474)?, 0);
        assert!(
            db.load_actor_state::<Backfill>("own-contact/backfill")?.ok_or("progress")?.complete
        );
        let at = match trigger {
            "schedule" => 475,
            "directory" => {
                own.persist_identity_directory(&manifest)?;
                200
            }
            "roster" => {
                crate::client::identity_authority::test_support::sign_manifest(
                    own.identity_root.as_ref().ok_or("root")?,
                    &mut roster,
                    3,
                )?;
                own.persist_identity_directory(&roster)?;
                200
            }
            _ => {
                // A pre-retry implementation may have completed permanently with old parked rows.
                db.persist_actor_state(
                    "own-contact/backfill",
                    &serde_json::json!({
                        "schema_version":1,"epoch":2,"cursor":"missing","complete":true,
                        "restrictions_done":true
                    }),
                )?;
                200
            }
        };
        assert_eq!(own.stage_contact_backfill_batch_at(at)?, 0);
        if trigger == "directory" {
            assert_eq!(own.stage_contact_backfill_batch_at(at)?, 1);
            assert_eq!(db.actor_state_usage("own-contact/parked/")?.0, 0);
        } else {
            assert_eq!(own.stage_contact_backfill_batch_at(at)?, 0);
            assert_eq!(
                own.claim_contact_backfill_refresh(at)?,
                Some(manifest.principal_commitment.clone())
            );
            assert_eq!(own.claim_contact_backfill_refresh(at)?, None);
        }
        drop((own, sibling, peer));
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
