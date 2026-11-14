// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-Issue bulk work cannot freeze an actor's stale public native head.
#[cfg(test)]
mod tests {
    use super::super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_issue_refreshes_native_head_after_source_preparation() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let mut rig = Box::pin(Rig::open_profile(true)).await?;
        let account = crate::custody::load_data_account(
            &rig.participant_a.root,
            &rig.participant_a.account_id,
            rig.now,
        )?;
        let original = object_hash(account.record())?;
        let primary = account.group_primary(rig.participant_a.vault.as_ref())?;
        let mut body = account.record().body.clone();
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(object_hash(account.record())?);
        body.profile.display_name = "Fresh native source profile".into();
        let publication = Publication { record: primary.sign_record(body)?, compacted_ids: None };
        drop(primary);
        rig.node.persist_head(&publication, rig.now)?;
        let expected = object_hash(&publication.record)?;
        assert_ne!(original, expected, "test: profile publication did not advance source head");
        let issued = Box::pin(rig.primary.begin_full(full_begin(rig.now))).await?;
        let Outcome::Begin { value } = issued.outcome else {
            return Err("test: refreshed source did not issue a full invitation".into());
        };
        let token = value.invite_token;
        assert_eq!(
            token.invitation.body.base_record_hash, expected,
            "test: Issue used the actor head cached before source preparation"
        );
        rig.primary.lock().await?;
        Ok(())
    }
}
