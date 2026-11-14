// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared attended enrollment through actual native and relay owners.
use super::*;
async fn exchange(rig: &mut Rig) -> Result<(String, String), SdkError> {
    rig.clock.advance_ms(1001);
    let a = phase(rig.primary.sync_relay().await?)?;
    rig.clock.advance_ms(1001);
    let b = phase(rig.secondary.sync_relay().await?)?;
    Ok((a, b))
}
pub(super) async fn enroll(rig: &mut Rig) -> TestResult {
    let begun = rig
        .primary
        .begin(Begin {
            schema: "ramflux.pairing.Begin.v2".into(),
            version: 2,
            capabilities: vec!["group".into(), "message".into(), "register".into(), "sync".into()],
            lease_not_before: rig.now,
            lease_expires_at: rig.now + 604_800,
            display_name: "Source phone".into(),
        })
        .await?;
    let Outcome::Begin { value } = begun.outcome else {
        return Err("test: enrollment invitation".into());
    };
    rig.secondary
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: value.invite_token,
            display_name: "Linked phone".into(),
        })
        .await?;
    for _ in 0..24 {
        exchange(rig).await?;
        if rig.primary.displayed_transcript().is_ok()
            && rig.secondary.displayed_transcript().is_ok()
        {
            break;
        }
    }
    let th = rig.primary.displayed_transcript()?;
    assert_eq!(th, rig.secondary.displayed_transcript()?, "test: enrollment SAS mismatch");
    for actor in [&mut rig.primary, &mut rig.secondary] {
        rig.clock.advance_ms(1001);
        actor
            .confirm(&Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: value.operation_id.clone(),
                generation: actor.actor_generation(),
                transcript_hash: th.clone(),
                r#match: true,
            })
            .await?;
    }
    for _ in 0..24 {
        if exchange(rig).await?.0 == "proposal_pending" {
            break;
        }
    }
    rig.clock.advance_ms(1001);
    rig.primary
        .approve(&Approve {
            schema: "ramflux.pairing.Approve.v2".into(),
            version: 2,
            operation_id: value.operation_id,
            generation: rig.primary.actor_generation(),
            transcript_hash: th,
            proposal_hash: rig.primary.displayed_proposal()?,
            approved: true,
        })
        .await?;
    for _ in 0..24 {
        if exchange(rig).await? == ("completed".into(), "completed".into()) {
            return Ok(());
        }
    }
    Err("test: original linked enrollment did not complete".into())
}
