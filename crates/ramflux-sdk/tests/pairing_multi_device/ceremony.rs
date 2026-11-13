// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended production coordinator; bounded causal packet exchanges, no readiness sleeps.
use super::{
    ResultOf,
    device::Device,
    node::{Node, now},
};
use ramflux_protocol::custody::pairing::local_dto::*;
fn phase(result: LocalResult) -> ResultOf<String> {
    match result.outcome {
        Outcome::Update { value } => Ok(value.phase),
        _ => Err("test: coordinator update missing".into()),
    }
}
async fn exchange(
    source: &mut Device,
    target: &mut Device,
    node: &Node,
) -> ResultOf<(String, String)> {
    node.clock.advance_ms(1001);
    let a = phase(source.actor.sync_relay().await?)?;
    node.clock.advance_ms(1001);
    let b = phase(target.actor.sync_relay().await?)?;
    Ok((a, b))
}
pub async fn enroll(source: &mut Device, target: &mut Device, node: &Node) -> ResultOf<()> {
    node.clock.advance_ms(1001);
    let begun = source
        .actor
        .begin(Begin {
            schema: "ramflux.pairing.Begin.v2".into(),
            version: 2,
            capabilities: vec!["group".into(), "message".into(), "register".into(), "sync".into()],
            lease_not_before: now()?,
            lease_expires_at: now()? + 86_400,
            display_name: "Phone".into(),
        })
        .await?;
    let Outcome::Begin { value } = begun.outcome else {
        return Err("test: missing invitation".into());
    };
    let operation = value.operation_id.clone();
    let generation = value.generation;
    target
        .actor
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: value.invite_token,
            display_name: target.id.clone(),
        })
        .await?;
    for _ in 0..24 {
        exchange(source, target, node).await?;
        if source.actor.displayed_transcript().is_ok()
            && target.actor.displayed_transcript().is_ok()
        {
            break;
        }
    }
    let transcript = source.actor.displayed_transcript()?;
    assert_eq!(
        transcript,
        target.actor.displayed_transcript()?,
        "test: independently staged devices displayed different SAS"
    );
    for actor in [&mut source.actor, &mut target.actor] {
        node.clock.advance_ms(1001);
        actor
            .confirm(&Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: operation.clone(),
                generation: actor.actor_generation(),
                transcript_hash: transcript.clone(),
                r#match: true,
            })
            .await?;
    }
    for _ in 0..24 {
        if exchange(source, target, node).await?.0 == "proposal_pending" {
            break;
        }
    }
    node.clock.advance_ms(1001);
    source
        .actor
        .approve(&Approve {
            schema: "ramflux.pairing.Approve.v2".into(),
            version: 2,
            operation_id: operation,
            generation,
            transcript_hash: transcript,
            proposal_hash: source.actor.displayed_proposal()?,
            approved: true,
        })
        .await?;
    for _ in 0..24 {
        let (a, b) = exchange(source, target, node).await?;
        if a == "completed" && b == "completed" {
            return Ok(());
        }
    }
    Err("test: real native enrollment did not reach both durable completion states".into())
}
