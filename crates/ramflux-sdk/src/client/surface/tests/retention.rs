// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

#[tokio::test]
async fn history_is_bounded_and_reports_its_retained_version_range() -> TestResult {
    let f = Fixture::new().await?;
    create(&f)?;
    for version in 2..=270 {
        let signed = carrier(
            &f.author,
            PayloadKind::Event,
            &format!("v{version}"),
            &event(
                version,
                C::AppendText(AppendText {
                    surface_id: "s".into(),
                    path: "/stream".into(),
                    delta: "x".into(),
                    final_: false,
                }),
            )?,
        )?;
        assert!(project(&f.author, &signed, &signed.message_id)?.accepted);
    }
    let mut after = 0;
    let mut count = 0;
    loop {
        let page = f.author.surface_get("s", after, None)?;
        assert_eq!(page["history_first_version"], 15);
        assert_eq!(page["history_truncated"], true);
        count += page["hash_history"].as_array().ok_or("history")?.len();
        let Some(next) = page["history_next_version"].as_u64() else {
            break;
        };
        after = next;
    }
    assert_eq!(count, 256);
    assert_eq!(f.author.surface_get("s", 0, None)?["version"], 270);
    Ok(())
}
#[tokio::test]
async fn byte_retention_preserves_the_latest_record_and_rolls_back_an_oversized_write() -> TestResult
{
    let f = Fixture::new().await?;
    let db = f.author.account_db()?;
    let prefix = key("actions", "retention") + "/";
    for version in 1..=5 {
        db.persist_actor_state(
            &format!("{prefix}{version}"),
            &json!({"version":version,"payload":"1234567890"}),
        )?;
    }
    db.prune_surface_records(&prefix, 4, 100, &format!("{prefix}5"))?;
    let before = db.surface_history_page::<Value>(&prefix, &prefix, 100)?;
    assert!(before.len() <= 2);
    assert_eq!(before.last().ok_or("last")?["version"], 5);
    assert!(serde_json::to_vec(&before)?.len() <= 110);
    let result: Result<(), SdkError> = db.surface_transaction(|| {
        let id = format!("{prefix}huge");
        db.persist_actor_state(&id, &json!({"version":6,"payload":"x".repeat(128)}))?;
        db.prune_surface_records(&prefix, 1, 100, &id)?;
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(db.surface_history_page::<Value>(&prefix, &prefix, 100)?, before);
    Ok(())
}
#[tokio::test]
async fn one_large_accepted_action_remains_readable_by_action_id() -> TestResult {
    let f = Fixture::new().await?;
    let mut content = snapshot();
    content.components = vec![
        json!({"id":"root","component":"Column","children":["input","approve"]}),
        json!({"id":"input","component":"TextField","label":"Note","value":{"@path":"/note"}}),
        json!({"id":"label","component":"Text","text":"Submit"}),
        json!({"id":"approve","component":"Button","child":"label","action":{"event":{"name":"approve","context":{"note":{"@path":"/note"}}}}}),
    ];
    content.data_model = json!({"note":""});
    let create =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(content))?)?;
    assert!(project(&f.author, &create, "create-author")?.accepted, "author base must commit");
    assert!(project(&f.human, &create, "create-human")?.accepted, "owned-agent form must render");
    let view = f.author.surface_get("s", 0, None)?;
    let baseline = action(&f.human, "large", 1, view["surface_hash"].as_str().ok_or("hash")?)?;
    let parsed = ramflux_protocol::SurfaceAction::from_wire_bytes(
        &ramflux_protocol::decode_base64url(&baseline.wire_base64)?,
    )?;
    let mut frame = parsed.frame().clone();
    frame.a2ui.action.context = serde_json::from_value(json!({"note":"x".repeat(4000)}))?;
    frame.args_hash = frame.arguments_hash()?;
    let raw = frame.wire_bytes()?;
    let signed = carrier(&f.human, PayloadKind::Action, "large", &raw)?;
    assert!(
        project(&f.author, &signed, "large")?.accepted,
        "the bounded raw owned input must remain readable"
    );
    let mut padded = b" ".repeat(160_000);
    padded.extend(&raw);
    assert!(
        ramflux_protocol::SurfaceAction::from_wire_bytes(&padded).is_err(),
        "noncanonical oversized action bytes must fail closed"
    );
    let result = f.author.surface_get("s", 0, None)?;
    let id = result["last_action_id"].as_str().ok_or("action")?;
    let selected = f.author.surface_get("s", 0, Some(id))?;
    assert_eq!(selected["actions"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        ramflux_protocol::decode_base64url(
            selected["actions"][0]["wire_base64"].as_str().ok_or("wire")?
        )?,
        raw
    );
    assert!(serde_json::to_vec(&selected)?.len() < 512 * 1024);
    assert!(selected["actions"][0].get("carrier").is_none(), "wire must be present only once");
    Ok(())
}
