// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-sealed Reaction receive, encrypted backup join, reopen and public projection.
use super::*;
use crate::GatewayInboxEntry;
use ramflux_protocol::message as g;
use ramflux_storage::{AccountDb, AccountIndex, BackupDatabase};

type ReactionInput = (GatewayInboxEntry, g::EventIdentity, g::Reaction);

#[derive(serde::Deserialize)]
struct RestoredRegister {
    identity: g::EventIdentity,
    reaction: g::Reaction,
}

fn seal_reaction(
    own: &Fixture,
    peer: &Fixture,
    target: &g::MessageRef,
    remove: bool,
    hlc: u64,
) -> TestResult<ReactionInput> {
    let mut identity =
        peer.client.allocate_generated_identity(&target.conversation_id, hlc, false)?;
    identity.hlc = hlc;
    let reaction = g::Reaction {
        target: Some(target.clone()),
        token: "👍".into(),
        remove,
        operation_id: identity.id.clone(),
    };
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content { value: Some(g::content::Value::Reaction(reaction.clone())) },
    )?;
    let envelope = peer.seal_inner_to(own, &exact)?;
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: hlc,
            target_delivery_id: own.config.target_delivery_id.clone(),
            envelope,
        },
        identity,
        reaction,
    ))
}

async fn receive_reaction(
    own: &mut Fixture,
    peer: &Fixture,
    target: &g::MessageRef,
    remove: bool,
    hlc: u64,
) -> TestResult<ReactionInput> {
    let input = seal_reaction(own, peer, target, remove, hlc)?;
    own.receive(input.0.envelope.clone(), hlc).await?;
    Ok(input)
}

#[tokio::test(flavor = "current_thread")]
async fn reaction_restore_preserves_signed_winner_and_replay() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        reaction_restore_preserves_signed_winner_and_replay_body(),
    )
    .await?
}

async fn reaction_restore_preserves_signed_winner_and_replay_body() -> TestResult {
    let mut own = Fixture::new("reaction-restore").await?;
    let peer = Fixture::new("reaction-restore-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (original, _, conversation) = history::receive_first_hand(&mut own, &peer).await?;
    let target = g::MessageRef {
        id: original.id,
        conversation_id: conversation.clone(),
        author_anchor: peer.client.own_account_anchor()?,
    };
    let message = ramflux_protocol::encode_base64url(&target.id);
    let add = receive_reaction(&mut own, &peer, &target, false, 100).await?;
    assert_eq!(
        own.client.generated_visible_reactions(&message)?.len(),
        1,
        "the real pair receive must project the original add before snapshot"
    );
    let old_path = own.root.0.join("reaction-add.db");
    let old = own.client.account_db()?.write_backup_snapshot(&old_path)?;
    let remove = receive_reaction(&mut own, &peer, &target, true, 200).await?;
    assert!(
        own.client.generated_visible_reactions(&message)?.is_empty(),
        "the real pair receive must project the newer removal before snapshot"
    );
    let unseen_older = seal_reaction(&own, &peer, &target, false, 150)?;
    let new_path = own.root.0.join("reaction-remove.db");
    let new = own.client.account_db()?.write_backup_snapshot(&new_path)?;
    reject_conflicting_receipt(&own, &peer, &add.2, &old_path, &old.key)?;
    for (number, (local, local_key, incoming, incoming_key)) in
        [(&old_path, &old.key, &new_path, &new.key), (&new_path, &new.key, &old_path, &old.key)]
            .into_iter()
            .enumerate()
    {
        restore_direction(
            &mut own,
            number,
            (local, local_key),
            (incoming, incoming_key),
            [&remove, &add, &unseen_older],
        )?;
    }
    Ok(())
}

fn restore_direction(
    own: &mut Fixture,
    number: usize,
    (local, local_key): (&std::path::Path, &ramflux_storage::AccountDbKey),
    (incoming, incoming_key): (&std::path::Path, &ramflux_storage::AccountDbKey),
    inputs: [&ReactionInput; 3],
) -> TestResult {
    let [remove, _, _] = inputs;
    let target = remove.2.target.as_ref().ok_or("reaction target")?;
    let conversation = target.conversation_id.clone();
    let message = ramflux_protocol::encode_base64url(&target.id);
    let account = own.client.account_db()?.local_account_id.clone();
    let index = AccountIndex::open(own.root.0.join(format!("restored-{number}")))?;
    index.create_account(&account, &own.client.own_account_anchor()?)?;
    let path = index.root().join(index.account(&account)?.db_relative_path);
    std::fs::create_dir_all(path.parent().ok_or("database parent")?)?;
    std::fs::copy(local, &path)?;
    let mut merged = BackupDatabase::open(&path, local_key)?;
    merged.merge_backup(incoming, incoming_key, || Ok(()))?;
    drop(merged);
    drop(own.client.active_account_db.take());
    own.client.active_account_db = Some(AccountDb::open(&index, &account, local_key)?);
    assert!(
        own.client.generated_visible_reactions(&message)?.is_empty(),
        "greater signed removal must win in both restore directions after reopen"
    );
    let registers = own
        .client
        .account_db()?
        .message_actor_entries::<RestoredRegister>(&message, "routed/reaction/")?;
    let [(_, winner)] = registers.as_slice() else {
        return Err("restored absent marker missing".into());
    };
    assert!(
        winner.reaction.remove && winner.identity == remove.1,
        "restore must retain the signed absent winner, not merely hide every register"
    );
    for (entry, identity, reaction) in inputs {
        own.client.apply_generated_reaction_entry(entry, identity, &conversation, reaction)?;
        assert!(
            own.client.generated_visible_reactions(&message)?.is_empty(),
            "duplicate removal and older opposite replay must preserve the restored winner"
        );
    }
    own.client.account_db()?.delete_direct_message(
        &conversation,
        &message,
        "local",
        "erase-reaction-target",
    )?;
    assert!(
        own.client.account_db()?.message_actor_keys(&message, "routed/reaction/")?.is_empty(),
        "target erasure must remove restored registers"
    );
    assert!(
        own.client
            .account_db()?
            .message_actor_keys(&message, "routed/reaction-operation/")?
            .is_empty(),
        "target erasure must remove restored operation receipts"
    );
    Ok(())
}

fn reject_conflicting_receipt(
    own: &Fixture,
    peer: &Fixture,
    add: &g::Reaction,
    old_path: &std::path::Path,
    old_key: &ramflux_storage::AccountDbKey,
) -> TestResult {
    let operation = format!(
        "routed/reaction-operation/{}/{}",
        peer.client.own_account_anchor()?,
        ramflux_protocol::encode_base64url(&add.operation_id)
    );
    let db = own.client.account_db()?;
    let bad = g::Reaction { remove: true, ..add.clone() };
    db.persist_actor_state(&operation, &bad)?;
    let bad_path = own.root.0.join("conflicting-receipt.db");
    let bad_snapshot = db.write_backup_snapshot(&bad_path)?;
    db.persist_actor_state(&operation, add)?;
    let account = db.local_account_id.clone();
    let index = AccountIndex::open(own.root.0.join("refused-restore"))?;
    index.create_account(&account, &own.client.own_account_anchor()?)?;
    let path = index.root().join(index.account(&account)?.db_relative_path);
    std::fs::create_dir_all(path.parent().ok_or("database parent")?)?;
    std::fs::copy(old_path, &path)?;
    let mut merged = BackupDatabase::open(&path, old_key)?;
    assert!(
        matches!(
            merged.merge_backup(&bad_path, &bad_snapshot.key, || Ok(())),
            Err(ramflux_storage::StorageError::AuthorizationRejected)
        ),
        "one operation identity cannot restore a different Reaction intent"
    );
    drop(merged);
    let restored = AccountDb::open(&index, &account, old_key)?;
    let target = add.target.as_ref().ok_or("reaction target")?;
    let registers = restored.message_actor_entries::<RestoredRegister>(
        &ramflux_protocol::encode_base64url(&target.id),
        "routed/reaction/",
    )?;
    assert!(
        registers.len() == 1 && registers.iter().all(|(_, row)| !row.reaction.remove),
        "failed receipt join must roll back the register winner too"
    );
    Ok(())
}
