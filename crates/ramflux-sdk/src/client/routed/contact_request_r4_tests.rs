// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Held-request quota, restored consent and global-pressure overflow regressions.
use super::*;
const PRESSURE: &str = "contact-admission/backpressure";
async fn sync(state: &mut LocalBusDaemonState) -> Result<(), SdkError> {
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    Ok(())
}
fn inbox_len(directory: &Directory) -> Result<usize, SdkError> {
    Ok(directory.incoming.lock().map_err(|_| invalid("inbox"))?.len())
}
fn rescan_now(state: &LocalBusDaemonState) -> Result<(), SdkError> {
    let db = account(state, "bob")?.account_db()?;
    let mut pressure =
        db.load_actor_state::<Value>(PRESSURE)?.ok_or_else(|| invalid("no deferred floor"))?;
    pressure["next_at"] = json!(0);
    db.persist_actor_state(PRESSURE, &pressure)?;
    Ok(())
}
fn charge(state: &LocalBusDaemonState, bucket: &str, limit: u64) -> Result<(), SdkError> {
    let db = account(state, "bob")?.account_db()?;
    for _ in 0..limit {
        assert!(db.charge_contact_request(bucket, limit, 3600, now_unix_timestamp())?);
    }
    Ok(())
}
fn fill_pending(state: &LocalBusDaemonState) -> Result<Vec<String>, SdkError> {
    let db = account(state, "bob")?.account_db()?;
    let now = now_unix_timestamp();
    let mut roots = Vec::new();
    for index in 0..128 {
        let root = format!("r4-pending-root-{index}");
        assert!(db.persist_contact_request(&ramflux_storage::ContactRequestRecord {
            contact_identity_commitment: root.clone(),
            direction: "inbound".into(),
            request_id: format!("r4-pending-{index}"),
            principal_id: format!("r4-principal-{index}"),
            link_id: format!("r4-link-{index}"),
            state: "pending".into(),
            request_json: b"{}".to_vec(),
            expires_at: now + 3600,
            updated_at: now,
        })?);
        roots.push(root);
    }
    Ok(roots)
}
fn sender_budget_left(state: &LocalBusDaemonState) -> Result<bool, SdkError> {
    let root = r2::root(state, "alice")?;
    Ok(account(state, "bob")?.account_db()?.contact_request_budget_available(
        &format!("bootstrap:{root}"),
        2,
        now_unix_timestamp(),
    )?)
}

#[tokio::test]
async fn contact02_r4_account_pressure_redrives_do_not_spend_the_held_sender_quota()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 171)?;
    let mut b = Fixture::new("bob", 181)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    charge(&state, "inbound-account", 64)?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry];
    sync(&mut state).await?;
    assert_eq!(inbox_len(&directory)?, 1, "account pressure must defer, not drop");
    for _ in 0..34 {
        rescan_now(&state)?;
        sync(&mut state).await?;
        assert_eq!(inbox_len(&directory)?, 1, "held request was dead-lettered by redrive");
    }
    assert!(sender_budget_left(&state)?, "redrives spent the requester bootstrap quota");
    Ok(())
}

#[tokio::test]
async fn contact02_r4_pending_cap_held_request_is_admitted_when_capacity_frees()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 191)?;
    let mut b = Fixture::new("bob", 201)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    let filler = fill_pending(&state)?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry];
    sync(&mut state).await?;
    assert_eq!(inbox_len(&directory)?, 1, "pending cap must defer, not drop");
    for _ in 0..34 {
        rescan_now(&state)?;
        sync(&mut state).await?;
        assert_eq!(inbox_len(&directory)?, 1, "held request was dead-lettered by redrive");
    }
    let db = account(&state, "bob")?.account_db()?;
    for (index, root) in filler.iter().enumerate() {
        db.remove_contact_request(root, "inbound", &format!("r4-pending-{index}"))?;
    }
    rescan_now(&state)?;
    sync(&mut state).await?;
    assert_eq!(inbox_len(&directory)?, 0, "freed capacity did not admit the held request");
    assert!(account(&state, "bob")?.pending_contact_root(&r2::root(&state, "alice")?)?);
    Ok(())
}

#[tokio::test]
async fn contact02_r4_unblock_restores_admission_and_accepted_links_are_never_fenced()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 211)?;
    let mut b = Fixture::new("bob", 221)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = pending(&mut state, &directory).await?;
    let source = r2::root(&state, "alice")?;
    contact(&mut state, "bob", "contact.block", json!({"root_commitment":source})).await?;
    let receiver = account(&state, "bob")?;
    assert!(receiver.contact_request_admission(&entry).is_err(), "block must fence");
    let link = receiver
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("request"))?
        .link_id;
    contact(&mut state, "bob", "contact.unblock", json!({"link_id":link})).await?;
    let receiver = account(&state, "bob")?;
    assert!(receiver.friend_link_peer_is_accepted(&source)?);
    assert!(
        receiver.account_db()?.retained_contact_request_fence(&source)?.is_none(),
        "unblock left the block fence behind"
    );
    receiver.contact_request_admission(&entry)?;
    receiver.account_db()?.fence_contact_request(
        &source,
        "declined",
        now_unix_timestamp() + 3600,
    )?;
    receiver.contact_request_admission(&entry)?;
    Ok(())
}

#[tokio::test]
async fn contact02_r4_local_re_add_after_decline_accepts_the_peer_response() -> Result<(), SdkError>
{
    let mut a = Fixture::new("alice", 231)?;
    let mut b = Fixture::new("bob", 241)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let source = r2::root(&state, "alice")?;
    contact(&mut state, "bob", "contact.decline", json!({"root_commitment":source})).await?;
    flush(&mut state, "bob").await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "alice", &entry).await?;
    }
    contact(&mut state, "bob", "contact.add", json!({"principal_id":"alice"})).await?;
    assert!(
        account(&state, "bob")?.account_db()?.retained_contact_request_fence(&source)?.is_none(),
        "local re-add left this side's decline fence behind"
    );
    flush(&mut state, "bob").await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "alice", &entry).await?;
    }
    let target = r2::root(&state, "bob")?;
    contact(&mut state, "alice", "contact.accept", json!({"root_commitment":target})).await?;
    flush(&mut state, "alice").await?;
    let responses = frames(&directory)?;
    assert!(!responses.is_empty(), "peer accept produced no response");
    for entry in &responses {
        deliver(&mut state, "bob", entry).await?;
        account(&state, "bob")?.contact_request_admission(entry)?;
    }
    let outbound = account(&state, "bob")?
        .account_db()?
        .contact_request(&source, "outbound")?
        .ok_or_else(|| invalid("re-add request"))?;
    assert_eq!(outbound.state, "accepted", "peer acceptance after local re-add was fenced");
    Ok(())
}

async fn held_under_global_pressure(
    state: &mut LocalBusDaemonState,
    directory: &Directory,
    ttl: Option<u32>,
) -> Result<(), SdkError> {
    let mut entry = r2::outbound(state, directory).await?;
    if let Some(ttl) = ttl {
        entry.envelope.ttl = ttl;
        entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            account(state, "alice")?.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &entry.envelope,
        )?;
    }
    charge(state, "bootstrap-attempts", 120)?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry];
    sync(state).await?;
    assert_eq!(inbox_len(directory)?, 1);
    Ok(())
}

#[tokio::test]
async fn contact02_r4_global_pressure_rescans_skip_the_manifest_fetch() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 5)?;
    let mut b = Fixture::new("bob", 15)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    held_under_global_pressure(&mut state, &directory, None).await?;
    let fetched = directory.manifest_fetches.load(Ordering::SeqCst);
    for _ in 0..3 {
        rescan_now(&state)?;
        sync(&mut state).await?;
    }
    assert_eq!(inbox_len(&directory)?, 1);
    assert_eq!(
        directory.manifest_fetches.load(Ordering::SeqCst),
        fetched,
        "global-pressure rescans fetched the requester manifest"
    );
    Ok(())
}

#[tokio::test]
async fn contact02_r4_deferred_slot_expiry_is_capped_like_state_expiry() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 45)?;
    let mut b = Fixture::new("bob", 55)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    held_under_global_pressure(&mut state, &directory, Some(u32::MAX)).await?;
    let pressure = account(&state, "bob")?
        .account_db()?
        .load_actor_state::<Value>(PRESSURE)?
        .ok_or_else(|| invalid("pressure"))?;
    let slot = pressure["roots"][r2::root(&state, "alice")?]["expires_at"]
        .as_i64()
        .ok_or_else(|| invalid("slot"))?;
    assert!(slot <= now_unix_timestamp() + 604_860, "slot expiry is not capped");
    Ok(())
}

#[tokio::test]
async fn contact02_r4_root_overflow_under_global_pressure_stays_unacknowledged()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 25)?;
    let mut b = Fixture::new("bob", 35)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let mut entry = r2::outbound(&mut state, &directory).await?;
    entry.inbox_seq = 5000;
    let now = now_unix_timestamp();
    let roots = (0..1024)
        .map(|index| {
            (format!("r4-held-{index}"), json!({"sequence":index + 1,"expires_at":now + 3600}))
        })
        .collect::<serde_json::Map<_, _>>();
    account(&state, "bob")?.account_db()?.persist_actor_state(
        PRESSURE,
        &json!({"floor":9000,"next_at":now + 3600,"expires_at":now + 3600,"scan":null,"roots":roots}),
    )?;
    charge(&state, "bootstrap-attempts", 120)?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry];
    sync(&mut state).await?;
    assert_eq!(inbox_len(&directory)?, 1, "global-pressure overflow was dead-lettered");
    let pressure = account(&state, "bob")?
        .account_db()?
        .load_actor_state::<Value>(PRESSURE)?
        .ok_or_else(|| invalid("pressure"))?;
    assert_eq!(pressure["floor"], 5000, "overflow lost its replay floor");
    Ok(())
}
