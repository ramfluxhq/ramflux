// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    MAX_BACKING, MAX_CLAIMS, MAX_CLAIMS_PER_PREFIX, MAX_CLOSED, MAX_FRAME_BYTES,
    MAX_FRAMES_PER_DIRECTION, MAX_HOUR_ENTRIES, MAX_ISSUES_PER_HOUR, MAX_SLOTS,
    MAX_SLOTS_PER_ACCOUNT, PairingClock, PairingRelayConfig, PairingRelayError, PairingRelayStore,
    TestPairingClock,
};
use ramflux_crypto::sign_canonical_bytes_with_seed;
use ramflux_protocol::custody::pairing::native::{
    Create, CreateSlot, CreateSpec, CreateTicket, Created, Issued, ticket_signing_bytes,
};
use ramflux_protocol::custody::pairing::relay::{Claim, Close, Poll, RelayFrame, Send};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::encode_base64url;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, PairingRelayError>;

const WALL: u64 = 1_700_000_000;
const SEED: [u8; 32] = [7; 32];

fn open() -> TestResult<(PairingRelayStore, Arc<TestPairingClock>)> {
    let clock = TestPairingClock::new(WALL);
    let store = PairingRelayStore::new(PairingRelayConfig {
        clock: Arc::clone(&clock) as Arc<dyn PairingClock>,
        node_seed: SEED,
        public_origin: "https://relay.example:443".into(),
    })?;
    Ok((store, clock))
}

fn id(tag: u8) -> String {
    let mut bytes = [0_u8; 32];
    bytes[0] = tag;
    bytes[31] = 1;
    encode_base64url(bytes)
}

fn id_usize(n: usize) -> String {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
    encode_base64url(bytes)
}

fn spec_n(n: usize, wall: u64) -> CreateSpec {
    let account_anchor = id_usize(n);
    CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: account_anchor.clone(),
        primary_ref: DeviceRef {
            account_anchor,
            device_id: format!("device-{n}"),
            device_epoch: 1,
        },
        base_record_hash: id(2),
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: wall,
        lease_expires_at: wall + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    }
}

fn spec(account: u8, wall: u64) -> CreateSpec {
    let account_anchor = id(account);
    CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: account_anchor.clone(),
        primary_ref: DeviceRef {
            account_anchor,
            device_id: format!("device-{account}"),
            device_epoch: 1,
        },
        base_record_hash: id(2),
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: wall,
        lease_expires_at: wall + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    }
}

fn create_from_n(issued: &Issued, n: usize, wall: u64) -> Create {
    Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: issued.ticket.clone(),
        spec: spec_n(n, wall),
    }
}

fn close_live(store: &mut PairingRelayStore, created: &Created) -> TestResult {
    store.close(&Close {
        schema: "ramflux.pairing.Close.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        reason: "done".into(),
    })?;
    Ok(())
}

fn claim_of(created: &Created, nonce: usize) -> Claim {
    Claim {
        schema: "ramflux.pairing.Claim.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        recipient_token: created.recipient_token.clone(),
        claim_nonce: id_usize(nonce),
    }
}

fn create_from(issued: &Issued, account: u8, wall: u64) -> Create {
    Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: issued.ticket.clone(),
        spec: spec(account, wall),
    }
}

fn confirm(role: &str) -> RelayFrame {
    RelayFrame::Confirm { role: role.into(), transcript_hash: id(9), mac: id(10) }
}

fn send_body(created: &Created, role: &str, token: &str, seq: u64) -> Send {
    Send {
        schema: "ramflux.pairing.Send.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: role.into(),
        token: token.into(),
        seq,
        frame: confirm(role),
    }
}

fn fill_issued(store: &mut PairingRelayStore, count: usize) -> TestResult<Vec<(u8, Issued)>> {
    let mut out = Vec::new();
    for i in 0..count {
        let account = u8::try_from(i / MAX_SLOTS_PER_ACCOUNT)
            .map_err(|_| PairingRelayError::invalid("account"))?;
        out.push((account, store.issue(spec(account, WALL))?));
    }
    Ok(out)
}

fn fill_live(store: &mut PairingRelayStore, count: usize) -> TestResult<Vec<Created>> {
    let issued = fill_issued(store, count)?;
    let mut live = Vec::new();
    for (account, ticket) in issued {
        live.push(store.create(create_from(&ticket, account, WALL))?);
    }
    Ok(live)
}

fn exact(err: PairingRelayError, code: &str) -> TestResult {
    if err.code() == code { Ok(()) } else { Err(PairingRelayError::invalid("code")) }
}

fn books_match(store: &PairingRelayStore) -> TestResult {
    if store.accounted_bytes() != store.measured_bytes() {
        return Err(PairingRelayError::invalid("books"));
    }
    let stats = store.stats();
    if stats.backing != store.accounted_bytes() {
        return Err(PairingRelayError::invalid("backing"));
    }
    if stats.high_water > MAX_BACKING || stats.backing > MAX_BACKING {
        return Err(PairingRelayError::invalid("high_water"));
    }
    Ok(())
}

fn high_water_at_cap(store: &mut PairingRelayStore) -> TestResult {
    let live = fill_live(store, MAX_SLOTS)?;
    if live.len() != MAX_SLOTS {
        return Err(PairingRelayError::invalid("slots"));
    }
    let stats = store.stats();
    if stats.live != MAX_SLOTS {
        return Err(PairingRelayError::invalid("high_water"));
    }
    books_match(store)
}

fn one_over_is_busy_without_eviction(store: &mut PairingRelayStore) -> TestResult {
    match store.issue(spec(200, WALL)) {
        Err(PairingRelayError::Busy { retry_after_ms })
            if (1_000..=30_000).contains(&retry_after_ms) => {}
        Err(err) => return exact(err, "Busy"),
        Ok(_) => return Err(PairingRelayError::invalid("evicted")),
    }
    if store.stats().live != MAX_SLOTS {
        return Err(PairingRelayError::invalid("eviction"));
    }
    Ok(())
}

fn retired_paths(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(1, clock.wall_unix_secs()?))?;
    let created = store.create(create_from(&issued, 1, clock.wall_unix_secs()?))?;
    let token = created.primary_token.clone();
    let close = Close {
        schema: "ramflux.pairing.Close.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token,
        reason: "done".into(),
    };
    store.close(&close)?;
    match store.create(create_from(&issued, 1, clock.wall_unix_secs()?)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("close")),
    }
    let issued = store.issue(spec(1, clock.wall_unix_secs()?))?;
    clock.advance_secs(301);
    match store.create(create_from(&issued, 1, WALL)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("expiry")),
    }
    Ok(())
}

fn prune_reuse_and_restart() -> TestResult {
    let (mut store, clock) = open()?;
    let issued = store.issue(spec(3, WALL))?;
    clock.advance_secs(301);
    let _ = store.issue(spec(4, clock.wall_unix_secs()?))?;
    match store.create(create_from(&issued, 3, WALL)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("prune")),
    }
    let reuse = store.issue(spec(3, clock.wall_unix_secs()?))?;
    if reuse.ticket.body.create_id == issued.ticket.body.create_id {
        return Err(PairingRelayError::invalid("reuse"));
    }
    match store.create(create_from(&issued, 3, WALL)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("slot_reuse")),
    }
    let old = store.create(create_from(&reuse, 3, clock.wall_unix_secs()?))?;
    let boot = store.boot_id().to_owned();
    drop(store);
    let (mut restarted, _) = open()?;
    if restarted.boot_id() == boot {
        return Err(PairingRelayError::invalid("boot_id"));
    }
    match restarted.create(create_from(&reuse, 3, clock.wall_unix_secs()?)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("restart")),
    }
    if restarted.stats().slots != 0 {
        return Err(PairingRelayError::invalid("restart_alloc"));
    }
    books_match(&restarted)?;
    restarted.issue(spec(3, clock.wall_unix_secs()?))?;
    let _ = old;
    Ok(())
}

fn lost_replies(store: &mut PairingRelayStore) -> TestResult {
    let issued = store.issue(spec(5, WALL))?;
    if store.account_slots(&id(5)) != 1 {
        return Err(PairingRelayError::invalid("lost_issue"));
    }
    let created = store.create(create_from(&issued, 5, WALL))?;
    let invitation = created.invitation.body.invitation_id.clone();
    let primary = created.primary_token.clone();
    drop(created);
    let again = store.create(create_from(&issued, 5, WALL))?;
    if again.invitation.body.invitation_id != invitation || again.primary_token != primary {
        return Err(PairingRelayError::invalid("lost_created"));
    }
    Ok(())
}

fn fill_role_queue(
    store: &mut PairingRelayStore,
    created: &Created,
    role: &str,
    token: &str,
) -> TestResult {
    for seq in 0..MAX_FRAMES_PER_DIRECTION as u64 {
        store.send(&send_body(created, role, token, seq))?;
    }
    match store.send(&send_body(created, role, token, 2)) {
        Err(err) => exact(err, "Busy"),
        Ok(_) => Err(PairingRelayError::invalid("queue")),
    }
}

fn independent_counts(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    books_match(store)?;
    let live = fill_live(store, MAX_SLOTS)?;
    books_match(store)?;
    for (i, created) in live.iter().enumerate() {
        fill_role_queue(store, created, "initiator", &created.primary_token)?;
        let octet = u8::try_from(i / MAX_CLAIMS_PER_PREFIX)
            .map_err(|_| PairingRelayError::invalid("prefix"))?;
        store.claim(IpAddr::V4(Ipv4Addr::new(198, 51, octet, 1)), &claim_of(created, i))?;
        fill_role_queue(store, created, "responder", &created.recipient_token)?;
    }
    let stats = store.stats();
    if stats.queued_frames != MAX_SLOTS * 4
        || stats.claims != MAX_CLAIMS
        || stats.sockets != MAX_CLAIMS
    {
        return Err(PairingRelayError::invalid("sockets"));
    }
    if stats.queued_bytes == 0 || stats.queued_bytes == stats.queued_frames * MAX_FRAME_BYTES {
        return Err(PairingRelayError::invalid("queued_bytes"));
    }
    books_match(store)
}

fn sparse_and_isolation(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(7, WALL))?;
    let create_id = issued.ticket.body.create_id.clone();
    match store.lookup_create(&id(8), &create_id) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("isolation")),
    }
    if store.lookup_create(&id(7), &create_id)? != CreateSlot::Issued {
        return Err(PairingRelayError::invalid("owner"));
    }
    match store.lookup_create(&id(7), &id(99)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("sparse")),
    }
    if store.account_slots(&id(8)) != 0 {
        return Err(PairingRelayError::invalid("foreign_quota"));
    }
    Ok(())
}

fn lost_holder(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    let issued = store.issue(spec(9, WALL))?;
    let created = store.create(create_from(&issued, 9, WALL))?;
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let claim = |nonce: u8| Claim {
        schema: "ramflux.pairing.Claim.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        recipient_token: created.recipient_token.clone(),
        claim_nonce: id(nonce),
    };
    store.claim(ip, &claim(1))?;
    if store.stats().claims != 1 {
        return Err(PairingRelayError::invalid("claim"));
    }
    clock.advance_ms(9_999);
    store.issue(spec(10, clock.wall_unix_secs()?))?;
    if store.stats().claims != 1 {
        return Err(PairingRelayError::invalid("grace_in"));
    }
    clock.advance_ms(1);
    store.issue(spec(16, clock.wall_unix_secs()?))?;
    if store.stats().claims != 0 {
        return Err(PairingRelayError::invalid("lost_holder"));
    }
    store.claim(ip, &claim(1))?;
    match store.claim(ip, &claim(2)) {
        Err(err) => exact(err, "Replay")?,
        Ok(_) => return Err(PairingRelayError::invalid("nonce")),
    }
    Ok(())
}

fn hour_and_account_caps(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    for _ in 0..3 {
        for _ in 0..MAX_SLOTS_PER_ACCOUNT {
            store.issue(spec(11, clock.wall_unix_secs()?))?;
        }
        match store.issue(spec(11, clock.wall_unix_secs()?)) {
            Err(err) => exact(err, "Busy")?,
            Ok(_) => return Err(PairingRelayError::invalid("account")),
        }
        clock.advance_secs(301);
    }
    store.issue(spec(11, clock.wall_unix_secs()?))?;
    match store.issue(spec(11, clock.wall_unix_secs()?)) {
        Err(err) => exact(err, "Busy")?,
        Ok(_) => return Err(PairingRelayError::invalid("hour")),
    }
    let _ = MAX_ISSUES_PER_HOUR;
    clock.advance_secs(3_601);
    store.issue(spec(11, clock.wall_unix_secs()?))?;
    Ok(())
}

fn missing_slot_stays_retired(store: &mut PairingRelayStore) -> TestResult {
    let mut ticket = CreateTicket {
        schema: "ramflux.pairing.CreateTicket.v2".into(),
        version: 2,
        node_key: store.node_key().into(),
        boot_id: store.boot_id().into(),
        create_id: id(42),
        issuer_seq: 1,
        account_anchor: id(12),
        primary_ref: spec(12, WALL).primary_ref,
        spec_hash: spec(12, WALL).spec_hash().map_err(|_| PairingRelayError::invalid("hash"))?,
        issued_at: WALL,
        expires_at: WALL + 300,
    };
    ticket.account_anchor = spec(12, WALL).account_anchor;
    let bytes = ticket_signing_bytes(&ticket).map_err(|_| PairingRelayError::invalid("sign"))?;
    let create = Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: Envelope { body: ticket, signature: sign_canonical_bytes_with_seed(&bytes, SEED) },
        spec: spec(12, WALL),
    };
    match store.create(create) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("missing")),
    }
    if store.account_slots(&id(12)) != 0 {
        return Err(PairingRelayError::invalid("missing_alloc"));
    }
    Ok(())
}

fn poll_rate_and_retry(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(13, WALL))?;
    let created = store.create(create_from(&issued, 13, WALL))?;
    let send = send_body(&created, "initiator", &created.primary_token, 0);
    store.send(&send)?;
    store.send(&send)?;
    store.claim(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)), &claim_of(&created, 13))?;
    let poll = Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "responder".into(),
        token: created.recipient_token.clone(),
        after_seq: None,
    };
    store.poll(&poll)?;
    store.poll(&poll)?;
    match store.poll(&poll) {
        Err(err) => exact(err, "Busy")?,
        Ok(_) => return Err(PairingRelayError::invalid("poll")),
    }
    Ok(())
}

fn wall_rollback(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    let issued = store.issue(spec(14, WALL))?;
    clock.set_wall(WALL - 100);
    clock.advance_ms(301_000);
    match store.create(create_from(&issued, 14, WALL)) {
        Err(err) => exact(err, "Retired")?,
        Ok(_) => return Err(PairingRelayError::invalid("rollback")),
    }
    Ok(())
}

fn hour_map_cap(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    for n in 0..MAX_HOUR_ENTRIES {
        if n > 0 && n % MAX_CLOSED == 0 {
            clock.advance_secs(301);
        }
        let wall = clock.wall_unix_secs()?;
        let issued = store.issue(spec_n(n, wall))?;
        let created = store.create(create_from_n(&issued, n, wall))?;
        close_live(store, &created)?;
        if n % 64 == 0 {
            books_match(store)?;
        }
    }
    match store.issue(spec_n(MAX_HOUR_ENTRIES, clock.wall_unix_secs()?)) {
        Err(err) => exact(err, "Busy")?,
        Ok(_) => return Err(PairingRelayError::invalid("hour_map")),
    }
    store.issue(spec_n(0, clock.wall_unix_secs()?))?;
    books_match(store)
}

fn claim_four_then_busy(
    store: &mut PairingRelayStore,
    live: &[Created],
    ip_at: impl Fn(usize) -> IpAddr,
    nonce_base: usize,
) -> TestResult {
    if live.len() < 5 {
        return Err(PairingRelayError::invalid("prefix_slots"));
    }
    for (i, created) in live.iter().enumerate().take(4) {
        store.claim(ip_at(i), &claim_of(created, nonce_base + i))?;
    }
    let fifth = live.get(4).ok_or(PairingRelayError::invalid("prefix_slots"))?;
    match store.claim(ip_at(4), &claim_of(fifth, nonce_base + 4)) {
        Err(err) => exact(err, "Busy"),
        Ok(_) => Err(PairingRelayError::invalid("prefix")),
    }
}

fn prefix_caps(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let live = fill_live(store, 5)?;
    claim_four_then_busy(
        store,
        &live,
        |i| IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(i + 1).unwrap_or(1))),
        200,
    )?;
    store.shutdown();
    let live = fill_live(store, 5)?;
    claim_four_then_busy(
        store,
        &live,
        |i| {
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                2,
                1,
                0,
                0,
                0,
                u16::try_from(i + 1).unwrap_or(1),
            ))
        },
        210,
    )?;
    store.shutdown();
    let live = fill_live(store, 5)?;
    claim_four_then_busy(
        store,
        &live,
        |i| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, u16::try_from(i).unwrap_or(0), 0, 0, 0, 1)),
        220,
    )?;
    store.shutdown();
    let live = fill_live(store, 5)?;
    claim_four_then_busy(
        store,
        &live,
        |i| {
            IpAddr::V6(
                Ipv4Addr::new(203, 0, 113, u8::try_from(i + 1).unwrap_or(1)).to_ipv6_mapped(),
            )
        },
        230,
    )
}

fn close_idempotent(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(22, WALL))?;
    let created = store.create(create_from(&issued, 22, WALL))?;
    let close = Close {
        schema: "ramflux.pairing.Close.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        reason: "done".into(),
    };
    let first = store.close(&close)?;
    let second = store.close(&close)?;
    if first != second {
        return Err(PairingRelayError::invalid("close_retry"));
    }
    let polled = store.poll(&Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        after_seq: None,
    })?;
    if !polled.closed {
        return Err(PairingRelayError::invalid("polled_closed"));
    }
    books_match(store)
}

fn responder_needs_claim(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(23, WALL))?;
    let created = store.create(create_from(&issued, 23, WALL))?;
    match store.send(&send_body(&created, "responder", &created.recipient_token, 0)) {
        Err(err) => exact(err, "WrongContext")?,
        Ok(_) => return Err(PairingRelayError::invalid("unclaimed")),
    }
    store.claim(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23)), &claim_of(&created, 23))?;
    store.send(&send_body(&created, "responder", &created.recipient_token, 0))?;
    Ok(())
}

fn stale_requeue(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    let issued = store.issue(spec(24, WALL))?;
    let created = store.create(create_from(&issued, 24, WALL))?;
    let send = send_body(&created, "initiator", &created.primary_token, 0);
    store.send(&send)?;
    clock.advance_ms(10_000);
    store.issue(spec(25, clock.wall_unix_secs()?))?;
    store.send(&send)?;
    store.claim(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 24)), &claim_of(&created, 24))?;
    let polled = store.poll(&Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "responder".into(),
        token: created.recipient_token.clone(),
        after_seq: None,
    })?;
    if polled.frames.len() != 1 || polled.frames[0].seq != 0 {
        return Err(PairingRelayError::invalid("requeue"));
    }
    books_match(store)
}

fn acked_send_not_requeued(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    let issued = store.issue(spec(27, WALL))?;
    let created = store.create(create_from(&issued, 27, WALL))?;
    let send = send_body(&created, "initiator", &created.primary_token, 0);
    store.send(&send)?;
    store.claim(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 27)), &claim_of(&created, 27))?;
    let poll = |after_seq: Option<u64>| Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "responder".into(),
        token: created.recipient_token.clone(),
        after_seq,
    };
    let first = store.poll(&poll(None))?;
    if first.frames.len() != 1 || first.frames[0].seq != 0 {
        return Err(PairingRelayError::invalid("acked_first"));
    }
    store.poll(&poll(Some(0)))?;
    store.send(&send)?;
    if store.stats().queued_frames != 0 {
        return Err(PairingRelayError::invalid("acked_requeue"));
    }
    clock.advance_ms(1_001);
    let polled = store.poll(&poll(None))?;
    if !polled.frames.is_empty() {
        return Err(PairingRelayError::invalid("acked_poll"));
    }
    books_match(store)
}

fn closed_map_cap(store: &mut PairingRelayStore, clock: &TestPairingClock) -> TestResult {
    store.shutdown();
    clock.set_wall(WALL);
    clock.set_mono(0);
    for n in 0..MAX_CLOSED {
        let issued = store.issue(spec_n(n, WALL))?;
        let created = store.create(create_from_n(&issued, n, WALL))?;
        close_live(store, &created)?;
        books_match(store)?;
    }
    let issued = store.issue(spec_n(MAX_CLOSED, WALL))?;
    let created = store.create(create_from_n(&issued, MAX_CLOSED, WALL))?;
    match close_live(store, &created) {
        Err(err) => exact(err, "Busy")?,
        Ok(()) => return Err(PairingRelayError::invalid("closed_map")),
    }
    if store.stats().live != 1 {
        return Err(PairingRelayError::invalid("closed_evict"));
    }
    books_match(store)
}

fn send_cipher(created: &Created, token: &str, seq: u64, nbytes: usize) -> Send {
    Send {
        schema: "ramflux.pairing.Send.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: token.into(),
        seq,
        frame: RelayFrame::Channel { counter: 0, ciphertext: encode_base64url(vec![0_u8; nbytes]) },
    }
}

fn encoded_send_len(send: &Send) -> usize {
    ramflux_protocol::canonical_json_bytes(send).map_or(0, |bytes| bytes.len())
}

fn frame_max_plus_minus(store: &mut PairingRelayStore) -> TestResult {
    store.shutdown();
    let issued = store.issue(spec(26, WALL))?;
    let created = store.create(create_from(&issued, 26, WALL))?;
    let token = created.primary_token.clone();
    let mut lo = 16_usize;
    let mut hi = 11_716_usize;
    while lo < hi {
        let mid = lo.saturating_add(hi).saturating_add(1) / 2;
        if encoded_send_len(&send_cipher(&created, &token, 0, mid)) <= MAX_FRAME_BYTES {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    store.send(&send_cipher(&created, &token, 0, lo))?;
    match store.send(&send_cipher(&created, &token, 1, lo.saturating_add(1))) {
        Err(err) => exact(err, "InvalidInput")?,
        Ok(_) => return Err(PairingRelayError::invalid("frame_over")),
    }
    Ok(())
}

#[test]
fn pairing_relay_caps_expiry_and_account_isolation() -> TestResult {
    let (mut store, clock) = open()?;
    books_match(&store)?;
    high_water_at_cap(&mut store)?;
    one_over_is_busy_without_eviction(&mut store)?;
    retired_paths(&mut store, &clock)?;
    lost_replies(&mut store)?;
    independent_counts(&mut store)?;
    sparse_and_isolation(&mut store)?;
    lost_holder(&mut store, &clock)?;
    hour_and_account_caps(&mut store, &clock)?;
    hour_map_cap(&mut store, &clock)?;
    missing_slot_stays_retired(&mut store)?;
    poll_rate_and_retry(&mut store)?;
    wall_rollback(&mut store, &clock)?;
    prefix_caps(&mut store)?;
    close_idempotent(&mut store)?;
    responder_needs_claim(&mut store)?;
    stale_requeue(&mut store, &clock)?;
    acked_send_not_requeued(&mut store, &clock)?;
    closed_map_cap(&mut store, &clock)?;
    frame_max_plus_minus(&mut store)?;
    prune_reuse_and_restart()?;
    Ok(())
}
