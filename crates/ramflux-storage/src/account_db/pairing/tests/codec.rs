// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::journal::{
    HeadRow, decode_adoption, decode_floor, decode_head, decode_live, decode_terminal,
};
use super::super::schema::{
    ADOPTION_ROW_MAX, DESCRIPTOR_MAX, FLOOR_ROW_MAX, HEAD_ROW_MAX, ID_MAX, LIVE_ROW_MAX,
    TERMINAL_ROW_MAX,
};
use super::helpers::{
    TestResult, ack_bytes, adoption, context_bytes, field_err, floor, h, head, invited,
    publication, publication_at, terminal,
};
use ramflux_protocol::MAX_SAFE_JSON_INTEGER;

pub(super) fn live_submitted_candidate_state() -> TestResult {
    let row = invited()?;
    decode_live(&row)?;
    let mut submitted = row;
    submitted.phase = "submitted".into();
    submitted.context = Some(context_bytes()?);
    submitted.transcript_hash = Some(h(8));
    submitted.proposal_hash = Some(h(9));
    submitted.candidate_id = None;
    // BtF: omitting LiveRow::validate_candidate_state accepts this fixture.
    field_err(&decode_live(&submitted), "candidate_id");
    submitted.candidate_id = Some(h(20));
    decode_live(&submitted)?;
    submitted.candidate_id = Some(h(21));
    field_err(&decode_live(&submitted), "candidate_id");
    Ok(())
}

pub(super) fn row_field_and_size_bounds() -> TestResult {
    let mut row = invited()?;
    row.account_id.clear();
    field_err(&decode_live(&row), "account_id");
    row = invited()?;
    row.account_id = "x".repeat(129);
    field_err(&decode_live(&row), "account_id");
    row = invited()?;
    row.account_id = "a/b".into();
    field_err(&decode_live(&row), "account_id");
    row = invited()?;
    row.account_id = ".".into();
    field_err(&decode_live(&row), "account_id");
    row = invited()?;
    row.operation_id = "bad".into();
    field_err(&decode_live(&row), "operation_id");
    row = invited()?;
    row.account_id = "x".repeat(ID_MAX);
    decode_live(&row)?;
    row = invited()?;
    row.descriptor = vec![1; DESCRIPTOR_MAX + 1];
    field_err(&decode_live(&row), "descriptor");
    row = invited()?;
    let live_prefix = row.account_id.len()
        + row.operation_id.len()
        + row.invitation_id.len()
        + row.role.len()
        + row.phase.len()
        + row.base_record_hash.len();
    row.descriptor = vec![1; LIVE_ROW_MAX - live_prefix];
    let at_max = decode_live(&row);
    assert!(
        !matches!(at_max, Err(crate::StorageError::PairingField("size"))),
        "live at-max size: {at_max:?}"
    );
    row = invited()?;
    row.descriptor = vec![1; LIVE_ROW_MAX + 1];
    field_err(&decode_live(&row), "size");
    let mut prepared = head()?;
    prepared.publisher_ref = vec![1; 4097];
    field_err(&decode_head(&prepared), "publisher_ref");
    prepared = head()?;
    prepared.candidate = vec![1; HEAD_ROW_MAX + 1];
    field_err(&decode_head(&prepared), "size");
    Ok(())
}

pub(super) fn live_binds_descriptor_ids() -> TestResult {
    let row = invited()?;
    decode_live(&row)?;
    let mut mismatch = row.clone();
    mismatch.invitation_id = h(99);
    field_err(&decode_live(&mismatch), "invitation_id");
    mismatch = row.clone();
    mismatch.issuer_seq = 2;
    field_err(&decode_live(&mismatch), "issuer_seq");
    Ok(())
}

pub(super) fn head_binds_candidate_hash_and_ack() -> TestResult {
    let mut row = head()?;
    decode_head(&row)?;
    row.candidate_hash = h(31);
    field_err(&decode_head(&row), "candidate_hash");
    let (candidate, hash, epoch) = publication()?;
    row = head()?;
    row.candidate = candidate;
    row.candidate_hash = hash.clone();
    row.state = "acknowledged".into();
    row.ack = Some(ack_bytes(&hash, epoch)?);
    decode_head(&row)?;
    row.ack = Some(ack_bytes(&h(31), epoch)?);
    field_err(&decode_head(&row), "ack");
    row.ack = Some(ack_bytes(&hash, epoch + 1)?);
    field_err(&decode_head(&row), "ack");
    Ok(())
}

pub(super) fn head_candidate_is_immutable() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-head-immut")?;
    let prepared = head()?;
    db.put_pairing_head(&prepared)?;
    let mut acked = prepared.clone();
    let (_, hash, epoch) = publication()?;
    acked.state = "acknowledged".into();
    acked.ack = Some(ack_bytes(&hash, epoch)?);
    db.put_pairing_head(&acked)?;
    let stored = db.pairing_head()?.ok_or("head")?;
    assert_eq!(stored.state, "acknowledged");
    assert_eq!(stored.candidate_hash, prepared.candidate_hash);
    let mut replaced = prepared;
    let (candidate, hash, _) = publication_at(8)?;
    replaced.candidate = candidate;
    replaced.candidate_hash = hash;
    field_err(&db.put_pairing_head(&replaced), "candidate_hash");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn head_one_account_forward_only() -> TestResult {
    other_operation_refused()?;
    backward_state_refused()?;
    forward_state_allowed()?;
    Ok(())
}

fn head_state(state: &str) -> TestResult<HeadRow> {
    let mut row = head()?;
    row.state = state.into();
    if state == "acknowledged" {
        let (_, hash, epoch) = publication()?;
        row.ack = Some(ack_bytes(&hash, epoch)?);
    }
    Ok(row)
}

fn other_operation_refused() -> TestResult {
    for state in ["prepared", "submitted", "acknowledged"] {
        let (root, db) = crate::tests::test_db(&format!("pair04-head-other-{state}"))?;
        let existing = head_state(state)?;
        db.put_pairing_head(&existing)?;
        let mut other = head_state("prepared")?;
        other.operation_id = h(21);
        field_err(&db.put_pairing_head(&other), "operation_id");
        let stored = db.pairing_head()?.ok_or("head")?;
        assert_eq!(stored.operation_id, existing.operation_id);
        assert_eq!(stored.state, state);
        if state == "acknowledged" {
            assert!(stored.ack.is_some(), "ack kept");
        }
        let _ = std::fs::remove_dir_all(root);
    }
    Ok(())
}

fn backward_state_refused() -> TestResult {
    let transitions =
        [("acknowledged", "prepared"), ("acknowledged", "submitted"), ("submitted", "prepared")];
    for (from, to) in transitions {
        let (root, db) = crate::tests::test_db(&format!("pair04-head-back-{from}-{to}"))?;
        db.put_pairing_head(&head_state(from)?)?;
        field_err(&db.put_pairing_head(&head_state(to)?), "state");
        let stored = db.pairing_head()?.ok_or("head")?;
        assert_eq!(stored.state, from);
        if from == "acknowledged" {
            assert!(stored.ack.is_some(), "ack kept");
        }
        let _ = std::fs::remove_dir_all(root);
    }
    Ok(())
}

fn forward_state_allowed() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-head-forward")?;
    db.put_pairing_head(&head_state("prepared")?)?;
    db.put_pairing_head(&head_state("submitted")?)?;
    assert_eq!(db.pairing_head()?.ok_or("head")?.state, "submitted");
    db.put_pairing_head(&head_state("acknowledged")?)?;
    let stored = db.pairing_head()?.ok_or("head")?;
    assert_eq!(stored.state, "acknowledged");
    assert!(stored.ack.is_some());
    let _ = std::fs::remove_dir_all(root);
    let (root, db) = crate::tests::test_db("pair04-head-responder-ack")?;
    db.put_pairing_head(&head_state("prepared")?)?;
    db.put_pairing_head(&head_state("acknowledged")?)?;
    assert_eq!(db.pairing_head()?.ok_or("head")?.state, "acknowledged");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn put_refuses_foreign_account_and_anchor() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-account-scope")?;
    db.put_pairing_floor(&floor())?;
    let mut foreign = floor();
    foreign.account_id = "other".into();
    field_err(&db.put_pairing_floor(&foreign), "account_id");
    let mut live = invited()?;
    live.account_id = "other".into();
    field_err(&db.put_pairing_live(&live), "account_id");
    let mut head = head()?;
    head.account_id = "other".into();
    field_err(&db.put_pairing_head(&head), "account_id");
    let mut term = terminal();
    term.account_id = "other".into();
    field_err(&db.put_pairing_terminal(&term), "account_id");
    let mut adopt = adoption("secondary", None)?;
    adopt.account_id = "other".into();
    field_err(&db.put_pairing_adoption(&adopt), "account_id");
    let mut anchor = floor();
    anchor.account_anchor = h(9);
    field_err(&db.put_pairing_floor(&anchor), "account_anchor");
    let kept = db.pairing_floor()?.ok_or("floor")?;
    assert_eq!(kept.account_anchor, h(2));
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn floor_decrease_exact_errors() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-floor-decrease")?;
    db.put_pairing_floor(&floor())?;
    let mut issued = floor();
    issued.issued_seq = 2;
    field_err(&db.put_pairing_floor(&issued), "issued_seq");
    let mut generation = floor();
    generation.next_generation = 1;
    field_err(&db.put_pairing_floor(&generation), "next_generation");
    let kept = db.pairing_floor()?.ok_or("floor")?;
    assert_eq!(kept.issued_seq, 3);
    assert_eq!(kept.next_generation, 2);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn bounds_id_u_and_row_sizes() -> TestResult {
    let mut live = invited()?;
    live.generation = MAX_SAFE_JSON_INTEGER;
    decode_live(&live)?;
    live.generation = MAX_SAFE_JSON_INTEGER + 1;
    field_err(&decode_live(&live), "generation");
    let mut fl = floor();
    fl.issued_seq = MAX_SAFE_JSON_INTEGER;
    decode_floor(&fl)?;
    fl.issued_seq = MAX_SAFE_JSON_INTEGER + 1;
    field_err(&decode_floor(&fl), "issued_seq");
    fl = floor();
    fl.account_id = "x".repeat(ID_MAX);
    assert!(fl.account_id.len() + fl.account_anchor.len() + 16 <= FLOOR_ROW_MAX);
    decode_floor(&fl)?;
    fl.account_id.push('y');
    field_err(&decode_floor(&fl), "account_id");
    fl = floor();
    let floor_other = fl.account_anchor.len() + 16;
    fl.account_id = "x".repeat(FLOOR_ROW_MAX - floor_other + 1);
    field_err(&decode_floor(&fl), "size");
    let mut term = terminal();
    term.account_id = "x".repeat(ID_MAX);
    let term_len = term.account_id.len()
        + term.operation_id.len()
        + term.invitation_id.len()
        + term.outcome.len()
        + term.record_hash.as_ref().map_or(0, String::len)
        + term.cleanup.len()
        + 32;
    assert!(term_len <= TERMINAL_ROW_MAX);
    decode_terminal(&term)?;
    term.account_id.push('y');
    field_err(&decode_terminal(&term), "account_id");
    term = terminal();
    let term_other = term.operation_id.len()
        + term.invitation_id.len()
        + term.outcome.len()
        + term.record_hash.as_ref().map_or(0, String::len)
        + term.cleanup.len()
        + 32;
    term.account_id = "x".repeat(TERMINAL_ROW_MAX - term_other + 1);
    field_err(&decode_terminal(&term), "size");
    let mut adopt = adoption("secondary", None)?;
    adopt.account_id = "x".repeat(ID_MAX);
    adopt.branch_vault_ref = "b".repeat(ID_MAX);
    adopt.data_vault_ref = "d".repeat(ID_MAX);
    decode_adoption(&adopt)?;
    adopt.local_ref = vec![1; ADOPTION_ROW_MAX];
    field_err(&decode_adoption(&adopt), "size");
    Ok(())
}

pub(super) fn terminal_ttl_and_cap() -> TestResult {
    let (root, mut db) = crate::tests::test_db("pair04-terminal-ttl")?;
    db.set_clock(crate::AccountClock::fixed(1_000_000));
    let mut under = terminal();
    under.operation_id = h(10);
    under.invitation_id = h(11);
    under.finished_at = 1_000_000 - 24 * 60 * 60 + 1;
    db.put_pairing_terminal(&under)?;
    assert_eq!(db.pairing_terminal_count()?, 1);
    let mut first = terminal();
    first.finished_at = 1_000_000;
    db.put_pairing_terminal(&first)?;
    assert_eq!(db.pairing_terminal_count()?, 2);
    db.set_clock(crate::AccountClock::fixed(1_000_000 + 24 * 60 * 60));
    assert_eq!(db.pairing_terminal_count()?, 0);
    db.set_clock(crate::AccountClock::fixed(2_000_000));
    for n in 0..128_u8 {
        let mut row = terminal();
        row.operation_id = h(n);
        row.invitation_id = h(n.wrapping_add(100));
        row.local_seq = u64::from(n) + 1;
        row.finished_at = 2_000_000;
        db.put_pairing_terminal(&row)?;
    }
    assert_eq!(db.pairing_terminal_count()?, 128);
    let mut extra = terminal();
    extra.operation_id = h(200);
    extra.invitation_id = h(201);
    extra.local_seq = 200;
    extra.finished_at = 2_000_000;
    field_err(&db.put_pairing_terminal(&extra), "terminal_cap");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn live_cap_exact_error() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-live-cap")?;
    for n in 0..3_u8 {
        db.put_pairing_live(&super::helpers::invited_ids(30 + n, 60 + n, u64::from(n) + 1)?)?;
    }
    field_err(&db.put_pairing_live(&super::helpers::invited_ids(40, 70, 4)?), "live_cap");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn adoption_role_arms() -> TestResult {
    let primary = adoption("primary", Some("vault-primary"))?;
    decode_adoption(&primary)?;
    let mut missing = primary.clone();
    missing.primary_vault_ref = None;
    field_err(&decode_adoption(&missing), "primary_vault_ref");
    let secondary = adoption("secondary", None)?;
    decode_adoption(&secondary)?;
    let mut extra = secondary;
    extra.primary_vault_ref = Some("vault-primary".into());
    field_err(&decode_adoption(&extra), "primary_vault_ref");
    Ok(())
}
