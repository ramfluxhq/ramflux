// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::journal::{HeadRow, decode_adoption, decode_head, decode_live};
use super::super::schema::{HEAD_ROW_MAX, LIVE_ROW_MAX};
use super::helpers::{TestResult, adoption, context_bytes, field_err, h, invited, ref_bytes};

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
    row.descriptor = vec![1; LIVE_ROW_MAX + 1];
    field_err(&decode_live(&row), "descriptor");
    let mut head = HeadRow {
        account_id: "acct".into(),
        operation_id: h(20),
        invitation_id: Some(h(1)),
        generation: 1,
        kind: "enroll".into(),
        base_record_hash: h(4),
        base_epoch: 1,
        publisher_ref: vec![1; 4097],
        candidate: vec![1; 16],
        candidate_hash: h(4),
        state: "prepared".into(),
        ack: None,
        recipient_ref: Some(vec![1; 8]),
        revoked_ref: None,
        created_at: 1,
    };
    field_err(&decode_head(&head), "publisher_ref");
    head.publisher_ref = ref_bytes("dev-a")?;
    head.candidate = vec![1; HEAD_ROW_MAX + 1];
    field_err(&decode_head(&head), "candidate");
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
