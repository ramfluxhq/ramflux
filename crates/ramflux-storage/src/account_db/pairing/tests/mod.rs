// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P04 closed schema, decoder bounds, migration and backup classification.
mod backup;
mod codec;
mod crash;
mod full_reference;
mod helpers;
mod schema;

#[test]
fn pairing_journal_crash_fences_and_backup_exclusion() -> Result<(), Box<dyn std::error::Error>> {
    crash::missing_writers_named();
    crash::j1_before_and_after_floor_live()?;
    crash::j2_live_phase_cancels_without_head()?;
    crash::post_candidate_live_without_head_fails_closed()?;
    crash::expired_live_without_head_keeps_expired_outcome()?;
    crash::j3_prepared_head_fences_same_hash()?;
    crash::j4_submitted_never_cancelled()?;
    crash::j6_acknowledged_same_hash()?;
    crash::j7c_adoption_stays_fenced()?;
    crash::j8_terminal_cleanup_deletes_head()?;
    crash::j8_refuses_cancelled_and_hash_mismatch()?;
    crash::j8_headless_cleanup_keeps_published_terminal()?;
    crash::j8_headless_post_candidate_live_refuses_cancel()?;
    crash::j8_headless_completed_without_adoption_is_refused()?;
    crash::j8_matching_hash_without_adoption_is_refused()?;
    crash::prepared_head_clears_on_cancel()?;
    crash::backup_mid_ceremony_strips_live_keeps_floor()?;
    crash::recover_does_not_change_candidate()?;
    Ok(())
}

#[test]
fn pairing_journal_schema_and_indexes_are_closed() -> Result<(), Box<dyn std::error::Error>> {
    schema::tables_and_indexes()?;
    schema::old_open_creates_tables()?;
    schema::caps_and_sql_bounds()?;
    codec::live_submitted_candidate_state()?;
    codec::row_field_and_size_bounds()?;
    codec::adoption_role_arms()?;
    codec::live_binds_descriptor_ids()?;
    codec::head_binds_candidate_hash_and_ack()?;
    codec::head_candidate_is_immutable()?;
    codec::head_one_account_forward_only()?;
    codec::put_refuses_foreign_account_and_anchor()?;
    codec::floor_decrease_exact_errors()?;
    codec::bounds_id_u_and_row_sizes()?;
    codec::terminal_ttl_and_cap()?;
    codec::live_cap_exact_error()?;
    backup::live_rows_are_stripped_floors_survive()?;
    backup::skip_merge_and_floor_maxima()?;
    backup::floor_merge_binds_local_account()?;
    Ok(())
}

mod full_adoption;
