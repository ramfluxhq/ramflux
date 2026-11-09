// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P04 closed schema, decoder bounds, migration and backup classification.
mod backup;
mod codec;
mod helpers;
mod schema;

#[test]
fn pairing_journal_schema_and_indexes_are_closed() -> Result<(), Box<dyn std::error::Error>> {
    schema::tables_and_indexes()?;
    schema::old_open_creates_tables()?;
    schema::caps_and_sql_bounds()?;
    codec::live_submitted_candidate_state()?;
    codec::row_field_and_size_bounds()?;
    codec::adoption_role_arms()?;
    backup::live_rows_are_stripped_floors_survive()?;
    backup::skip_merge_and_floor_maxima()?;
    Ok(())
}
