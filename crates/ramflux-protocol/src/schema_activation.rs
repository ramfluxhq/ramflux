// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preconditions of the message schema v1 activation.
//!
//! The storage generation may leave zero only in the change that also attests every row below.
//! The crate fails to compile when the generation is flipped while a row is still unmet, and
//! source-tree tests in the SDK refuse an attestation that the tree contradicts.

use crate::schema_profile::{ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION};

/// One activation precondition and its attested state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Precondition {
    pub name: &'static str,
    pub met: bool,
}

/// Native control executors cover every generated control arm; no pending fallthrough remains.
pub const NATIVE_CONTROLS_COMPLETE: &str = "native_controls_complete";
/// History producer/courier and native sibling transport deliver end to end.
pub const HISTORY_TRANSPORT_COMPLETE: &str = "history_transport_complete";
/// Restore merges edited winners, erasures, openings, counters and floors.
pub const RESTORE_MERGE_COMPLETE: &str = "restore_merge_complete";
/// `SelfSync` refresh barrier, floor bootstrap and delivery lifecycle are complete.
pub const SELF_SYNC_COMPLETE: &str = "self_sync_complete";
/// Typed runtime, durable read model and lag signalling are integrated.
pub const TYPED_RUNTIME_COMPLETE: &str = "typed_runtime_complete";
/// Generation-zero codecs and their selection branches are deleted.
pub const LEGACY_CODEC_REMOVED: &str = "legacy_codec_removed";
/// The raw Inner wire and the schema-profile reset are installed for existing stores.
pub const RAW_WIRE_RESET_INSTALLED: &str = "raw_wire_reset_installed";
/// The real router and gateway module gate passed on the activation tree.
pub const REAL_COMPONENT_GATE_GREEN: &str = "real_component_gate_green";
/// The tampered committed-binding gate passed on the activation tree.
pub const TAMPERED_BINDING_GATE_GREEN: &str = "tampered_binding_gate_green";
/// The lane gates printed their aggregate success line on the activation tree.
pub const LANE_GATES_GREEN: &str = "lane_gates_green";

/// Every row must be `met: true` in the same change that flips the generation.
pub const PRECONDITIONS: [Precondition; 10] = [
    Precondition { name: NATIVE_CONTROLS_COMPLETE, met: false },
    Precondition { name: HISTORY_TRANSPORT_COMPLETE, met: false },
    Precondition { name: RESTORE_MERGE_COMPLETE, met: false },
    Precondition { name: SELF_SYNC_COMPLETE, met: false },
    Precondition { name: TYPED_RUNTIME_COMPLETE, met: false },
    Precondition { name: LEGACY_CODEC_REMOVED, met: false },
    Precondition { name: RAW_WIRE_RESET_INSTALLED, met: false },
    Precondition { name: REAL_COMPONENT_GATE_GREEN, met: false },
    Precondition { name: TAMPERED_BINDING_GATE_GREEN, met: false },
    Precondition { name: LANE_GATES_GREEN, met: false },
];

/// True when every listed precondition is attested.
#[must_use]
pub const fn all_met(rows: &[Precondition]) -> bool {
    let mut index = 0;
    while index < rows.len() {
        if !rows[index].met {
            return false;
        }
        index += 1;
    }
    true
}

/// Generation zero is always allowed. Schema v1 needs every row; no other generation exists.
#[must_use]
pub const fn activation_allowed(generation: i64, rows: &[Precondition]) -> bool {
    generation == 0 || (generation == MESSAGE_SCHEMA_V1_GENERATION && all_met(rows))
}

/// Attested state of one named precondition; an unknown name is unmet.
#[must_use]
pub fn is_met(name: &str) -> bool {
    PRECONDITIONS.iter().any(|row| row.name == name && row.met)
}

const _: () = assert!(
    activation_allowed(ACTIVE_STORAGE_GENERATION, &PRECONDITIONS),
    "ACTIVE_STORAGE_GENERATION left zero while an activation precondition is unmet; \
     see schema_activation::PRECONDITIONS"
);

#[cfg(test)]
mod tests {
    use super::*;

    const fn rows(met: bool) -> [Precondition; 2] {
        [Precondition { name: "first", met: true }, Precondition { name: "second", met }]
    }

    #[test]
    fn dormant_generation_needs_no_precondition() {
        assert!(activation_allowed(0, &rows(false)));
        assert!(activation_allowed(0, &PRECONDITIONS));
    }

    #[test]
    fn flip_is_refused_while_any_precondition_is_unmet() {
        assert!(!activation_allowed(MESSAGE_SCHEMA_V1_GENERATION, &rows(false)));
        assert!(activation_allowed(MESSAGE_SCHEMA_V1_GENERATION, &rows(true)));
        for missing in 0..PRECONDITIONS.len() {
            let mut attested = PRECONDITIONS;
            for (index, row) in attested.iter_mut().enumerate() {
                row.met = index != missing;
            }
            assert!(
                !activation_allowed(MESSAGE_SCHEMA_V1_GENERATION, &attested),
                "flip allowed without {}",
                PRECONDITIONS.get(missing).map_or("", |row| row.name)
            );
        }
    }

    #[test]
    fn unknown_generations_are_refused_even_when_fully_attested() {
        for generation in [-1, 2, i64::MAX] {
            assert!(!activation_allowed(generation, &rows(true)));
        }
    }

    #[test]
    fn live_generation_matches_the_attested_table() {
        assert!(activation_allowed(ACTIVE_STORAGE_GENERATION, &PRECONDITIONS));
        assert_eq!(
            ACTIVE_STORAGE_GENERATION == MESSAGE_SCHEMA_V1_GENERATION,
            all_met(&PRECONDITIONS) && ACTIVE_STORAGE_GENERATION != 0,
            "attesting every precondition and flipping the generation are one change"
        );
        let mut names = PRECONDITIONS.map(|row| row.name);
        names.sort_unstable();
        assert!(names.windows(2).all(|pair| pair[0] != pair[1]), "duplicate precondition");
        assert!(!is_met("unknown"));
    }
}
