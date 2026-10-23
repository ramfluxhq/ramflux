// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only structural work counters; no timing threshold or production instrumentation.
use std::cell::Cell;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Work {
    pub snapshots: usize,
    pub canonical: usize,
    pub visits: usize,
    pub ops: usize,
}
thread_local! {static WORK:Cell<Work>=const {Cell::new(Work{snapshots:0,canonical:0,visits:0,ops:0})};}
pub(super) fn reset() {
    WORK.set(Work::default());
}
pub(super) fn read() -> Work {
    WORK.get()
}
pub(super) fn snapshot() {
    WORK.update(|mut w| {
        w.snapshots += 1;
        w
    });
}
pub(super) fn canonical() {
    WORK.update(|mut w| {
        w.canonical += 1;
        w
    });
}
pub(super) fn visit() {
    WORK.update(|mut w| {
        w.visits += 1;
        w
    });
}
pub(super) fn operation() {
    WORK.update(|mut w| {
        w.ops += 1;
        w
    });
}

#[cfg(test)]
mod tests {
    use super::{read, reset};
    use crate::{
        A2UI_CONVERSATION_SCHEMA, A2uiConversationEvent, CreateSurfaceCommand, SurfaceState,
        SurfaceType, canonical_json_bytes, surface_snapshot_hash,
    };
    use serde_json::json;
    #[test]
    fn sixty_four_op_work_is_linear() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = CreateSurfaceCommand {
            surface_id: "s".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "f".repeat(1000),
            fallback_markdown: None,
            components: (0..32)
                .map(|i| json!({"id":format!("c{i}"),"text":"t".repeat(1000)}))
                .collect(),
            data_model: serde_json::Map::default(),
            allowed_actions: (0..16)
                .map(|i| json!({"name":format!("a{i}"),"label":"a".repeat(1000)}))
                .collect(),
        };
        let bytes = canonical_json_bytes(&snapshot)?.len();
        assert!((45_000..65_537).contains(&bytes));
        let create = json!({"schema":A2UI_CONVERSATION_SCHEMA,"conversationId":"c","version":1,"command":{"command":"createSurface","surfaceId":snapshot.surface_id,"surfaceType":snapshot.surface_type,"catalog":snapshot.catalog,"catalogVersion":snapshot.catalog_version,"fallbackText":snapshot.fallback_text,"components":snapshot.components,"allowedActions":snapshot.allowed_actions}});
        let state = SurfaceState::default()
            .apply(&A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&create)?)?)?;
        let hash = surface_snapshot_hash(&snapshot)?;
        let make = |count: usize| -> Result<A2uiConversationEvent, Box<dyn std::error::Error>> {
            let ops = vec![json!({"op":"set_actions","actions":snapshot.allowed_actions}); count];
            let wire = json!({"schema":A2UI_CONVERSATION_SCHEMA,"conversationId":"c","version":2,"command":{"command":"patchSurface","surfaceId":"s","baseSurfaceHash":hash,"newSurfaceHash":hash,"ops":ops}});
            Ok(A2uiConversationEvent::from_wire_bytes(&serde_json::to_vec(&wire)?)?)
        };
        let small = make(1)?;
        let batch = make(64)?;
        reset();
        state.apply(&small)?;
        let one = read();
        reset();
        let start = std::time::Instant::now();
        let next = state.apply(&batch)?;
        let elapsed = start.elapsed();
        let many = read();
        assert_eq!(one.snapshots, 1);
        assert_eq!(many.snapshots, 1);
        assert_eq!(one.canonical, 1);
        assert_eq!(many.canonical, 1);
        assert_eq!(many.visits, one.visits);
        assert!(many.visits < 1000);
        assert_eq!(one.ops, 1);
        assert_eq!(many.ops, 64);
        assert_eq!(next.content(), state.content());
        eprintln!(
            "64-op apply: snapshot_bytes={bytes}, snapshots={}, canonicalizations={}, visited_nodes={}, operations={}, elapsed_us={} (diagnostic only)",
            many.snapshots,
            many.canonical,
            many.visits,
            many.ops,
            elapsed.as_micros()
        );
        Ok(())
    }
}
