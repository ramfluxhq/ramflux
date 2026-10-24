// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Trusted local reduction checkpoints; these are never a peer or own-device ingress format.
use super::{TaskHistory, invalid};
use crate::SdkError;
use ramflux_protocol::{NeedsMe, TaskState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Checkpoint {
    pub state: TaskState,
    pub openings: BTreeMap<String, (String, u64, NeedsMe)>,
    pub certificate_hashes: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
impl TaskHistory {
    pub(super) fn certificate_hashes(&self) -> Result<Vec<String>, SdkError> {
        let mut hashes =
            self.checkpoint.as_ref().map_or_else(std::collections::BTreeSet::new, |c| {
                c.certificate_hashes.iter().cloned().collect()
            });
        for proof in self.events.iter().filter_map(|e| e.decision_certificate.as_ref()) {
            hashes.insert(ramflux_protocol::hash_base64url(
                "ramflux.task.archived_certificate.v1",
                &serde_json::to_vec(proof)?,
            ));
        }
        Ok(hashes.into_iter().collect())
    }
    pub(super) fn local_checkpoint(&self) -> Result<Checkpoint, SdkError> {
        let state = self.state()?;
        let task = state.task().ok_or_else(|| invalid("cannot checkpoint an absent task"))?;
        let mut openings = BTreeMap::new();
        for step in &task.steps {
            if let Some(target) = &step.needs_me {
                let (device, revision) = self.intervention_source(&step.id, target)?;
                openings.insert(step.id.clone(), (device, revision, target.clone()));
            }
        }
        Ok(Checkpoint {
            state,
            openings,
            certificate_hashes: self.certificate_hashes()?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
