// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A node block retires its adopted peers' positive grants inside the same account writer.
use super::*;
use ramflux_protocol::contact_reach::StateRecord;
use std::collections::BTreeSet;

pub(super) fn retire_node_grants(
    tx: &redb::WriteTransaction,
    state: &mut AccountReach,
    recipient: &str,
    update: &custody::Envelope<Admission>,
) -> Result<()> {
    let Subject::Node { node_id } = &update.body.subject else { return Ok(()) };
    if update.body.decision != Decision::Block {
        return Ok(());
    }
    let prefix = format!("[{},", serde_json::to_string(recipient).map_err(storage)?);
    let table = tx.open_table(TRUST).map_err(storage)?;
    let mut roots = BTreeSet::new();
    for entry in table.range(prefix.as_str()..).map_err(storage)?.take(1025) {
        let (key, bytes) = entry.map_err(storage)?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        let peer: AdoptedPeer = row(bytes.value())?;
        if peer.home.record.home().0 == node_id {
            let (owner, root): (String, String) =
                serde_json::from_str(key.value()).map_err(storage)?;
            if owner != recipient {
                return Err(storage("adopted peer account index mismatch"));
            }
            roots.insert(root);
        }
    }
    state.grants.retain(|_, record| {
        !matches!(record, StateRecord::Grant { subject, .. }
            if subject.root().is_some_and(|root| roots.contains(root)))
    });
    for root in roots {
        let id = ramflux_protocol::message::dm_scope::derive(recipient, &root)
            .map_err(|_| refuse(Reason::ReachRouteInvalid))?;
        // Placement carries only positive presentation. Its absence cannot clear the node floor.
        state.placements.remove(&id);
    }
    Ok(())
}
