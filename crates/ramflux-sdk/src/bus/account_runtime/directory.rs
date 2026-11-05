// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Writer-only preparation and conditional application of public directory responses.

use super::AccountRuntime;
use crate::bus::couriers::directory::{BackfillKind, BackfillPlan, DirectoryWork, SafetyPlan};
use crate::{SdkError, time::now_unix_timestamp};

impl AccountRuntime {
    pub(super) fn apply_directory_work(&mut self, work: DirectoryWork) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(());
        };
        let Some(connection) = account.connection.as_ref() else {
            return Ok(());
        };
        let generation = connection.generation();
        match work {
            DirectoryWork::HeadRefresh(work) => {
                crate::bus::couriers::head_refresh::apply_work(account, work);
            }
            DirectoryWork::PrepareBackfill { generation: requested, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                let result = prepare_backfill(account);
                let _ = reply.send(result);
            }
            DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                let current = account
                    .client
                    .account_db()?
                    .load_actor_state::<serde_json::Value>(plan.checkpoint_key)?
                    .unwrap_or(serde_json::Value::Null);
                let accepted = matches!(plan.kind, BackfillKind::Own)
                    || account.client.friend_links()?.iter().any(|link| {
                        link.state == "accepted"
                            && (link.requester_id == plan.root || link.target_id == plan.root)
                    });
                if current != plan.checkpoint || !accepted {
                    let _ = reply.send(Err(crate::ContactReason::UnknownPrincipal.into()));
                    return Ok(());
                }
                let source = match plan.kind {
                    BackfillKind::Own => "own-contact-backfill",
                    BackfillKind::Peer => "own-contact-peer-backfill",
                };
                let result = outcome.and_then(|manifest| {
                    account
                        .client
                        .accept_fetched_device_manifest(manifest, &plan.root, source)
                        .map(|_| ())
                });
                // Peer refresh failure still permits staging from already-verified local data.
                let result = match result {
                    Err(error) if matches!(plan.kind, BackfillKind::Own) => Err(error),
                    result => {
                        if let Err(error) = result {
                            tracing::debug!(%error, "peer backfill refresh deferred; using verified local material");
                        }
                        account.client.stage_contact_backfill_batch().map(|_| ())
                    }
                };
                let _ = reply.send(result);
            }
            DirectoryWork::PrepareSafety { generation: requested, root, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                let result = prepare_safety(account, root);
                let _ = reply.send(result);
            }
            DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                // A removal while the task was fetching cannot resurrect a contact cache.
                let accepted = account.client.friend_links()?.iter().any(|link| {
                    link.state == "accepted"
                        && (link.requester_id == plan.peer || link.target_id == plan.peer)
                        && serde_json::to_value(link).ok().as_ref() == Some(&plan.link)
                });
                let result = if accepted {
                    account
                        .client
                        .accept_fetched_device_manifest(*own, &plan.own, "contact.safety_number")
                        .and_then(|_| {
                            account.client.accept_fetched_device_manifest(
                                peer,
                                &plan.peer,
                                "contact.safety_number",
                            )
                        })
                        .and_then(|_| account.client.contact_safety_number(&plan.peer))
                        .map(|_| ())
                } else {
                    Err(crate::ContactReason::UnknownPrincipal.into())
                };
                let _ = reply.send(result);
            }
        }
        Ok(())
    }
}

fn prepare_backfill(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<Option<BackfillPlan>, SdkError> {
    let client = &account.client;
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    let last = db.load_actor_state::<i64>("own-contact/last-refresh")?.unwrap_or(0);
    let (kind, root) = if now.saturating_sub(last) >= 5 {
        db.persist_actor_state("own-contact/last-refresh", &now)?;
        (BackfillKind::Own, client.owned_device_identity()?.root_commitment().to_owned())
    } else if let Some(root) = client.claim_contact_backfill_refresh(now)? {
        (BackfillKind::Peer, root)
    } else {
        client.stage_contact_backfill_batch()?;
        return Ok(None);
    };
    let checkpoint_key = match kind {
        BackfillKind::Own => "own-contact/last-refresh",
        BackfillKind::Peer => "own-contact/backfill",
    };
    let checkpoint = db
        .load_actor_state::<serde_json::Value>(checkpoint_key)?
        .unwrap_or(serde_json::Value::Null);
    Ok(Some(BackfillPlan {
        kind,
        root,
        config: account.gateway_config.clone(),
        checkpoint_key,
        checkpoint,
    }))
}

fn prepare_safety(
    account: &crate::bus::state::LocalBusAccountState,
    root: String,
) -> Result<Option<SafetyPlan>, SdkError> {
    account.client.friend_links().and_then(|links| {
        links
            .into_iter()
            .find(|link| {
                link.state == "accepted" && (link.requester_id == root || link.target_id == root)
            })
            .map(|link| {
                Ok(SafetyPlan {
                    link: serde_json::to_value(&link)?,
                    own: if link.requester_id == root { link.target_id } else { link.requester_id },
                    peer: root,
                    config: account.gateway_config.clone(),
                })
            })
            .transpose()
    })
}
