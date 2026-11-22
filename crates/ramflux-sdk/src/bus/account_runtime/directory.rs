// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Writer-only preparation and conditional application of public directory responses.

use super::AccountRuntime;
use crate::bus::couriers::directory::{BackfillKind, BackfillPlan, DirectoryWork, SafetyPlan};
use crate::{SdkError, time::now_unix_timestamp};

impl AccountRuntime {
    pub(super) async fn apply_directory_pausing(
        &mut self,
        mut work: DirectoryWork,
    ) -> Result<(), SdkError> {
        loop {
            ramflux_storage::writer_budget::begin_attempt();
            let saved = {
                let _scope = ramflux_storage::writer_budget::PauseScope::enter();
                match self.apply_directory_work(work) {
                    Err(SdkError::WriterPause) => {
                        let Some(saved) = crate::bus::couriers::directory::take_paused() else {
                            tracing::warn!(
                                account_id = %self.id,
                                "directory writer pause dropped an unstashed attempt"
                            );
                            return Ok(());
                        };
                        saved
                    }
                    other => return other,
                }
            };
            work = saved;
            self.service_waiting_commands().await?;
        }
    }

    fn apply_directory_work(&mut self, work: DirectoryWork) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(());
        };
        let Some(connection) = account.connection.as_ref() else {
            return Ok(());
        };
        let generation = connection.generation();
        match work {
            DirectoryWork::HeadRefresh(work) => {
                crate::bus::couriers::head_refresh::apply_work(account, work)?;
            }
            DirectoryWork::PrepareBackfill { generation: requested, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                match prepare_backfill(account) {
                    Err(error @ SdkError::WriterPause) => {
                        return Err(stash_if_pause(
                            DirectoryWork::PrepareBackfill { generation: requested, reply },
                            error,
                        ));
                    }
                    result => {
                        let _ = reply.send(result);
                    }
                }
            }
            DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply } => {
                apply_backfill(account, generation, requested, plan, outcome, reply)?;
            }
            DirectoryWork::PrepareSafety { generation: requested, root, reply } => {
                if requested != generation || reply.is_closed() {
                    return Ok(());
                }
                match prepare_safety(account, root.clone()) {
                    Err(error @ SdkError::WriterPause) => {
                        return Err(stash_if_pause(
                            DirectoryWork::PrepareSafety { generation: requested, root, reply },
                            error,
                        ));
                    }
                    result => {
                        let _ = reply.send(result);
                    }
                }
            }
            work @ DirectoryWork::ApplySafety { .. } => {
                apply_safety(account, generation, work)?;
            }
        }
        Ok(())
    }
}

fn stash_if_pause(work: DirectoryWork, error: SdkError) -> SdkError {
    if matches!(error, SdkError::WriterPause) {
        crate::bus::couriers::directory::stash_paused(work);
    }
    error
}

fn load_checkpoint(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
) -> Result<serde_json::Value, SdkError> {
    Ok(account
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(key)?
        .unwrap_or(serde_json::Value::Null))
}

fn apply_backfill(
    account: &mut crate::bus::state::LocalBusAccountState,
    generation: u64,
    requested: u64,
    plan: Box<BackfillPlan>,
    outcome: Result<crate::SdkDeviceManifestResponse, SdkError>,
    reply: tokio::sync::oneshot::Sender<Result<(), SdkError>>,
) -> Result<(), SdkError> {
    if requested != generation || reply.is_closed() {
        return Ok(());
    }
    let current = match load_checkpoint(account, plan.checkpoint_key) {
        Ok(current) => current,
        Err(error) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply },
                error,
            ));
        }
    };
    let links = match account.client.friend_links() {
        Ok(links) => links,
        Err(error) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply },
                error,
            ));
        }
    };
    let accepted = matches!(plan.kind, BackfillKind::Own)
        || links.iter().any(|link| {
            link.state == "accepted"
                && (link.requester_id == plan.root || link.target_id == plan.root)
        });
    if current != plan.checkpoint || !accepted {
        let _ = reply.send(Err(crate::ContactReason::UnknownPrincipal.into()));
        return Ok(());
    }
    match plan.kind {
        BackfillKind::Own => finish_own_backfill(account, requested, plan, outcome, reply),
        BackfillKind::Peer => finish_peer_backfill(account, requested, plan, outcome, reply),
    }
}

fn finish_own_backfill(
    account: &mut crate::bus::state::LocalBusAccountState,
    requested: u64,
    plan: Box<BackfillPlan>,
    outcome: Result<crate::SdkDeviceManifestResponse, SdkError>,
    reply: tokio::sync::oneshot::Sender<Result<(), SdkError>>,
) -> Result<(), SdkError> {
    let manifest = match outcome {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = reply.send(Err(error));
            return Ok(());
        }
    };
    // The clone is the attempt. The original stays so a pause can retry this apply.
    match account.client.accept_fetched_device_manifest(
        manifest.clone(),
        &plan.root,
        "own-contact-backfill",
    ) {
        Err(error @ SdkError::WriterPause) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplyBackfill {
                    generation: requested,
                    plan,
                    outcome: Ok(manifest),
                    reply,
                },
                error,
            ));
        }
        Err(error) => {
            let _ = reply.send(Err(error));
            return Ok(());
        }
        Ok(_) => {}
    }
    reply_staged(account, requested, plan, Ok(manifest), reply)
}

fn finish_peer_backfill(
    account: &mut crate::bus::state::LocalBusAccountState,
    requested: u64,
    plan: Box<BackfillPlan>,
    outcome: Result<crate::SdkDeviceManifestResponse, SdkError>,
    reply: tokio::sync::oneshot::Sender<Result<(), SdkError>>,
) -> Result<(), SdkError> {
    if let Ok(manifest) = &outcome {
        match account.client.accept_fetched_device_manifest(
            manifest.clone(),
            &plan.root,
            "own-contact-peer-backfill",
        ) {
            Err(error @ SdkError::WriterPause) => {
                return Err(stash_if_pause(
                    DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply },
                    error,
                ));
            }
            Err(error) => {
                tracing::debug!(%error, "peer backfill refresh deferred; using verified local material");
            }
            Ok(_) => {}
        }
    } else if let Err(error) = &outcome {
        tracing::debug!(%error, "peer backfill refresh deferred; using verified local material");
    }
    reply_staged(account, requested, plan, outcome, reply)
}

fn reply_staged(
    account: &mut crate::bus::state::LocalBusAccountState,
    requested: u64,
    plan: Box<BackfillPlan>,
    outcome: Result<crate::SdkDeviceManifestResponse, SdkError>,
    reply: tokio::sync::oneshot::Sender<Result<(), SdkError>>,
) -> Result<(), SdkError> {
    match account.client.stage_contact_backfill_batch() {
        Err(error @ SdkError::WriterPause) => Err(stash_if_pause(
            DirectoryWork::ApplyBackfill { generation: requested, plan, outcome, reply },
            error,
        )),
        other => {
            let _ = reply.send(other.map(|_| ()));
            Ok(())
        }
    }
}

fn apply_safety(
    account: &mut crate::bus::state::LocalBusAccountState,
    generation: u64,
    work: DirectoryWork,
) -> Result<(), SdkError> {
    let DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply } = work else {
        return Ok(());
    };
    if requested != generation || reply.is_closed() {
        return Ok(());
    }
    let links = match account.client.friend_links() {
        Ok(links) => links,
        Err(error) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply },
                error,
            ));
        }
    };
    // A removal while the task was fetching cannot resurrect a contact cache.
    let accepted = links.iter().any(|link| {
        link.state == "accepted"
            && (link.requester_id == plan.peer || link.target_id == plan.peer)
            && serde_json::to_value(link).ok().as_ref() == Some(&plan.link)
    });
    if !accepted {
        let _ = reply.send(Err(crate::ContactReason::UnknownPrincipal.into()));
        return Ok(());
    }
    let own_root = plan.own.clone();
    let peer_root = plan.peer.clone();
    // Clones are this attempt. The originals stay so a pause can retry the same apply.
    let own_attempt = (*own).clone();
    let peer_attempt = peer.clone();
    match account.client.accept_fetched_device_manifest(
        own_attempt,
        &own_root,
        "contact.safety_number",
    ) {
        Err(error @ SdkError::WriterPause) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply },
                error,
            ));
        }
        Err(error) => {
            let _ = reply.send(Err(error));
            return Ok(());
        }
        Ok(_) => {}
    }
    match account.client.accept_fetched_device_manifest(
        peer_attempt,
        &peer_root,
        "contact.safety_number",
    ) {
        Err(error @ SdkError::WriterPause) => {
            return Err(stash_if_pause(
                DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply },
                error,
            ));
        }
        Err(error) => {
            let _ = reply.send(Err(error));
            return Ok(());
        }
        Ok(_) => {}
    }
    match account.client.contact_safety_number(&peer_root) {
        Err(error @ SdkError::WriterPause) => Err(stash_if_pause(
            DirectoryWork::ApplySafety { generation: requested, plan, own, peer, reply },
            error,
        )),
        other => {
            let _ = reply.send(other.map(|_| ()));
            Ok(())
        }
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
