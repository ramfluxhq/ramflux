// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact profile reads through a fresh centre decision and the real terminal home's transport.
use super::{
    Result, directory, error, home::HomeService, refuse, rpc, source::Sources, tcp, tls, wire,
};
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::{home_migration::ResolveResult, username_directory as w};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PROFILE_PATH: &str = "/v1/usernames/profile";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    resolve: w::DirectoryResolve,
    binding: w::UsernameBinding,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FetchReply {
    Profile { view: Box<directory::HomeProfileView>, history: Box<ResolveResult>, nonce: String },
    Refused { failure: w::DirectoryFailure },
}

#[derive(Default)]
pub(super) struct HandlerBudgets(Mutex<BTreeMap<String, usize>>);
pub(super) struct HandlerPermit {
    owner: Arc<HandlerBudgets>,
    root: String,
}

impl HandlerBudgets {
    pub fn acquire(self: &Arc<Self>, root: &str) -> Result<HandlerPermit> {
        let mut rows = self.0.lock().map_err(|_| error("username handlers unavailable"))?;
        if rows.values().sum::<usize>() >= 64 || rows.get(root).copied().unwrap_or(0) >= 4 {
            return refuse("username handler capacity");
        }
        *rows.entry(root.into()).or_default() += 1;
        Ok(HandlerPermit { owner: Arc::clone(self), root: root.into() })
    }
}
impl Drop for HandlerPermit {
    fn drop(&mut self) {
        if let Ok(mut rows) = self.owner.0.lock()
            && let Some(count) = rows.get_mut(&self.root)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                rows.remove(&self.root);
            }
        }
    }
}

fn check_resolution(
    pin: &directory::CenterPin,
    resolve: &w::DirectoryResolve,
    binding: &w::UsernameBinding,
    nonce: &str,
    master: &str,
) -> Result<()> {
    let now = crate::now_unix_seconds()?;
    let center = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)?;
    crypto::verify_resolve(&center, &pin.id, resolve)?;
    let key = ramflux_crypto::verifying_key_from_base64url(master)?;
    crypto::verify_binding(&key, binding)?;
    if resolve.body.request_nonce != nonce
        || resolve.body.issued_at > now
        || now >= resolve.body.expires_at
        || resolve
            .body
            .expires_at
            .checked_sub(resolve.body.issued_at)
            .is_none_or(|n| n == 0 || n > 60)
        || resolve.body.name != binding.body.name
        || resolve.body.node != binding.body.node
        || resolve.body.epoch != binding.body.epoch
        || resolve.body.principal_commitment != binding.body.principal_commitment
        || resolve.body.binding_hash != crypto::binding_hash(binding)?
        || ramflux_crypto::identity_root_commitment(&key) != resolve.body.principal_commitment
    {
        return refuse("username resolution tuple mismatch");
    }
    Ok(())
}

impl HomeService {
    pub(super) fn resolve(
        &self,
        reporter: &str,
        name: &str,
        nonce: &str,
    ) -> Result<w::NativeUsernameReply> {
        let response = self.client.exchange_blocking(
            reporter,
            directory::DirectoryRequest::Resolve { name: name.into(), nonce: nonce.into() },
        )?;
        let directory::AuthorityResponse::Resolved { resolve, binding, master_public_key, service } =
            response
        else {
            return match response {
                directory::AuthorityResponse::Refused { failure } => {
                    Ok(w::NativeUsernameReply::Refused { failure })
                }
                _ => refuse("username lookup response mismatch"),
            };
        };
        check_resolution(&self.client.pin, &resolve, &binding, nonce, &master_public_key)?;
        if resolve.body.name != name || resolve.body.node != service.body.node {
            return refuse("username lookup substitution");
        }
        let request = FetchRequest {
            resolve: *resolve.clone(),
            binding: *binding.clone(),
            nonce: nonce.into(),
        };
        let fetched: FetchReply =
            rpc::home(&self.client.node, &service, &self.private, PROFILE_PATH, &request)?;
        let FetchReply::Profile { view, history, nonce: echoed } = fetched else {
            let FetchReply::Refused { failure } = fetched else {
                return refuse("username profile response");
            };
            return Ok(w::NativeUsernameReply::Refused { failure });
        };
        if echoed != nonce {
            return refuse("username profile nonce mismatch");
        }
        let first = history.predecessors.first().unwrap_or(&history.home);
        if !matches!(first.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. }) {
            return refuse("username profile genesis missing");
        }
        let verified = ramflux_crypto::home_migration::verify_home_chain(
            &history,
            first,
            crate::now_unix_seconds()?,
        )?;
        if verified.home() != (resolve.body.node.as_str(), service.body.public_key.as_str())
            || verified.evidence().record.account_anchor() != resolve.body.principal_commitment
            || history.home.authority.record.body.master_certificate.body.master_public_key
                != master_public_key
        {
            return refuse("username profile home evidence mismatch");
        }
        let master = ramflux_crypto::verifying_key_from_base64url(&master_public_key)?;
        crypto::verify_profile(&master, &view.profile)?;
        crypto::verify_operation(&master, &view.operation)?;
        let native = &history.home.authority.record.body;
        if view.profile.body.principal_id != native.principal_id
            || view.profile.body.kind != w::ProfileKind::from_principal_kind(native.principal_kind)
        {
            return refuse("username native profile classification mismatch");
        }
        let center = ramflux_crypto::verifying_key_from_base64url(&self.client.pin.public_key)?;
        crypto::verify_receipt(&center, &self.client.pin.id, &view.receipt)?;
        let now = crate::now_unix_seconds()?;
        if view.binding.as_ref() != Some(binding.as_ref())
            || view.operation.body.binding != view.binding
            || view.operation.body.profile != resolve.body.profile
            || view.operation.body.operation_id != view.receipt.body.operation_id
            || crypto::operation_hash(&view.operation)? != view.receipt.body.operation_hash
            || view.receipt.body.state != w::ReceiptState::Committed
            || view.profile.body.avatar.is_some()
            || view.profile.body.principal_commitment != resolve.body.principal_commitment
            || view.receipt.body.principal_commitment != resolve.body.principal_commitment
            || view.receipt.body.epoch != resolve.body.epoch
            || view.receipt.body.binding_hash.as_ref() != Some(&resolve.body.binding_hash)
            || view.receipt.body.profile != resolve.body.profile
            || !view.receipt.body.discoverable
            || view.receipt.body.committed_at > now
            || now >= view.receipt.body.expires_at
            || view.receipt.body.expires_at
                > now.checked_add(60).ok_or_else(|| error("username clock"))?
            || resolve.body.profile.hash.as_ref() != Some(&crypto::profile_hash_v2(&view.profile)?)
        {
            return refuse("username profile bytes are not current resolution");
        }
        Ok(w::NativeUsernameReply::Resolved {
            operation: Box::new(view.operation),
            resolve,
            binding,
            profile: Box::new(view.profile),
            receipt: Box::new(view.receipt),
            history,
            nonce: echoed,
        })
    }

    fn publication(
        &self,
        request: FetchRequest,
        channel: &str,
    ) -> Result<directory::HomePublication> {
        let root = &request.resolve.body.principal_commitment;
        let history = self.client.history(root)?;
        let master_public =
            &history.home.authority.record.body.master_certificate.body.master_public_key;
        check_resolution(
            &self.client.pin,
            &request.resolve,
            &request.binding,
            &request.nonce,
            master_public,
        )?;
        if request.resolve.body.node != self.client.discovery.node_id {
            return refuse("profile is not on this home");
        }
        let master = ramflux_crypto::verifying_key_from_base64url(master_public)?;
        let live = self.client.revalidate(&self.directory, root, None)?;
        Ok(self.directory.prepare_publication(root, live, &master, crate::now_unix_seconds()?, channel, |view| {
            if view.binding.as_ref() != Some(&request.binding) || view.receipt.body.profile != request.resolve.body.profile {
                return Err(directory::CheckpointError::Directory(w::DirectoryCode::StaleEpoch));
            }
            let reply = FetchReply::Profile { view: Box::new(view.clone()), history: Box::new(history), nonce: request.nonce };
            let body = ramflux_protocol::canonical_json_bytes(&reply).map_err(|_| directory::CheckpointError::Refused("home_response_encoding"))?;
            let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len()).into_bytes();
            bytes.extend(body); Ok(bytes)
        })?)
    }
}

pub(super) fn listen(home: Arc<HomeService>) -> Result<()> {
    let listener = TcpListener::bind(home.client.service.listen)?;
    listener.set_nonblocking(true)?;
    let tls = Arc::new(tls::server(&home.client.node)?);
    let sources = Sources::new();
    ramflux_node_core::spawn_service_worker("username-home-http", move |shutdown| {
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
        while !shutdown.is_cancelled() {
            workers.retain(|worker| !worker.is_finished());
            match listener.accept() {
                Ok((socket, address)) if workers.len() < 16 && sources.admit(address.ip()) => {
                    let tls = Arc::clone(&tls);
                    let owner = Arc::clone(&home);
                    let spawned = std::thread::Builder::new()
                        .name("username-home-profile".into())
                        .spawn(move || {
                            let result = (|| -> Result<()> {
                                let mut incoming = owner.client.secret.with_bytes(|seed| {
                                    tcp::accept(socket, tls, &owner.client.discovery.node_id, seed)
                                })?;
                                if incoming.path != PROFILE_PATH || incoming.body.len() > 8192 {
                                    return refuse("username profile request bound");
                                }
                                let request: FetchRequest = wire::decode(&incoming.body)?;
                                let _permit = owner
                                    .budgets
                                    .acquire(&request.resolve.body.principal_commitment)?;
                                let channel = ramflux_protocol::encode_base64url(incoming.exporter);
                                let mut call = owner.publication(request, &channel)?;
                                loop {
                                    if Instant::now() >= incoming.deadline {
                                        return refuse("username profile deadline");
                                    }
                                    if owner.directory.write_publication_step(
                                        &mut call,
                                        &channel,
                                        crate::now_unix_seconds()?,
                                        |bytes| incoming.try_write(bytes),
                                    )? {
                                        return Ok(());
                                    }
                                    if !ramflux_node_core::service_shutdown_sleep(
                                        Duration::from_millis(5),
                                    ) {
                                        return refuse("username profile shutdown");
                                    }
                                }
                            })();
                            if let Err(error) = result {
                                tracing::debug!(%error, "username home profile connection closed");
                            }
                        });
                    match spawned {
                        Ok(worker) => workers.push(worker),
                        Err(error) => tracing::warn!(%error, "username profile worker unavailable"),
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    tracing::error!(%error, "username home listener stopped");
                    break;
                }
            }
            if !ramflux_node_core::service_shutdown_sleep(Duration::from_millis(5)) {
                break;
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
    })?;
    Ok(())
}
