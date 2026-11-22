// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Construct current response documents inside the witness and release only through its fence.
use super::{
    CheckpointError, DirectoryAuthority, DirectoryRequest, Result, ServingCall, WriterIdentity,
    image::ImagePlan,
    transitions::{after, ensure},
};
use ed25519_dalek::SigningKey;
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityResponse {
    Receipt {
        receipt: Box<w::DirectoryReceipt>,
    },
    Resolved {
        resolve: Box<w::DirectoryResolve>,
        binding: Box<w::UsernameBinding>,
        master_public_key: String,
        service: Box<super::SignedHomeServiceAddress>,
    },
    Revalidated {
        result: Box<w::HomeRevalidateResult>,
    },
    Refused {
        failure: w::DirectoryFailure,
    },
}

impl DirectoryAuthority {
    /// An authenticated request is admitted only after the current primary is reconciled.
    /// # Errors
    /// Refuses retired writers, wrong heads and saturated context quotas.
    pub fn admit_call(&mut self, writer: &WriterIdentity, call: ServingCall) -> Result<String> {
        self.fence.admit(writer, &self.head(), call, self.witness.sample_time()?)
    }

    /// Build/sign one response candidate against the same protected image and live call.
    /// Signing key must match the independently provisioned centre pin before this entry point.
    /// # Errors
    /// Refuses wrong callers, stale state, mismatched requests and unavailable/corrupt image data.
    pub fn prepare_response(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        signer: &SigningKey,
    ) -> Result<()> {
        let time = self.witness.sample_time()?;
        self.fence.check_writer(writer, time)?;
        let call = self.fence.call(call_id)?.clone();
        let response = self.build_response(&call, signer, time.wall);
        let response = match response {
            Ok(response) => response,
            Err(CheckpointError::Directory(code)) => {
                AuthorityResponse::Refused { failure: super::failure(code) }
            }
            Err(error) => return Err(error),
        };
        self.queue_response(writer, call_id, channel, response, false)
    }

    /// HTTP framing is part of the same fenced candidate, including its length/status headers.
    /// # Errors
    /// Refuses stale contexts, mismatched channels or oversized final responses.
    pub(crate) fn prepare_http_response(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        signer: &SigningKey,
    ) -> Result<()> {
        let time = self.witness.sample_time()?;
        self.fence.check_writer(writer, time)?;
        let call = self.fence.call(call_id)?.clone();
        let response = match self.build_response(&call, signer, time.wall) {
            Ok(value) => value,
            Err(CheckpointError::Directory(code)) => {
                AuthorityResponse::Refused { failure: super::failure(code) }
            }
            Err(error) => return Err(error),
        };
        self.queue_response(writer, call_id, channel, response, true)
    }

    fn queue_response(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        response: AuthorityResponse,
        http: bool,
    ) -> Result<()> {
        let time = self.witness.sample_time()?;
        let body = super::canonical(&response)?;
        let bytes = if http {
            let status = if let AuthorityResponse::Refused { failure } = &response {
                super::http_status(failure.code)
            } else {
                200
            };
            let mut bytes = format!("HTTP/1.1 {status} Directory\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len()).into_bytes();
            bytes.extend(body);
            bytes
        } else {
            body
        };
        self.fence.queue(writer, &self.head(), call_id, channel, bytes, time)
    }

    /// # Errors
    /// Refuses fencing/clock/transport failures; the caller must reset a partial stream on error.
    pub fn write_response_step(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        try_write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    ) -> Result<bool> {
        self.fence.write_step(
            writer,
            &self.head(),
            call_id,
            channel,
            self.witness.sample_time()?,
            try_write,
        )
    }

    pub fn cancel_call(&mut self, call_id: &str) {
        self.fence.cancel(call_id);
    }

    /// Queue a typed mutation refusal under the same live fence as a successful response.
    /// # Errors
    /// Refuses missing/stale contexts, wrong channels and unavailable clocks.
    pub fn prepare_refusal(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        code: Code,
    ) -> Result<()> {
        let response = AuthorityResponse::Refused { failure: super::failure(code) };
        self.queue_response(writer, call_id, channel, response, false)
    }

    /// # Errors
    /// Refuses stale contexts or oversized framed refusals.
    pub fn prepare_http_refusal(
        &mut self,
        writer: &WriterIdentity,
        call_id: &str,
        channel: &str,
        code: Code,
    ) -> Result<()> {
        self.queue_response(
            writer,
            call_id,
            channel,
            AuthorityResponse::Refused { failure: super::failure(code) },
            true,
        )
    }

    fn build_response(
        &self,
        call: &ServingCall,
        signer: &SigningKey,
        now: u64,
    ) -> Result<AuthorityResponse> {
        let center = self.head().center_id;
        match &call.request {
            DirectoryRequest::Mutate { operation, .. } => {
                ensure(operation.body.principal_commitment == call.root, Code::OwnershipMismatch)?;
                let receipt =
                    self.operation_receipt(&call.root, &operation.body.operation_id, signer, now)?;
                Ok(AuthorityResponse::Receipt { receipt: Box::new(receipt) })
            }
            DirectoryRequest::Status { operation_id } => {
                let receipt = if let Some(operation) = operation_id {
                    self.operation_receipt(&call.root, operation, signer, now)?
                } else {
                    crypto::sign_receipt(signer, &center, self.receipt_body(&call.root, now)?)?
                };
                Ok(AuthorityResponse::Receipt { receipt: Box::new(receipt) })
            }
            DirectoryRequest::Resolve { name, nonce } => {
                let plan = ImagePlan::new(&self.witness.db);
                let index = plan.name(name)?.ok_or(CheckpointError::Directory(Code::NotFound))?;
                ensure(index.state == w::IndexState::Active, Code::NotFound)?;
                let root = plan
                    .root(&index.root)?
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                ensure(self.lookup_allowed(&index.root, &root)?, Code::NotFound)?;
                let binding = root
                    .current_binding
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                ensure(
                    binding.body.name == *name
                        && binding.body.node == root.node
                        && binding.body.epoch == root.epoch
                        && binding.body.principal_commitment == index.root
                        && Some(crypto::binding_hash(&binding)?) == root.binding_hash,
                    Code::DirectoryUnavailable,
                )?;
                let home = self
                    .reporting_floor(&index.root)?
                    .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
                ensure(
                    home.home == root.node && home.service.body.node == root.node,
                    Code::DirectoryUnavailable,
                )?;
                home.service.verify(&root.node, &home.service.body.public_key, now)?;
                let resolve = crypto::sign_resolve(
                    signer,
                    &center,
                    w::DirectoryResolveBody {
                        center_id: center.clone(),
                        name: name.clone(),
                        node: root.node,
                        principal_commitment: index.root,
                        epoch: root.epoch,
                        binding_hash: root
                            .binding_hash
                            .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?,
                        profile: root.profile,
                        request_nonce: nonce.clone(),
                        issued_at: now,
                        expires_at: after(now, 60)?,
                    },
                )?;
                Ok(AuthorityResponse::Resolved {
                    resolve: Box::new(resolve),
                    binding: Box::new(binding),
                    master_public_key: home.master_public_key,
                    service: Box::new(home.service),
                })
            }
            DirectoryRequest::Revalidate { request } => {
                ensure(request.root == call.root, Code::OwnershipMismatch)?;
                let Some(root) = self.current_root(&request.root)? else {
                    ensure(request.known_directory_epoch == 0, Code::StaleEpoch)?;
                    return Ok(AuthorityResponse::Revalidated {
                        result: Box::new(w::HomeRevalidateResult {
                            root: request.root.clone(),
                            nonce: request.nonce.clone(),
                            current_binding: None,
                            current_receipt: None,
                            pending_receipt: None,
                            lookup_allowed: false,
                            issued_at: now,
                            expires_at: after(now, 10)?,
                        }),
                    });
                };
                ensure(root.node == call.home, Code::OwnershipMismatch)?;
                ensure(request.known_directory_epoch <= root.epoch, Code::StaleEpoch)?;
                if let (Some(requested), Some(pending)) =
                    (&request.operation_id, &root.pending_operation_id)
                {
                    ensure(requested == pending, Code::OperationPending)?;
                }
                let lookup_allowed = self.lookup_allowed(&request.root, &root)?;
                let current_receipt = if root.epoch > 0 {
                    Some(crypto::sign_receipt(
                        signer,
                        &center,
                        self.receipt_body(&request.root, now)?,
                    )?)
                } else {
                    None
                };
                let pending_receipt = root
                    .pending_operation_id
                    .as_ref()
                    .map(|id| self.operation_receipt(&request.root, id, signer, now))
                    .transpose()?;
                let result = w::HomeRevalidateResult {
                    root: request.root.clone(),
                    nonce: request.nonce.clone(),
                    current_binding: root.current_binding,
                    current_receipt,
                    pending_receipt,
                    lookup_allowed,
                    issued_at: now,
                    expires_at: after(now, 10)?,
                };
                w::encode(&result)?;
                Ok(AuthorityResponse::Revalidated { result: Box::new(result) })
            }
        }
    }

    pub(super) fn lookup_allowed(&self, root_key: &str, root: &w::RootRow) -> Result<bool> {
        if root.deleted || !root.discoverable || root.name.is_none() {
            return Ok(false);
        }
        if let Some(pending) = &root.pending_operation_id {
            let key = w::OperationKey { root: root_key.into(), operation_id: pending.clone() };
            let row = ImagePlan::new(&self.witness.db)
                .operation(&key)?
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
            ensure(row.state == w::ReceiptState::Reserved, Code::DirectoryUnavailable)?;
            if matches!(
                row.operation.body.action,
                w::Action::Rename | w::Action::Release | w::Action::Delete | w::Action::MoveHome
            ) || row.operation.body.action == w::Action::SetVisibility
                && !row.operation.body.discoverable
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn operation_receipt(
        &self,
        root: &str,
        operation: &str,
        signer: &SigningKey,
        now: u64,
    ) -> Result<w::DirectoryReceipt> {
        let center = self.head().center_id;
        if let Some(row) = ImagePlan::new(&self.witness.db)
            .operation(&w::OperationKey { root: root.into(), operation_id: operation.into() })?
        {
            let op = &row.operation.body;
            let committed_at = row.finished_at.unwrap_or(row.reserved_at);
            let expires_at = if row.state == w::ReceiptState::Reserved {
                ensure(now < row.reservation_expires_at, Code::OperationPending)?;
                row.reservation_expires_at
            } else {
                after(now, 60)?
            };
            return Ok(crypto::sign_receipt(
                signer,
                &center,
                w::DirectoryReceiptBody {
                    center_id: center.clone(),
                    operation_id: operation.into(),
                    operation_hash: row.operation_hash,
                    principal_commitment: root.into(),
                    epoch: op.next_epoch,
                    state: row.state,
                    binding_hash: op.binding.as_ref().map(crypto::binding_hash).transpose()?,
                    profile: op.profile.clone(),
                    discoverable: op.discoverable,
                    committed_at,
                    expires_at,
                },
            )?);
        }
        let body = self.receipt_body(root, now)?;
        ensure(body.operation_id == operation, Code::NotFound)?;
        Ok(crypto::sign_receipt(signer, &center, body)?)
    }
}
