// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production attachment plane: owner upload, grant registration, grantee reads and
//! retirement, served on a gateway-only mutually authenticated mesh surface. The local
//! gateway authenticates the requester from the live device session and sends it in the
//! mesh request; no other peer is read.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ramflux_node_core::backend::{AttachmentBackend, BackendSegment, LocalAttachmentBackend};
use ramflux_node_core::{
    ATTACHMENT_CALL_BODY_MAX, ATTACHMENT_MESH_PATH, AttachmentAuthority, AttachmentAuthorityReply,
    AttachmentCall, AttachmentLedgerError, AttachmentMeshReply, AttachmentMeshRequest,
    AttachmentOwner, AttachmentPolicy, AttachmentReplayError, AttachmentReplayProof,
    AttestedRegistration, NodeServiceConfig, OwnerAdmission, OwnerAdmissionError, RelayRedbStore,
    RequesterWire, RetirementOutcome, ScopedGrantRegistry, WireBytes,
};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, AttachmentRetirement, ContentManifest, QualifiedOwner,
    ScopedAttachmentGrant,
};

const ADDR_ENV: &str = "RAMFLUX_RELAY_ATTACHMENT_ADDR";
const SEED_FILE_ENV: &str = "RAMFLUX_RELAY_ATTACHMENT_AUTHORITY_SEED_FILE";
const SOURCE_ENV: &str = "RAMFLUX_RELAY_ATTACHMENT_SOURCE";
const GENERATION_ENV: &str = "RAMFLUX_RELAY_ATTACHMENT_GENERATION";
const WORKERS: usize = 8;
const REQUEST_BUDGET: Duration = Duration::from_secs(20);
/// One network chunk is the most a single read returns.
const READ_MAX: u64 = 524_288;
/// Reader right bit: GET.
const RIGHT_GET: u32 = 1;
const GATEWAY_SERVICE: &str = "ramflux-gateway";
const WIRE_MAX: usize = ATTACHMENT_CALL_BODY_MAX * 2 + 8192;

pub(crate) const CODE_QUOTA: &str = "quota_exceeded";
pub(crate) const CODE_EXPIRED: &str = "expired";
pub(crate) const CODE_REJECTED: &str = "upload_rejected";
pub(crate) const CODE_NOT_GRANTEE: &str = "not_grantee";
pub(crate) const CODE_DELETED: &str = "attachment_deleted";
pub(crate) const CODE_UNAVAILABLE: &str = "authority_unavailable";
pub(crate) const CODE_LAYOUT: &str = "layout_invalid";

/// The attachment plane of one relay.
pub(crate) struct AttachmentService {
    registry: ScopedGrantRegistry,
    backend: LocalAttachmentBackend,
    signer: SigningKey,
    source: String,
    generation: u64,
    home: String,
}

/// Starts the surface when `RAMFLUX_RELAY_ATTACHMENT_ADDR` is set.
pub(crate) fn start(
    config: &NodeServiceConfig,
    store: &Arc<RelayRedbStore>,
    redb_path: &Path,
) -> anyhow::Result<()> {
    let state_dir = redb_path.parent().unwrap_or_else(|| Path::new("."));
    let Some(addr) = ramflux_node_core::environment::var(ADDR_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let service = Arc::new(AttachmentService::open(&config.node_id, store, state_dir)?);
    let server =
        ramflux_transport::MeshTlsServer::bind(&addr, &crate::config::mesh_tls_config(config))?;
    server.set_nonblocking(true)?;
    let server = Arc::new(server);
    for _ in 0..WORKERS {
        let server = Arc::clone(&server);
        let service = Arc::clone(&service);
        let node = config.node_id.clone();
        ramflux_node_core::spawn_service_worker("attachment-mesh", move |shutdown| {
            while !shutdown.is_cancelled() {
                if let Err(error) = serve_one(&server, &service, &node) {
                    tracing::debug!(%error, "attachment mesh request ended");
                }
            }
        })?;
    }
    tracing::info!(addr, source = %service.source, "relay attachment surface listening");
    Ok(())
}

pub(crate) fn serve_one(
    server: &ramflux_transport::MeshTlsServer,
    service: &AttachmentService,
    node: &str,
) -> anyhow::Result<()> {
    let accepted = match server.accept_authenticated() {
        Ok(accepted) => accepted,
        Err(ramflux_transport::TransportError::Io(error))
            if error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            std::thread::sleep(Duration::from_millis(10));
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let identity = ramflux_node_core::parse_mesh_spiffe_uri(
        accepted.peer_spiffe_uri.as_deref().unwrap_or_default(),
    )?;
    if identity.service_id != GATEWAY_SERVICE || identity.node_id != node {
        anyhow::bail!("attachment surface requires the local gateway mTLS identity");
    }
    let mut stream = accepted.stream;
    stream.sock.set_read_timeout(Some(REQUEST_BUDGET))?;
    stream.sock.set_write_timeout(Some(REQUEST_BUDGET))?;
    let Some(request) = ramflux_transport::read_mesh_http_request_limited(&mut stream, WIRE_MAX)?
    else {
        return Ok(());
    };
    if request.method != "POST" || request.path != ATTACHMENT_MESH_PATH {
        ramflux_transport::write_mesh_text_response(
            &mut stream,
            "404 Not Found",
            "unknown attachment route",
        )?;
        return Ok(());
    }
    let reply = match ramflux_protocol::parse_i_json::<AttachmentMeshRequest>(&request.body) {
        Ok(parsed) => service.handle(&owner_of(&parsed.requester), parsed.call, now()),
        Err(_) => refuse(CODE_LAYOUT),
    };
    ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &reply)?;
    ramflux_transport::close_mesh_server_stream(&mut stream)?;
    Ok(())
}

fn now() -> u64 {
    crate::config::now_unix_seconds()
}

fn owner_of(wire: &RequesterWire) -> QualifiedOwner {
    QualifiedOwner {
        account_anchor: wire.account_anchor.clone(),
        device_id: wire.device_id.clone(),
        device_epoch: wire.device_epoch,
        signing_public_key: wire.signing_public_key,
        home_node_id: wire.home_node_id.clone(),
    }
}

fn refuse(code: &str) -> AttachmentMeshReply {
    AttachmentMeshReply { code: Some(code.to_owned()), body: WireBytes::default() }
}

fn ok(body: Vec<u8>) -> AttachmentMeshReply {
    AttachmentMeshReply { code: None, body: WireBytes(body) }
}

impl AttachmentService {
    pub(crate) fn open(
        node_id: &str,
        store: &RelayRedbStore,
        state_dir: &Path,
    ) -> anyhow::Result<Self> {
        let signer = load_or_create_seed(state_dir)?;
        let source = ramflux_node_core::environment::var(SOURCE_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| node_id.to_owned());
        let generation = match ramflux_node_core::environment::var(GENERATION_ENV) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|error| anyhow::anyhow!("invalid {GENERATION_ENV}: {error}"))?,
            Err(_) => 1,
        };
        let registry = store
            .attachment_ledger(AttachmentPolicy::default())
            .map_err(|error| anyhow::anyhow!("attachment ledger: {error}"))?
            .scoped_grants(AttachmentAuthority {
                source: source.clone(),
                generation,
                signing_public_key: signer.verifying_key().to_bytes(),
            })
            .map_err(|error| anyhow::anyhow!("attachment authority: {error}"))?;
        let namespace = ramflux_protocol::large_attachment::digest(
            "ramflux.relay.attachment.namespace.v1",
            source.as_bytes(),
        )
        .map_err(|error| anyhow::anyhow!("attachment namespace: {error:?}"))?;
        let backend = store
            .local_attachment_backend(namespace, state_dir.join("attachment-objects"))
            .map_err(|error| anyhow::anyhow!("attachment backend: {error}"))?;
        Ok(Self { registry, backend, signer, source, generation, home: node_id.to_owned() })
    }

    /// Serves one call for an authenticated requester.
    pub(crate) fn handle(
        &self,
        requester: &QualifiedOwner,
        call: AttachmentCall,
        now: u64,
    ) -> AttachmentMeshReply {
        let registry = self.registry.with_deadline(Some(Instant::now() + REQUEST_BUDGET));
        match call {
            AttachmentCall::Authority => self.authority(),
            AttachmentCall::Owner { operation, body, proof, signature } => owner(
                &registry,
                &self.backend,
                requester,
                [&operation.0, &body.0, &proof.0],
                &signature.0,
                now,
            ),
            AttachmentCall::Register { upload_id, manifest, grant } => {
                self.register(&registry, requester, [&upload_id.0, &manifest.0, &grant.0], now)
            }
            AttachmentCall::Read {
                capability,
                object_id,
                manifest_hash,
                index,
                offset,
                length,
            } => {
                let range = ReadRange { index, offset, length };
                self.read(
                    &registry,
                    requester,
                    [&capability.0, &object_id.0, &manifest_hash.0],
                    &range,
                    now,
                )
            }
            AttachmentCall::Retire { retirement, signature } => {
                self.retire(&registry, requester, &retirement.0, &signature.0, now)
            }
        }
    }

    fn authority(&self) -> AttachmentMeshReply {
        let reply = AttachmentAuthorityReply {
            source: self.source.clone(),
            generation: self.generation,
            signing_public_key: ramflux_protocol::encode_base64url(
                self.signer.verifying_key().to_bytes(),
            ),
            home_node_id: self.home.clone(),
        };
        match serde_json::to_vec(&reply) {
            Ok(bytes) => ok(bytes),
            Err(_) => refuse(CODE_UNAVAILABLE),
        }
    }

    fn register(
        &self,
        registry: &ScopedGrantRegistry,
        requester: &QualifiedOwner,
        [upload, manifest, grant]: [&Vec<u8>; 3],
        now: u64,
    ) -> AttachmentMeshReply {
        let Ok(upload_id) = <[u8; 32]>::try_from(upload.as_slice()) else {
            return refuse(CODE_LAYOUT);
        };
        let (Ok(native), Ok(grant)) =
            (ContentManifest::decode_signed(manifest), ScopedAttachmentGrant::decode_signed(grant))
        else {
            return refuse(CODE_LAYOUT);
        };
        match registry.register_attested(&AttestedRegistration {
            requester,
            upload_id: &upload_id,
            native: &native,
            grant: &grant,
            signer: &self.signer,
            now,
        }) {
            Ok(row) => match ramflux_protocol::decode_base64url(&row.capability) {
                Ok(bytes) => ok(bytes),
                Err(_) => refuse(CODE_UNAVAILABLE),
            },
            Err(error) => ledger_code(&error),
        }
    }

    fn read(
        &self,
        registry: &ScopedGrantRegistry,
        requester: &QualifiedOwner,
        [capability, object, manifest_hash]: [&Vec<u8>; 3],
        range: &ReadRange,
        now: u64,
    ) -> AttachmentMeshReply {
        let (Ok(object_id), Ok(manifest_hash)) = (
            <[u8; 32]>::try_from(object.as_slice()),
            <[u8; 32]>::try_from(manifest_hash.as_slice()),
        ) else {
            return refuse(CODE_LAYOUT);
        };
        if range.length == 0 || range.length > READ_MAX {
            return refuse(CODE_LAYOUT);
        }
        let key = self.signer.verifying_key().to_bytes();
        let Ok((grant, _)) = AttachmentRegistrationReceipt::decode_capability(
            capability,
            &self.source,
            self.generation,
            &key,
            now,
        ) else {
            return refuse(CODE_NOT_GRANTEE);
        };
        if grant.grant().object_id != object_id || grant.grant().manifest_hash != manifest_hash {
            return refuse(CODE_LAYOUT);
        }
        let mut nonce = [0_u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            return refuse(CODE_UNAVAILABLE);
        }
        let proof =
            AttachmentReplayProof { nonce, issued_at: now, expires_at: now.saturating_add(30) };
        let lease = match registry
            .admit_reader_after_authentication(requester, &grant, RIGHT_GET, &proof, now)
        {
            Ok(lease) => lease,
            Err(error) => return replay_code(&error),
        };
        let segment = match Self::segment(registry, &grant, range.index) {
            Ok(segment) => segment,
            Err(code) => return refuse(code),
        };
        let mut output = Vec::new();
        let read = lease.publish(now, || {
            self.backend
                .read_range(&segment, range.offset, range.length, &mut output)
                .map_err(|_| AttachmentLedgerError::State)
        });
        match read {
            Ok(()) => ok(output),
            Err(error) => ledger_code(&error),
        }
    }

    /// The manifest comes from the committed ledger row, never from process memory.
    fn segment(
        registry: &ScopedGrantRegistry,
        grant: &ramflux_protocol::large_attachment::VerifiedScopedGrant,
        index: u64,
    ) -> Result<BackendSegment, &'static str> {
        let row = registry
            .lookup(&grant.grant().grant_id)
            .map_err(|_| CODE_UNAVAILABLE)?
            .ok_or(CODE_NOT_GRANTEE)?;
        let owner =
            AttachmentOwner::from_authenticated_session(&grant.grant().owner.account_anchor)
                .map_err(|_| CODE_LAYOUT)?;
        let record =
            registry.ledger_reservation(&owner, &row.upload_id).map_err(|_| CODE_UNAVAILABLE)?;
        let generation = record.committed_generation.ok_or(CODE_UNAVAILABLE)?;
        let native =
            ContentManifest::decode_signed(&record.manifest_bytes).map_err(|_| CODE_UNAVAILABLE)?;
        let index = u32::try_from(index).map_err(|_| CODE_LAYOUT)?;
        BackendSegment::from_manifest(&native, generation, index).map_err(|_| CODE_LAYOUT)
    }

    fn retire(
        &self,
        registry: &ScopedGrantRegistry,
        requester: &QualifiedOwner,
        retirement: &[u8],
        signature: &[u8],
        now: u64,
    ) -> AttachmentMeshReply {
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return refuse(CODE_LAYOUT);
        };
        let Ok(signed) =
            AttachmentRetirement::verify(retirement, &signature, &requester.signing_public_key)
        else {
            return refuse(CODE_REJECTED);
        };
        let grant_id = signed.request().grant_id;
        let (state, erased) = match registry.retire_attested(requester, &signed, now) {
            Ok(RetirementOutcome::Retired) => {
                let erased =
                    registry.erase_unreferenced(&grant_id, &self.backend).unwrap_or_else(|error| {
                        tracing::warn!(%error, "attachment erase deferred");
                        false
                    });
                ("retired", erased)
            }
            Ok(RetirementOutcome::RevocationPending) => ("retirement_pending", false),
            Err(error) => return ledger_code(&error),
        };
        match serde_json::to_vec(&serde_json::json!({ "state": state, "object_erased": erased })) {
            Ok(bytes) => ok(bytes),
            Err(_) => refuse(CODE_UNAVAILABLE),
        }
    }
}

struct ReadRange {
    index: u64,
    offset: u64,
    length: u64,
}

fn owner(
    registry: &ScopedGrantRegistry,
    backend: &dyn AttachmentBackend,
    requester: &QualifiedOwner,
    [operation, body, proof]: [&Vec<u8>; 3],
    signature: &[u8],
    now: u64,
) -> AttachmentMeshReply {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return refuse(CODE_LAYOUT);
    };
    if body.len() > ATTACHMENT_CALL_BODY_MAX {
        return refuse(CODE_LAYOUT);
    }
    let admitted = registry.admit_owner_operation_after_authentication(
        &OwnerAdmission { operation, body, proof, proof_signature: &signature, requester, now },
        backend,
    );
    match admitted {
        Ok(bytes) => ok(bytes),
        Err(OwnerAdmissionError::Ledger(error)) => ledger_code(&error),
        Err(OwnerAdmissionError::Replay(error)) => replay_code(&error),
        Err(OwnerAdmissionError::Refused | OwnerAdmissionError::Publication) => {
            refuse(CODE_REJECTED)
        }
    }
}

fn ledger_code(error: &AttachmentLedgerError) -> AttachmentMeshReply {
    refuse(match error {
        AttachmentLedgerError::AccountQuotaExceeded { .. } => CODE_QUOTA,
        AttachmentLedgerError::Expired => CODE_EXPIRED,
        AttachmentLedgerError::Conflict => CODE_REJECTED,
        AttachmentLedgerError::State => CODE_DELETED,
        _ => CODE_UNAVAILABLE,
    })
}

fn replay_code(error: &AttachmentReplayError) -> AttachmentMeshReply {
    refuse(match error {
        AttachmentReplayError::Ledger(AttachmentLedgerError::Conflict) => CODE_NOT_GRANTEE,
        AttachmentReplayError::Ledger(inner) => return ledger_code(inner),
        AttachmentReplayError::Expired => CODE_EXPIRED,
        _ => CODE_REJECTED,
    })
}

fn load_or_create_seed(state_dir: &Path) -> anyhow::Result<SigningKey> {
    let path: PathBuf = match ramflux_node_core::environment::var(SEED_FILE_ENV) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
        _ => state_dir.join("attachment-authority.seed"),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::read(&path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("attachment authority seed must be 32 bytes"))?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0_u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|error| anyhow::anyhow!("attachment authority seed: {error}"))?;
            write_private(&path, &seed)?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) => Err(error.into()),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
