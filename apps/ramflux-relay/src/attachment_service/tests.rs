// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The attachment plane over a real mutually authenticated mesh listener, a real ledger and
//! the real local object backend. The test client plays the gateway: it sends the requester
//! the session would have proved.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use ramflux_node_core::{
    ATTACHMENT_MESH_PATH, AttachmentAuthorityReply, AttachmentCall, AttachmentMeshReply,
    AttachmentMeshRequest, RelayRedbStore, RequesterWire,
};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, AttachmentRetirement, ContentManifest, OwnerAttachmentOperation,
    OwnerBind, OwnerPut, OwnerReserve, QualifiedOwner, RequesterPop, ScopedAttachmentGrant,
    SegmentLayout, digest, requester_digest,
};

use super::{AttachmentService, serve_one};
use crate::test_support::{path_str, run_openssl};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NODE: &str = "localhost";
const DEADLINE: Duration = Duration::from_secs(30);

fn wire(owner: &QualifiedOwner) -> RequesterWire {
    RequesterWire {
        account_anchor: owner.account_anchor.clone(),
        device_id: owner.device_id.clone(),
        device_epoch: owner.device_epoch,
        signing_public_key: owner.signing_public_key,
        home_node_id: owner.home_node_id.clone(),
    }
}

fn device(anchor: &str, id: &str, seed: u8) -> (QualifiedOwner, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    (
        QualifiedOwner {
            account_anchor: anchor.into(),
            device_id: id.into(),
            device_epoch: 1,
            signing_public_key: key.verifying_key().to_bytes(),
            home_node_id: NODE.into(),
        },
        key,
    )
}

struct Certs {
    relay: ramflux_transport::MeshTlsConfig,
    gateway: ramflux_transport::MeshTlsConfig,
    other: ramflux_transport::MeshTlsConfig,
}

fn issue(
    dir: &std::path::Path,
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
    name: &str,
    uri: &str,
) -> Result<ramflux_transport::MeshTlsConfig, Box<dyn std::error::Error>> {
    let key = dir.join(format!("{name}-key.pem"));
    let csr = dir.join(format!("{name}.csr"));
    let cert = dir.join(format!("{name}.pem"));
    let ext = dir.join(format!("{name}.ext"));
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&key)?])?;
    run_openssl(&[
        "req",
        "-new",
        "-key",
        path_str(&key)?,
        "-out",
        path_str(&csr)?,
        "-subj",
        &format!("/CN={name}"),
    ])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{name}, DNS:localhost, URI:{uri}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        path_str(&csr)?,
        "-CA",
        path_str(ca_cert)?,
        "-CAkey",
        path_str(ca_key)?,
        "-CAcreateserial",
        "-out",
        path_str(&cert)?,
        "-days",
        "30",
        "-extfile",
        path_str(&ext)?,
    ])?;
    Ok(ramflux_transport::MeshTlsConfig {
        ca_cert: ca_cert.to_path_buf(),
        service_cert: cert,
        service_key: key,
    })
}

fn certs(root: &std::path::Path) -> Result<Certs, Box<dyn std::error::Error>> {
    let ca_key = root.join("ca-key.pem");
    let ca_cert = root.join("ca.pem");
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        path_str(&ca_key)?,
        "-out",
        path_str(&ca_cert)?,
        "-days",
        "30",
        "-subj",
        "/CN=Attachment Mesh Test CA",
    ])?;
    Ok(Certs {
        relay: issue(root, &ca_cert, &ca_key, "ramflux-relay", "spiffe://localhost/ramflux-relay")?,
        gateway: issue(
            root,
            &ca_cert,
            &ca_key,
            "ramflux-gateway",
            "spiffe://localhost/ramflux-gateway/ramflux-gateway",
        )?,
        other: issue(
            root,
            &ca_cert,
            &ca_key,
            "ramflux-router",
            "spiffe://localhost/ramflux-router",
        )?,
    })
}

struct World {
    addr: String,
    gateway: ramflux_transport::MeshTlsConfig,
    other: ramflux_transport::MeshTlsConfig,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    authority_key: [u8; 32],
    seq: std::cell::Cell<u8>,
    _root: ramflux_test_support::TestPath,
}

impl World {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let root = ramflux_test_support::TestPath::new()?.child("attachment-service");
        std::fs::create_dir_all(&root)?;
        let tls = certs(&root)?;
        let store = RelayRedbStore::open(root.join("state").join("relay.redb"))?;
        let service = AttachmentService::open(NODE, &store, &root.join("state"))?;
        let authority_key = service.signer.verifying_key().to_bytes();
        let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &tls.relay)?;
        let addr = server.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let _keep = store;
            while !flag.load(Ordering::SeqCst) {
                let _ = serve_one(&server, &service, NODE);
            }
        });
        Ok(Self {
            addr,
            gateway: tls.gateway,
            other: tls.other,
            stop,
            server: Some(handle),
            authority_key,
            seq: std::cell::Cell::new(1),
            _root: root,
        })
    }

    fn post(
        &self,
        tls: &ramflux_transport::MeshTlsConfig,
        requester: &QualifiedOwner,
        call: AttachmentCall,
    ) -> Result<AttachmentMeshReply, Box<dyn std::error::Error>> {
        let body = AttachmentMeshRequest { requester: wire(requester), call };
        Ok(ramflux_transport::MeshHttpClient::new().post_json_with_deadline(
            &self.addr,
            ATTACHMENT_MESH_PATH,
            tls,
            "ramflux-relay",
            &body,
            Instant::now() + DEADLINE,
        )?)
    }

    fn call(
        &self,
        requester: &QualifiedOwner,
        call: AttachmentCall,
    ) -> Result<AttachmentMeshReply, Box<dyn std::error::Error>> {
        self.post(&self.gateway, requester, call)
    }

    fn owner(
        &self,
        owner: &QualifiedOwner,
        key: &SigningKey,
        op: &OwnerAttachmentOperation,
        body: &[u8],
    ) -> Result<AttachmentMeshReply, Box<dyn std::error::Error>> {
        let nonce_byte = self.seq.get();
        self.seq.set(nonce_byte.wrapping_add(1));
        let mut nonce = [nonce_byte; 32];
        nonce[1] = 0xA5;
        let now = crate::config::now_unix_seconds();
        let pop = RequesterPop {
            operation_hash: op.hash()?,
            requester_digest: requester_digest(owner)?,
            nonce,
            issued_at: now,
            expires_at: now + 30,
            forward_digest: [0; 32],
        };
        let signature = key.sign(&pop.signing_bytes()?).to_bytes();
        self.call(
            owner,
            AttachmentCall::Owner {
                operation: op.canonical_bytes()?.into(),
                body: body.to_vec().into(),
                proof: pop.canonical_bytes()?.into(),
                signature: signature.to_vec().into(),
            },
        )
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // One more authenticated call wakes the blocking accept so the thread can end.
        let (wake, _) = device("wake", "wake", 9);
        let _ = self.call(&wake, AttachmentCall::Authority);
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
    }
}

struct Staged {
    upload: [u8; 32],
    object: [u8; 32],
    hash: [u8; 32],
    signed: Vec<u8>,
    native: ramflux_protocol::large_attachment::VerifiedContentManifest,
}

fn expect_ok(reply: &AttachmentMeshReply, what: &str) {
    assert_eq!(reply.code, None, "{what} was refused");
}

fn upload(
    world: &World,
    owner: &QualifiedOwner,
    key: &SigningKey,
    id: u8,
) -> Result<Staged, Box<dyn std::error::Error>> {
    let object = [id; 32];
    let upload = [id.wrapping_add(100); 32];
    let layout = SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 };
    let mut sealer =
        ramflux_crypto::large_attachment::SegmentSealer::from_persisted([7; 32], object, layout)?;
    let cipher = sealer.seal(0, &[])?;
    let manifest = ContentManifest {
        object_id: object,
        owner: owner.clone(),
        layout,
        segment_digests: vec![ramflux_crypto::large_attachment::segment_digest(&cipher)?],
    };
    let signature = key.sign(&manifest.signing_bytes()?).to_bytes();
    let signed = manifest.signed_bytes(&signature)?;
    let native = ContentManifest::decode_signed(&signed)?;
    let hash = native.manifest().hash()?;
    let now = crate::config::now_unix_seconds();
    let (reserve, body) = OwnerAttachmentOperation::reserve(&OwnerReserve {
        audience: NODE,
        object_id: object,
        authority_generation: 1,
        upload_id: upload,
        plaintext_length: 0,
        network_chunk_bytes: 524_288,
        lease_hard_until: now + 3600,
    })?;
    expect_ok(&world.owner(owner, key, &reserve, &body)?, "reserve");
    let bind = OwnerAttachmentOperation::bind(&OwnerBind {
        audience: NODE,
        object_id: object,
        manifest_hash: hash,
        authority_generation: 1,
        operation_id: upload,
        payload_generation: 1,
        body: &signed,
    })?;
    expect_ok(&world.owner(owner, key, &bind, &signed)?, "bind");
    let put = OwnerAttachmentOperation::put(&OwnerPut {
        audience: NODE,
        object_id: object,
        manifest_hash: hash,
        authority_generation: 1,
        operation_id: upload,
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        body: &cipher,
    })?;
    expect_ok(&world.owner(owner, key, &put, &cipher)?, "put");
    let commit = OwnerAttachmentOperation::commit(NODE, object, hash, 1, upload, 1)?;
    let committed = world.owner(owner, key, &commit, &[])?;
    expect_ok(&committed, "commit");
    let state: serde_json::Value = serde_json::from_slice(&committed.body.0)?;
    assert_eq!(state["state"], "committed", "commit reply: {state}");
    let retry = world.owner(owner, key, &commit, &[])?;
    expect_ok(&retry, "commit retry");
    let state: serde_json::Value = serde_json::from_slice(&retry.body.0)?;
    assert_eq!(state["state"], "committed", "a committed retry is idempotent: {state}");
    Ok(Staged { upload, object, hash, signed, native })
}

struct Registered {
    capability: Vec<u8>,
    grant: ScopedAttachmentGrant,
}

fn register(
    world: &World,
    owner: &QualifiedOwner,
    key: &SigningKey,
    up: &Staged,
    grantee: &QualifiedOwner,
    grant_byte: u8,
) -> Result<Registered, Box<dyn std::error::Error>> {
    let now = crate::config::now_unix_seconds();
    let grant_id = [grant_byte; 32];
    let mut material = [0_u8; 64];
    material[..32].copy_from_slice(&up.object);
    material[32..].copy_from_slice(&grant_id);
    let grant = ScopedAttachmentGrant {
        grant_id,
        reference_id: digest("ramflux.attachment.reference.v1", &material)?,
        object_id: up.object,
        manifest_hash: up.hash,
        owner: owner.clone(),
        grantee: grantee.clone(),
        epoch: 1,
        rights: 15,
        issued_at: now,
        expires_at: now + 3600,
    };
    let signature = key.sign(&grant.signing_bytes()?).to_bytes();
    let signed = grant.signed_bytes(&signature)?;
    let reply = world.call(
        owner,
        AttachmentCall::Register {
            upload_id: up.upload.to_vec().into(),
            manifest: up.signed.clone().into(),
            grant: signed.into(),
        },
    )?;
    expect_ok(&reply, "register");
    Ok(Registered { capability: reply.body.0, grant })
}

fn read(
    world: &World,
    reader: &QualifiedOwner,
    up: &Staged,
    capability: &[u8],
) -> Result<AttachmentMeshReply, Box<dyn std::error::Error>> {
    world.call(
        reader,
        AttachmentCall::Read {
            capability: capability.to_vec().into(),
            object_id: up.object.to_vec().into(),
            manifest_hash: up.hash.to_vec().into(),
            index: 0,
            offset: 0,
            length: 16,
        },
    )
}

fn retire(
    world: &World,
    owner: &QualifiedOwner,
    key: &SigningKey,
    registered: &Registered,
) -> Result<AttachmentMeshReply, Box<dyn std::error::Error>> {
    let g = &registered.grant;
    let request = AttachmentRetirement {
        reference_id: g.reference_id,
        grant_id: g.grant_id,
        grant_hash: g.hash()?,
        grant_epoch: g.epoch,
        source_authority: NODE.into(),
        authority_generation: 1,
        operation_id: [g.grant_id[0].wrapping_add(50); 32],
        issued_at: crate::config::now_unix_seconds(),
    };
    let signature = key.sign(&request.signing_bytes()?).to_bytes();
    world.call(
        owner,
        AttachmentCall::Retire {
            retirement: request.canonical_bytes()?.into(),
            signature: signature.to_vec().into(),
        },
    )
}

#[test]
fn owner_upload_register_read_and_last_retire_erase_the_object() -> TestResult {
    let world = World::open()?;
    let (owner, owner_key) = device("owner-anchor", "device-a", 3);
    let (reader, _) = device("reader-anchor", "device-b", 4);
    let (stranger, _) = device("stranger-anchor", "device-c", 5);
    let (sibling, _) = device("reader-anchor", "device-d", 6);

    let authority = world.call(&owner, AttachmentCall::Authority)?;
    expect_ok(&authority, "authority");
    let pin: AttachmentAuthorityReply = serde_json::from_slice(&authority.body.0)?;
    assert_eq!(pin.source, NODE);
    assert_eq!(pin.generation, 1);
    assert_eq!(ramflux_protocol::decode_base64url(&pin.signing_public_key)?, world.authority_key);

    let up = upload(&world, &owner, &owner_key, 9)?;
    let first = register(&world, &owner, &owner_key, &up, &reader, 21)?;
    let second = register(&world, &owner, &owner_key, &up, &sibling, 22)?;
    let (decoded, _) = AttachmentRegistrationReceipt::decode_capability(
        &first.capability,
        NODE,
        1,
        &world.authority_key,
        crate::config::now_unix_seconds(),
    )?;
    assert_eq!(decoded.grant().grantee, reader, "the capability names the grantee");
    assert_eq!(up.native.manifest().object_id, up.object);

    let body = read(&world, &reader, &up, &first.capability)?;
    expect_ok(&body, "grantee read");
    assert_eq!(body.body.0.len(), 16, "the one empty segment is 16 ciphertext bytes");
    let copied = read(&world, &stranger, &up, &first.capability)?;
    assert_eq!(copied.code.as_deref(), Some("not_grantee"), "a copied capability is refused");
    let wrong_object = world.call(
        &reader,
        AttachmentCall::Read {
            capability: first.capability.clone().into(),
            object_id: vec![1; 32].into(),
            manifest_hash: up.hash.to_vec().into(),
            index: 0,
            offset: 0,
            length: 16,
        },
    )?;
    assert_eq!(wrong_object.code.as_deref(), Some("layout_invalid"));

    // A peer other than the gateway is closed before any request is read.
    let denied = world.post(&world.other, &owner, AttachmentCall::Authority);
    assert!(denied.is_err(), "a non-gateway peer must not be served: {denied:?}");

    let stranger_retire = retire(&world, &stranger, &owner_key, &first)?;
    assert!(stranger_retire.code.is_some(), "only the owner may retire: {stranger_retire:?}");

    let one = retire(&world, &owner, &owner_key, &first)?;
    expect_ok(&one, "first retire");
    let state: serde_json::Value = serde_json::from_slice(&one.body.0)?;
    assert_eq!(state["state"], "retired", "{state}");
    assert_eq!(state["object_erased"], false, "another grant still reads the object: {state}");
    let after = read(&world, &reader, &up, &first.capability)?;
    assert_eq!(after.code.as_deref(), Some("attachment_deleted"), "a retired grant reads nothing");
    expect_ok(&read(&world, &sibling, &up, &second.capability)?, "sibling still reads");

    let last = retire(&world, &owner, &owner_key, &second)?;
    expect_ok(&last, "last retire");
    let state: serde_json::Value = serde_json::from_slice(&last.body.0)?;
    assert_eq!(state["object_erased"], true, "the last retire erases the relay bytes: {state}");
    let gone = read(&world, &sibling, &up, &second.capability)?;
    assert!(gone.code.is_some(), "no read after erase: {gone:?}");
    let again = retire(&world, &owner, &owner_key, &second)?;
    let state: serde_json::Value = serde_json::from_slice(&again.body.0)?;
    assert_eq!(state["object_erased"], true, "a retire retry reports the same erase: {state}");
    Ok(())
}
