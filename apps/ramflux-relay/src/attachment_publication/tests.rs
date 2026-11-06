// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_node_core::attachment::{
    AttachmentReplayProof, RetirementOutcome,
    backend::{BackendCommit, BackendEntry},
    fixture::RetirementFixture,
};
use std::{
    io::Read,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
struct HeldBackend {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    refused: Arc<Mutex<(bool, bool)>>,
}
impl AttachmentBackend for HeldBackend {
    fn write_chunk(
        &self,
        _: &BackendSegment,
        _: u64,
        _: &mut dyn Read,
    ) -> Result<(), BackendError> {
        Err(BackendError::Bounds)
    }
    fn commit(&self, _: &BackendSegment) -> Result<BackendCommit, BackendError> {
        Err(BackendError::Bounds)
    }
    fn read_range(
        &self,
        _: &BackendSegment,
        _: u64,
        _: u64,
        output: &mut dyn Write,
    ) -> Result<(), BackendError> {
        output.write_all(&[42; 8])?;
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        let write = output.write_all(&[43; 8]);
        let flush = output.flush();
        *self.refused.lock().unwrap() = (
            write.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied),
            flush.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied),
        );
        write?;
        flush?;
        Ok(())
    }
    fn enumerate(&self, _: Option<&[u8]>, _: usize) -> Result<Vec<BackendEntry>, BackendError> {
        Err(BackendError::Bounds)
    }
    fn reconcile(&self, _: &BackendSegment) -> Result<(), BackendError> {
        Err(BackendError::Bounds)
    }
    fn delete(&self, _: &BackendSegment) -> Result<(), BackendError> {
        Err(BackendError::Bounds)
    }
}
#[derive(Clone)]
struct Spy(Arc<Mutex<(Vec<u8>, usize)>>);
impl Write for Spy {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().0.extend(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().1 += 1;
        Ok(())
    }
}
#[test]
fn relay_guard_holds_backend_until_join_and_refuses_late_write_and_flush() {
    let root = std::env::temp_dir().join(format!("rf-relay-retire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let fixture = RetirementFixture::new(&root.join("db"));
    let now = fixture.now;
    let (entered, wait) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let refused = Arc::new(Mutex::new((false, false)));
    let backend =
        HeldBackend { entered, release: Mutex::new(blocked), refused: Arc::clone(&refused) };
    let spy = Spy(Arc::new(Mutex::new((Vec::new(), 0))));
    let mut output = spy.clone();
    let native = fixture.native.clone();
    let grant = fixture.grant.clone();
    let registry = fixture.registry.clone();
    // Bounds and scope failures happen before a backend can receive bytes.
    let mut request = ScopedAttachmentRange {
        grant: &grant,
        manifest: &native,
        generation: 1,
        segment: 0,
        offset: 0,
        length: 0,
    };
    assert!(matches!(
        read_after_operation_admission(
            &registry,
            &backend,
            &request,
            &replay_proof(now, 0),
            &mut output,
            &|| now
        ),
        Err(BackendError::Bounds)
    ));
    let mut wrong = grant.grant().clone();
    wrong.object_id = [9; 32];
    let key = SigningKey::from_bytes(&std::array::from_fn(|i| u8::try_from(i).unwrap()));
    let sig = key.sign(&wrong.signing_bytes().unwrap()).to_bytes();
    let wrong = ramflux_protocol::large_attachment::ScopedAttachmentGrant::decode_signed(
        &wrong.signed_bytes(&sig).unwrap(),
    )
    .unwrap();
    request.length = 16;
    request.grant = &wrong;
    assert!(matches!(
        read_after_operation_admission(
            &registry,
            &backend,
            &request,
            &replay_proof(now, 0),
            &mut output,
            &|| now
        ),
        Err(BackendError::Conflict)
    ));
    // Capacity is retryable Busy, never a retired identity.
    let holders = (0..32)
        .map(|n| {
            registry
                .admit_operation_after_authentication(&grant, 1, &replay_proof(now, n), now)
                .unwrap()
        })
        .collect::<Vec<_>>();
    request.grant = &grant;
    assert!(matches!(
        read_after_operation_admission(
            &registry,
            &backend,
            &request,
            &replay_proof(now, 0),
            &mut output,
            &|| now
        ),
        Err(BackendError::Busy)
    ));
    drop(holders);
    let worker = std::thread::spawn(move || {
        read_after_operation_admission(
            &registry,
            &backend,
            &ScopedAttachmentRange {
                grant: &grant,
                manifest: &native,
                generation: 1,
                segment: 0,
                offset: 0,
                length: 16,
            },
            &replay_proof(now, 33),
            &mut output,
            &|| now,
        )
    });
    wait.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(spy.0.lock().unwrap().0, vec![42; 8]);
    assert!(
        matches!(
            fixture.registry.admit_operation_after_authentication(
                &fixture.grant,
                1,
                &replay_proof(now, 33),
                now
            ),
            Err(ramflux_node_core::attachment::AttachmentReplayError::Replay)
        ),
        "read must consume the exact admitted nonce"
    );
    let retire = fixture.request();
    assert_eq!(fixture.retire(&retire).unwrap(), RetirementOutcome::RevocationPending);
    assert_eq!(fixture.retire(&retire).unwrap(), RetirementOutcome::RevocationPending);
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    assert_eq!(*refused.lock().unwrap(), (true, true));
    assert_eq!(*spy.0.lock().unwrap(), (vec![42; 8], 0));
    assert_eq!(fixture.retire(&retire).unwrap(), RetirementOutcome::Retired);
    drop(fixture);
    std::fs::remove_dir_all(root).unwrap();
}

fn replay_proof(now: u64, n: u8) -> AttachmentReplayProof {
    AttachmentReplayProof { nonce: [n; 32], issued_at: now, expires_at: now + 30 }
}
