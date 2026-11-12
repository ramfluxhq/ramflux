// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One outstanding local request; the ordinary owner supplies its actual writer only
//! after receiving the request and releases it before any relay work resumes.
use super::{
    AccountDb, FullLocalAction, FullLocalIoReply, FullLocalIoRequest, FullLocalIoScope,
    FullLocalResult, FullReverseManifestDraft, FullTransferLocalIo, SdkError, SourceManifest,
    Zeroizing, chunk_digest, wire, wrong,
};
use tokio::sync::{mpsc, oneshot};

struct Envelope {
    request: FullLocalIoRequest,
    reply: oneshot::Sender<Result<FullLocalIoReply, SdkError>>,
}
/// A memory-only worker port. It owns no DB, stage key, signer or publication right.
/// Exclusive mutable calls permit only one outstanding request and one bounded reply.
pub struct FullLocalIoPort {
    scope: FullLocalIoScope,
    sender: mpsc::Sender<Envelope>,
}
/// Held by the ordinary account owner. Drop closes queued work and erases its bytes.
pub struct FullLocalIoService(mpsc::Receiver<Envelope>);
/// A received request with no DB loan. It can only execute against the original live
/// selected account writer; the caller cannot fabricate an authenticated I/O reply.
pub struct FullLocalIoLoan(Envelope);

impl FullTransferLocalIo {
    /// Split local data work from its ordinary writer owner. Neither half retains the
    /// actual database; keep the service in that owner's lifecycle and drop it on lock.
    #[must_use]
    pub fn into_port(self) -> (FullLocalIoPort, FullLocalIoService) {
        let (sender, receiver) = mpsc::channel(1);
        (FullLocalIoPort { scope: self.scope, sender }, FullLocalIoService(receiver))
    }
}
impl Drop for FullLocalIoService {
    fn drop(&mut self) {
        self.0.close();
        while self.0.try_recv().is_ok() {}
    }
}
impl FullLocalIoService {
    /// Take one queued request without borrowing a database or blocking its owner.
    pub fn try_receive(&mut self) -> Option<FullLocalIoLoan> {
        self.0.try_recv().ok().map(FullLocalIoLoan)
    }
    /// Wait without borrowing a database, then acquire the ordinary owner's short loan
    /// solely for `apply`. A closed worker has no remaining requests.
    pub async fn receive(&mut self) -> Option<FullLocalIoLoan> {
        self.0.recv().await.map(FullLocalIoLoan)
    }
}
impl FullLocalIoLoan {
    /// Execute and destroy the local request before returning to async/network work.
    /// A cancelled worker is refused before opening a stage or decrypting any bytes.
    /// # Errors
    /// Refuses a closed worker or the underlying scope, digest, role or I/O failure.
    pub fn apply(self, db: &AccountDb) -> Result<(), SdkError> {
        let Envelope { request, reply } = self.0;
        if reply.is_closed() {
            return Err(SdkError::PairingCode("Retired"));
        }
        // Private results of an abandoned receiver drop synchronously in this owner.
        reply.send(request.apply(db)).map_err(|_| SdkError::PairingCode("Retired"))
    }
}
impl FullLocalIoPort {
    /// Pin the actual target through its ordinary owner's short local loan.
    /// Copy the returned view in a root-owned blocking worker after the loan ends.
    /// # Errors
    /// Refuses wrong scope/role, foreign input or a changed selected writer.
    pub async fn pin_receiver_base(
        &mut self,
        hash: &str,
    ) -> Result<Box<ramflux_storage::FullPinnedReceiverBase>, SdkError> {
        let FullLocalResult::ReceiverPinned(pinned) =
            self.request(FullLocalAction::PinReceiverBase { hash: hash.into() }).await?
        else {
            return Err(wrong());
        };
        Ok(pinned)
    }
    /// Apply signed base records to the exact receiver-owned copy. This is not DV.
    /// # Errors
    /// Refuses changed B/stage, bad input or typed conflicts; failed copies are erased.
    pub async fn project_receiver_base(
        &mut self,
        copy: Box<ramflux_storage::FullReceiverBaseCopy>,
    ) -> Result<Box<ramflux_storage::FullReceiverBaseCopy>, SdkError> {
        let FullLocalResult::ReceiverProjected(copy) =
            self.request(FullLocalAction::ProjectReceiverBase { copy }).await?
        else {
            return Err(wrong());
        };
        Ok(copy)
    }
    /// Retain this endpoint's independently fetched native head before applying its
    /// pre-publication role/key gate. This does not grant publication or tail admission.
    /// The stream owner must fetch through its own native query, never a peer/relay hint.
    /// # Errors
    /// Refuses rollback/forks/revocations, changed grant roles/keys or expired scope.
    pub async fn observe_prepublication_head(
        &mut self,
        current: ramflux_crypto::custody::VerifiedRecord,
    ) -> Result<(), SdkError> {
        let FullLocalResult::NativeObserved =
            self.request(FullLocalAction::ObservePrepublication(Box::new(current))).await?
        else {
            return Err(wrong());
        };
        Ok(())
    }
    async fn request(&mut self, action: FullLocalAction) -> Result<FullLocalResult, SdkError> {
        self.scope.live()?;
        let (reply, response) = oneshot::channel();
        self.sender
            .send(Envelope { request: self.scope.request(action), reply })
            .await
            .map_err(|_| SdkError::PairingCode("Retired"))?;
        let FullLocalIoReply(value) =
            response.await.map_err(|_| SdkError::PairingCode("Retired"))??;
        self.scope.live()?;
        Ok(value)
    }
    /// Read one exact locally signed chunk without retaining its database loan.
    /// # Errors
    /// Refuses locked/stale/foreign scope, unsigned chunks or a closed service.
    pub async fn read_source_chunk(
        &mut self,
        hash: &str,
        index: u64,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let FullLocalResult::SourceChunk(bytes) =
            self.request(FullLocalAction::ReadSourceChunk { hash: hash.into(), index }).await?
        else {
            return Err(wrong());
        };
        Ok(bytes)
    }
    /// Retain a signed forward manifest through the original receiver's ledger.
    /// # Errors
    /// Refuses wrong scope/signature/catalog/chain or a closed service.
    pub async fn retain_manifest(
        &mut self,
        manifest: &SourceManifest,
    ) -> Result<Option<u64>, SdkError> {
        let FullLocalResult::DurablePrefix(prefix) = self
            .request(FullLocalAction::RetainManifest { manifest: Box::new(manifest.clone()) })
            .await?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Fsync one bounded encrypted chunk before returning its disk prefix.
    /// # Errors
    /// Refuses wrong scope/order/bytes, failed durability or a closed service.
    pub async fn retain_chunk(
        &mut self,
        hash: &str,
        index: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Option<u64>, SdkError> {
        let digest = chunk_digest(index, &bytes).map_err(|error| wire(&error))?;
        let FullLocalResult::DurablePrefix(prefix) = self
            .request(FullLocalAction::RetainChunk { hash: hash.into(), index, digest, bytes })
            .await?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Verify complete disk bytes only; this grants no semantic/DV or adoption marker.
    /// # Errors
    /// Refuses incomplete/corrupt input, changed ownership or a closed service.
    pub async fn verify_forward_root(&mut self, hash: &str) -> Result<(), SdkError> {
        let FullLocalResult::ForwardRootChecked =
            self.request(FullLocalAction::VerifyForwardRoot { hash: hash.into() }).await?
        else {
            return Err(wrong());
        };
        Ok(())
    }
    /// Prepare only the original new recipient's actual pinned empty reverse cut.
    /// # Errors
    /// Refuses another mode/role, effective vetoes or a closed service.
    pub async fn prepare_empty_reverse(&mut self) -> Result<FullReverseManifestDraft, SdkError> {
        let FullLocalResult::UnsignedReverse(manifest) =
            self.request(FullLocalAction::PrepareEmptyReverse).await?
        else {
            return Err(wrong());
        };
        Ok(FullReverseManifestDraft { manifest, scope: self.scope.clone() })
    }
    /// Retain exact original-B reverse metadata without granting semantic verification.
    /// # Errors
    /// Refuses foreign scope/signatures/catalog, recuts or a closed service.
    pub async fn retain_reverse_manifest(
        &mut self,
        manifest: &SourceManifest,
    ) -> Result<(), SdkError> {
        let FullLocalResult::ReverseManifestRetained = self
            .request(FullLocalAction::RetainReverseManifest {
                manifest: Box::new(manifest.clone()),
            })
            .await?
        else {
            return Err(wrong());
        };
        Ok(())
    }
}
