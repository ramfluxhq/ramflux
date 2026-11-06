// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant receive payload copies whose credit follows the final Bytes view.
//!
//! Payload storage and the Bytes wrapper have separate reservations; both follow
//! their actual free boundaries. Other receive allocations remain uncertified.
use super::{
    metadata_credit::{MetadataClass, MetadataCredit, ResourceExhausted},
    metadata_owned_bytes::{self, PayloadBacking},
};
use bytes::Bytes;
use std::sync::Arc;

/// Select one diagnostic family for one shared packet payload allocation.
/// Two frames in that packet share the backing, never two allocation charges.
pub(super) fn payload_class(bytes: &Bytes) -> Option<MetadataClass> {
    crate::frame::Iter::new(bytes.clone()).ok()?.find_map(|frame| match frame.ok()? {
        crate::frame::Frame::Stream(frame) if !frame.data.is_empty() => Some(MetadataClass::StreamAssemblers),
        crate::frame::Frame::Crypto(frame) if !frame.data.is_empty() => Some(MetadataClass::CryptoAssemblers),
        _ => None,
    })
}

pub(super) fn copy_payload(
    source: &[u8],
    raw_owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
    credit: &Arc<MetadataCredit>,
    class: MetadataClass,
) -> Result<Bytes, ResourceExhausted> {
    let charge = Some(credit.reserve(source.len(), class)?);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(source.len()).map_err(|_| credit.fail(class))?;
    assert_eq!(bytes.capacity(), source.len(), "receive-copy layout differs from admitted capacity");
    credit.allocated();
    credit.receive_backing_capacity(bytes.capacity());
    bytes.extend_from_slice(source);
    metadata_owned_bytes::into_bytes(PayloadBacking::new(bytes, raw_owner, charge), credit, class)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_payload_capacity_is_shared_through_slices_and_last_clone() {
        for class in [MetadataClass::StreamAssemblers, MetadataClass::CryptoAssemblers] {
            let owner_charge = ((metadata_owned_bytes::owner_layout().size()+63)&!63)+64;
            let credit = MetadataCredit::new(192+owner_charge);
            let mut bytes = copy_payload(&[0x5a; 65], None, &credit, class).unwrap();
            assert_eq!(credit.stats().receive_backing_capacity, 65);
            let tail = bytes.split_off(32);
            let held = tail.slice(1..).clone();
            drop((bytes, tail));
            assert_eq!(&held[..], &[0x5a;32]);
            assert_eq!(credit.stats().used, 192+owner_charge);
            assert_eq!(credit.stats().allocations, 2);
            drop(held);assert_eq!(credit.stats().used, 0);
        }
    }
    #[test]
    fn real_crypto_handshake_uses_payload_backing_hook() {
        use crate::tests::util::{Pair, client_config};
        let mut pair=Pair::default();let client=pair.begin_connect(client_config());
        let credit=MetadataCredit::new(1<<20);
        let connection=pair.client_conn_mut(client);
        for space in &mut connection.spaces {
            space.pending.bind(Some(credit.clone()),MetadataClass::PendingRetransmits).unwrap();
        }
        connection.metadata=Some(credit.clone());connection.streams.metadata=Some(credit.clone());
        pair.drive();pair.server.assert_accept();
        let connection=pair.client_conn_mut(client);
        assert!(connection.stats().frame_rx.crypto>0);
        assert!(std::iter::from_fn(||connection.poll()).any(|event|matches!(event,crate::Event::Connected)));
        assert!(credit.stats().receive_backing_capacity>0,"real decrypted CRYPTO reaches the copy site");
        assert!(!credit.stats().exhausted);
        drop(pair);assert_eq!(credit.stats().used,0);
    }

    #[test]
    fn refusal_precedes_payload_growth_and_preserves_input() {
        let credit = MetadataCredit::new(191);
        let source = [7;65];
        assert!(copy_payload(&source,None,&credit,MetadataClass::StreamAssemblers).is_err());
        assert_eq!(source,[7;65]);assert_eq!(credit.stats().allocations,0);
        assert_eq!(credit.stats().receive_backing_capacity,0);assert_eq!(credit.stats().used,0);
    }
}
