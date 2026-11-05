// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retransmit owner storage and fallible loss/PTO ownership transfers.
use super::{StreamsState,metadata_collections::{MetadataVec,MetadataDeque,MetadataSet},metadata_credit::{AllocationCharge,MetadataClass,MetadataCredit,ResourceExhausted}};
use crate::{Dir,StreamId,VarInt,TransportError,SocketAddr,cid_queue::CidQueue,frame,shared::IssuedCid};
use std::{ops::Range,sync::Arc};
/// Retransmittable data queue
#[allow(unreachable_pub)] // fuzzing only
#[derive(Debug, Default)]
pub struct Retransmits {
    pub(super) credit: Option<Arc<MetadataCredit>>,
    pub(super) max_data: bool,
    pub(super) data_blocked: bool,
    pub(super) max_stream_id: [bool; 2],
    pub(super) reset_stream: MetadataVec<(StreamId, VarInt)>,
    pub(super) stop_sending: MetadataVec<frame::StopSending>,
    pub(super) max_stream_data: MetadataSet<StreamId>,
    pub(super) stream_data_blocked: MetadataSet<StreamId>,
    pub(super) crypto: MetadataDeque<frame::Crypto>,
    pub(super) new_cids: MetadataVec<IssuedCid>,
    pub(super) retire_cids: MetadataVec<u64>,
    pub(super) ack_frequency: bool,
    pub(super) handshake_done: bool,
    /// For each enqueued NEW_TOKEN frame, a copy of the path's remote address
    ///
    /// There are 2 reasons this is unusual:
    ///
    /// - If the path changes, NEW_TOKEN frames bound for the old path are not retransmitted on the
    ///   new path. That is why this field stores the remote address: so that ones for old paths
    ///   can be filtered out.
    /// - If a token is lost, a new randomly generated token is re-transmitted, rather than the
    ///   original. This is so that if both transmissions are received, the client won't risk
    ///   sending the same token twice. That is why this field does _not_ store any actual token.
    ///
    /// It is true that a QUIC endpoint will only want to effectively have NEW_TOKEN frames
    /// enqueued for its current path at a given point in time. Based on that, we could conceivably
    /// change this from a vector to an `Option<(SocketAddr, usize)>` or just a `usize` or
    /// something. However, due to the architecture of Quinn, it is considerably simpler to not do
    /// that; consider what such a change would mean for implementing `BitOrAssign` on Self.
    pub(super) new_tokens: MetadataVec<SocketAddr>,
}

impl Retransmits {
    pub(super) fn with_metadata(credit:Option<Arc<MetadataCredit>>,class:MetadataClass)->Self {
        let mut value=Self::default();
        value.bind(credit,class).expect("empty collections do not allocate");value
    }
    pub(super) fn bind(&mut self,credit:Option<Arc<MetadataCredit>>,class:MetadataClass)->Result<(),ResourceExhausted>{
        if self.credit.is_none(){self.credit=credit.clone();}
        self.reset_stream.bind(credit.clone(),class)?;self.stop_sending.bind(credit.clone(),class)?;
        self.max_stream_data.bind(credit.clone(),class)?;self.stream_data_blocked.bind(credit.clone(),class)?;
        self.crypto.bind(credit.clone(),class)?;self.new_cids.bind(credit.clone(),class)?;
        self.retire_cids.bind(credit.clone(),class)?;self.new_tokens.bind(credit,class)?;Ok(())
    }
    #[cfg(any(test,feature="__control-test"))]
    pub(super) fn capacity_bytes(&self)->usize{self.reset_stream.capacity_bytes()+self.stop_sending.capacity_bytes()+self.max_stream_data.capacity_bytes()+self.stream_data_blocked.capacity_bytes()+self.crypto.capacity_bytes()+self.new_cids.capacity_bytes()+self.retire_cids.capacity_bytes()+self.new_tokens.capacity_bytes()}

    pub(super) fn retire_cids(&mut self, cids: Range<u64>) -> Result<(), TransportError> {
        // We don't bother counting in-flight frames because those are bounded by congestion control.
        let num = cids.end.saturating_sub(cids.start);
        if (self.retire_cids.len() as u64).saturating_add(num) > Self::MAX_PENDING_RETIRED_CIDS {
            return Err(TransportError::CONNECTION_ID_LIMIT_ERROR(
                "queued too many retired CIDs",
            ));
        }

        for cid in cids {if self.retire_cids.push(cid).is_err(){return Ok(());}}
        Ok(())
    }

    pub(super) fn is_empty(&self, streams: &StreamsState) -> bool {
        !self.max_data
            && !(self.data_blocked && streams.can_send_data_blocked())
            && !self.max_stream_id.into_iter().any(|x| x)
            && self.reset_stream.is_empty()
            && self.stop_sending.is_empty()
            && self
                .max_stream_data
                .iter()
                .all(|&id| !streams.can_send_flow_control(id))
            && self
                .stream_data_blocked
                .iter()
                .all(|&id| streams.stream_data_blocked_limit(id).is_none())
            && self.crypto.is_empty()
            && self.new_cids.is_empty()
            && self.retire_cids.is_empty()
            && !self.ack_frequency
            && !self.handshake_done
            && self.new_tokens.is_empty()
    }

    /// Ensure `pending_retired` cannot grow without bound
    ///
    /// Limit is somewhat arbitrary but very permissive.
    const MAX_PENDING_RETIRED_CIDS: u64 = CidQueue::LEN as u64 * 10;
}

impl Retransmits {
    pub(super) fn try_merge(&mut self,rhs:Self)->Result<(),ResourceExhausted>{
        self.reserve_merge(&rhs)?;
        self.reset_stream.extend_from_slice(&rhs.reset_stream)?;self.stop_sending.extend_from_slice(&rhs.stop_sending)?;
        for &value in rhs.max_stream_data.iter(){self.max_stream_data.insert(value)?;}
        for &value in rhs.stream_data_blocked.iter(){self.stream_data_blocked.insert(value)?;}
        for crypto in rhs.crypto.into_iter().rev(){self.crypto.push_front(crypto)?;}
        self.new_cids.extend_from_slice(&rhs.new_cids)?;
        for value in rhs.retire_cids {self.retire_cids.push(value)?;}
        self.new_tokens.extend_from_slice(&rhs.new_tokens)?;
        self.max_data|=rhs.max_data;self.data_blocked|=rhs.data_blocked;
        for dir in Dir::iter(){self.max_stream_id[dir as usize]|=rhs.max_stream_id[dir as usize];}
        self.ack_frequency|=rhs.ack_frequency;self.handshake_done|=rhs.handshake_done;Ok(())
    }
    fn reserve_merge(&mut self,rhs:&Self)->Result<(),ResourceExhausted>{
        // Source backing and its box remain charged during every destination reservation.
        self.reset_stream.reserve(rhs.reset_stream.len())?;self.stop_sending.reserve(rhs.stop_sending.len())?;
        self.max_stream_data.reserve_union(&rhs.max_stream_data)?;self.stream_data_blocked.reserve_union(&rhs.stream_data_blocked)?;
        self.crypto.reserve(rhs.crypto.len())?;self.new_cids.reserve(rhs.new_cids.len())?;
        self.retire_cids.reserve(rhs.retire_cids.len())?;self.new_tokens.reserve(rhs.new_tokens.len())?;
        Ok(())
    }
    pub(super) fn try_merge_thin(&mut self,mut rhs:ThinRetransmits)->Result<(),ResourceExhausted>{
        if let Some(boxed)=rhs.retransmits.as_ref(){self.reserve_merge(&boxed[0].value)?;}
        if let Some(mut boxed)=rhs.retransmits.take(){
            let charge=boxed[0].charge.take();
            let value=std::mem::take(&mut boxed[0].value);
            drop(boxed);
            // Children still carry their own leases after the box allocation is freed.
            drop(charge);
            self.try_merge(value)?;
        }Ok(())
    }
}
/// A variant of `Retransmits` which only allocates storage when required
#[derive(Debug, Default)]
pub(super) struct ThinRetransmits {
    retransmits: Option<Box<[RetransmitBox;1]>>,
}

impl ThinRetransmits {
    #[cfg(any(test,feature="__control-test"))]
    pub(super) fn box_charge()->usize{((std::mem::size_of::<RetransmitBox>()+63)&!63)+64}
    #[cfg(any(test,feature="__control-test"))]
    pub(super) fn storage(&self)->(usize,usize){self.retransmits.as_ref().map_or((0,0),|b|(std::mem::size_of::<RetransmitBox>(),b[0].value.capacity_bytes()))}
    /// Returns `true` if no retransmits are necessary
    pub(super) fn is_empty(&self, streams: &StreamsState) -> bool {
        match &self.retransmits {
            Some(retransmits) => retransmits[0].value.is_empty(streams),
            None => true,
        }
    }

    /// Returns a reference to the retransmits stored in this box
    pub(super) fn get(&self) -> Option<&Retransmits> {
        self.retransmits.as_ref().map(|b|&b[0].value)
    }

    /// Returns a mutable reference to the stored retransmits
    ///
    /// This function will allocate a backing storage if required.
    pub(super) fn get_or_create(&mut self,credit:Option<Arc<MetadataCredit>>)->Result<&mut Retransmits,ResourceExhausted>{
        if self.retransmits.is_none(){
            let class=MetadataClass::RetransmitOwners;
            let charge=credit.as_ref().map(|c|c.reserve(std::mem::size_of::<RetransmitBox>(),class)).transpose()?;
            let mut slot=Vec::new();
            if let Err(error)=slot.try_reserve_exact(1){
                if let Some(c)=&credit{return Err(c.fail(class));}else{panic!("retransmit allocation failed: {error}");}
            }
            assert_eq!(slot.capacity(),1);
            if let Some(c)=&credit{c.allocated();}
            slot.push(RetransmitBox{value:Retransmits::with_metadata(credit,class),charge});
            self.retransmits=Some(slot.into_boxed_slice().try_into().unwrap());
        }
        Ok(&mut self.retransmits.as_mut().unwrap()[0].value)
    }
}
#[derive(Debug)]
struct RetransmitBox{value:Retransmits,charge:Option<AllocationCharge>}
impl Drop for ThinRetransmits{
    fn drop(&mut self){if let Some(mut owner)=self.retransmits.take(){let charge=owner[0].charge.take();drop(owner);drop(charge);}}
}

#[cfg(test)]
impl Retransmits {
    pub(super) fn test_child(&mut self,kind:usize,serial:u64)->Result<(),ResourceExhausted>{
        let id=StreamId::new(crate::Side::Server,Dir::Uni,serial);
        match kind {
            0=>self.reset_stream.push((id,0u32.into())),
            1=>self.stop_sending.push(frame::StopSending{id,error_code:0u32.into()}),
            2=>self.max_stream_data.insert(id).map(|_|()),
            3=>self.stream_data_blocked.insert(id).map(|_|()),
            4=>self.crypto.push_back(frame::Crypto{offset:serial,data:bytes::Bytes::from_static(b"x")}),
            5=>self.new_cids.push(IssuedCid{sequence:serial,id:crate::ConnectionId::new(&[1;8]),reset_token:[0;16].into()}),
            6=>self.retire_cids.push(serial),
            7=>self.new_tokens.push(std::net::SocketAddr::from(([127,0,0,1],serial as u16))),
            _=>panic!("unknown retransmit child"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_box_child_and_pending_collection_preflights_actual_capacity(){
        for class in [MetadataClass::RetransmitOwners,MetadataClass::PendingRetransmits] {
            for kind in 0..8 {
                let credit=MetadataCredit::new(0);
                let mut value=Retransmits::with_metadata(Some(credit.clone()),class);
                assert!(value.test_child(kind,0).is_err());
                assert_eq!(value.capacity_bytes(),0,"refused child must not allocate");
                assert_eq!(credit.stats().allocations,0);
                assert_eq!(credit.stats().failed_class,Some(class));
                let credit=MetadataCredit::new(1<<20);
                let mut value=Retransmits::with_metadata(Some(credit.clone()),class);
                for serial in 0..4 {value.test_child(kind,serial).unwrap();}
                let capacity=value.capacity_bytes();assert!(capacity>0);
                assert_eq!(credit.stats().used,((capacity+63)&!63)+64);
                let used=credit.stats().used;
                let frozen=MetadataCredit::new(used);
                drop(value);assert_eq!(credit.stats().used,0);
                let mut value=Retransmits::with_metadata(Some(frozen.clone()),class);
                for serial in 0..4 {value.test_child(kind,serial).unwrap();}
                assert!(value.test_child(kind,4).is_err());
                assert_eq!(value.capacity_bytes(),capacity);assert_eq!(frozen.stats().allocations,1);
                drop(value);assert_eq!(frozen.stats().used,0);
            }
        }
        let credit=MetadataCredit::new(ThinRetransmits::box_charge());
        let mut thin=ThinRetransmits::default();
        thin.get_or_create(Some(credit.clone())).unwrap();
        assert_eq!(credit.stats().used,ThinRetransmits::box_charge());
        assert!(thin.get_or_create(Some(credit.clone())).unwrap().test_child(0,0).is_err());
        assert_eq!(thin.storage().1,0);assert_eq!(credit.stats().allocations,1);
        drop(thin);assert_eq!(credit.stats().used,0);
    }
    #[test]
    fn transfer_reserves_destination_while_box_and_children_are_live(){
        let ceiling=ThinRetransmits::box_charge()+128;
        let credit=MetadataCredit::new(ceiling);
        let mut thin=ThinRetransmits::default();
        thin.get_or_create(Some(credit.clone())).unwrap().test_child(0,0).unwrap();
        assert_eq!(thin.storage().1,64);
        let mut pending=Retransmits::with_metadata(Some(credit.clone()),MetadataClass::PendingRetransmits);
        assert!(pending.try_merge_thin(thin).is_err());assert_eq!(pending.capacity_bytes(),0);
        assert_eq!(credit.stats().failed_class,Some(MetadataClass::PendingRetransmits));
        assert_eq!(credit.stats().allocations,2);assert_eq!(credit.stats().used,0);
        let credit=MetadataCredit::new(ceiling+128);
        let mut thin=ThinRetransmits::default();thin.get_or_create(Some(credit.clone())).unwrap().test_child(0,0).unwrap();
        let mut pending=Retransmits::with_metadata(Some(credit.clone()),MetadataClass::PendingRetransmits);
        pending.try_merge_thin(thin).unwrap();assert_eq!(credit.stats().peak,ceiling+128);
        assert_eq!(pending.reset_stream.len(),1);assert_eq!(credit.stats().used,128);
        let mut iter=pending.reset_stream.into_iter();assert!(iter.next().is_some());
        assert_eq!(credit.stats().used,128,"popped value does not free the owned iterator backing");
        drop(iter);assert_eq!(credit.stats().used,0);
    }
}
