// SPDX-License-Identifier: MIT OR Apache-2.0
//! Send-space allocation boundaries and real protocol Retry/handshake close behavior.
use super::*;
use super::metadata_credit::{MetadataClass,MetadataCredit};
use crate::tests::util::{Pair,client_config,IncomingConnectionBehavior};

fn arm(conn:&mut Connection,limit:usize)->Arc<MetadataCredit>{
    let credit=MetadataCredit::new(limit);
    for space in &mut conn.spaces {space.pending.bind(Some(credit.clone()),MetadataClass::PendingRetransmits).unwrap();}
    conn.metadata=Some(credit.clone());conn.streams.metadata=Some(credit.clone());credit
}

#[test]
fn builders_refuse_before_packet_numbers_in_every_space(){
    for id in SpaceId::iter(){
        let mut pair=Pair::default();let(client,_)=pair.connect();let now=pair.time;
        let conn=pair.client_conn_mut(client);
        let credit=MetadataCredit::new(0);conn.metadata=Some(credit.clone());
        let before=(conn.spaces[id].next_packet_number,conn.spaces[id].sent_packets.len());
        let mut buffer=Vec::new();
        assert!(PacketBuilder::new(now,id,ConnectionId::new(&[7;8]),&mut buffer,1200,0,true,conn).is_none());
        assert!(buffer.is_empty());
        assert_eq!((conn.spaces[id].next_packet_number,conn.spaces[id].sent_packets.len()),before);
        assert_eq!(credit.stats().failed_class,Some(MetadataClass::SentRecords));
        assert_eq!(credit.stats().allocations,0);
    }
}

#[test]
fn retry_retains_shared_send_credit_until_actual_owners_are_destroyed(){
    let mut pair=Pair::default();
    pair.server.handle_incoming=Box::new(|incoming|if incoming.remote_address_validated(){IncomingConnectionBehavior::Accept}else{IncomingConnectionBehavior::Retry});
    let client=pair.begin_connect(client_config());
    let credit=arm(pair.client_conn_mut(client),1<<20);
    pair.drive();let server=pair.server.assert_accept();
    assert!(pair.client_conn_mut(client).retry_src_cid.is_some());
    for (endpoint,handle) in [(&mut pair.client,client),(&mut pair.server,server)]{
        let conn=endpoint.connections.get_mut(&handle).unwrap();
        assert!(std::iter::from_fn(||conn.poll()).any(|e|matches!(e,Event::Connected)));
    }
    assert!(!credit.stats().exhausted);assert!(credit.stats().allocations>0);
    assert!(credit.stats().used>0);assert!(credit.stats().peak<=1<<20);
    drop(pair);assert_eq!(credit.stats().used,0);
}

#[test]
fn handshake_record_refusal_emits_application_error_without_crypto_effects(){
    let mut pair=Pair::default();let client=pair.begin_connect(client_config());
    pair.drive_client();pair.server.drive_incoming(pair.time,pair.client.addr);
    let server=pair.server.assert_accept();
    let credit=MetadataCredit::new(0);pair.server_conn_mut(server).metadata=Some(credit.clone());
    pair.drive();
    let conn=pair.client_conn_mut(client);
    assert_eq!(conn.stats().frame_rx.crypto,0,"refused server builder emits no ordinary CRYPTO");
    assert!(std::iter::from_fn(||conn.poll()).any(|event|matches!(event,Event::ConnectionLost{reason:ConnectionError::ConnectionClosed(ref close)} if close.error_code==TransportErrorCode::APPLICATION_ERROR)));
    assert_eq!(credit.stats().failed_class,Some(MetadataClass::SentRecords));
    assert_eq!(credit.stats().allocations,0);assert_eq!(credit.stats().used,0);
}

#[test]
fn all_three_space_transfers_and_key_discard_charge_actual_retained_backing(){
    let mut pair=Pair::default();let(client,_)=pair.connect();let now=pair.time;
    let conn=pair.client_conn_mut(client);let credit=MetadataCredit::new(1<<20);
    for space in &mut conn.spaces {
        space.pending=Retransmits::with_metadata(Some(credit.clone()),MetadataClass::PendingRetransmits);
        space.sent_packets=Default::default();
        let mut owner=ThinRetransmits::default();owner.get_or_create(Some(credit.clone())).unwrap().test_child(4,0).unwrap();
        space.sent_packets.reserve_insert(Some(&credit)).unwrap();
        space.sent_packets.insert(0,SentPacket{path_generation:0,time_sent:now,size:0,ack_eliciting:false,largest_acked:None,retransmits:owner,stream_frames:Default::default()});
        space.loss_probes=1;space.maybe_queue_probe(false,&conn.streams);
        assert_eq!(space.pending.crypto.len(),1);
        assert_eq!(space.sent_packets.get(&0).unwrap().retransmits.storage(),(0,0));
    }
    let charges=conn.spaces.iter().map(|s|{
        let record=s.sent_packets.capacity_bytes();let pending=s.pending.capacity_bytes();
        assert!(record>0&&pending>0);
        ((record+63)&!63)+64+((pending+63)&!63)+64
    }).sum::<usize>();
    assert_eq!(credit.stats().used,charges,"three spaces share one actual-capacity ledger");
    conn.discard_space(now,SpaceId::Initial);conn.discard_space(now,SpaceId::Handshake);
    for id in [SpaceId::Initial,SpaceId::Handshake]{
        assert_eq!(conn.spaces[id].sent_packets.capacity_bytes(),0);
        assert!(conn.spaces[id].pending.capacity_bytes()>0,"key discard does not destroy retained pending backing");
    }
    assert!(credit.stats().used>0);drop(pair);assert_eq!(credit.stats().used,0);
}
