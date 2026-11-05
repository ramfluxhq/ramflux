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

#[test]
fn refused_probe_keeps_the_committed_packet_owner(){
    let mut pair=Pair::default();let(client,_)=pair.connect();let now=pair.time;
    let conn=pair.client_conn_mut(client);
    let record_bytes=4*std::mem::size_of::<super::metadata_map::Slot<SentPacket>>();
    let limit=ThinRetransmits::box_charge()+128+((record_bytes+63)&!63)+64;
    let credit=MetadataCredit::new(limit);
    let space=&mut conn.spaces[SpaceId::Data];
    space.pending=Retransmits::with_metadata(Some(credit.clone()),MetadataClass::PendingRetransmits);
    space.sent_packets=Default::default();
    let mut owner=ThinRetransmits::default();owner.get_or_create(Some(credit.clone())).unwrap().test_child(0,0).unwrap();
    let backing=owner.storage();
    space.sent_packets.reserve_insert(Some(&credit)).unwrap();
    space.sent_packets.insert(0,SentPacket{path_generation:0,time_sent:now,size:0,ack_eliciting:false,largest_acked:None,retransmits:owner,stream_frames:Default::default()});
    let used=credit.stats().used;space.loss_probes=1;
    space.maybe_queue_probe(false,&conn.streams);
    assert_eq!(credit.stats().failed_class,Some(MetadataClass::PendingRetransmits));
    assert_eq!(space.sent_packets.get(&0).unwrap().retransmits.storage(),backing,"refused transfer must preserve the committed box and children");
    assert_eq!(credit.stats().used,used);assert_eq!(space.pending.capacity_bytes(),0);
    drop(pair);assert_eq!(credit.stats().used,0);
}

#[test]
fn populate_refusal_preserves_the_finished_datagram_prefix(){
    let mut pair=Pair::default();let(client,_)=pair.connect();let now=pair.time;
    let conn=pair.client_conn_mut(client);
    let record_bytes=4*std::mem::size_of::<super::metadata_map::Slot<SentPacket>>();
    let limit=384+((record_bytes+63)&!63)+64;
    for space in &mut conn.spaces {
        assert!(space.pending.is_empty(&conn.streams));
        space.pending=Retransmits::default();
    }
    let old=std::mem::take(&mut conn.spaces[SpaceId::Data].sent_packets);
    for packet in old.into_values(){conn.remove_in_flight(&packet);}
    let credit=arm(conn,limit);
    let first=conn.streams().open(Dir::Uni).unwrap();let second=conn.streams().open(Dir::Uni).unwrap();
    conn.send_stream(first).set_priority(10).unwrap();
    let payload=vec![0x5a;conn.path.current_mtu() as usize];
    conn.send_stream(first).write(&payload).unwrap();conn.send_stream(second).write(b"second").unwrap();
    let mut buffer=Vec::new();
    let tx=conn.poll_transmit(now,2,&mut buffer).unwrap();
    assert!(conn.metadata_exhausted(),"second packet must hit STREAM metadata spill");
    assert_eq!(credit.stats().failed_class,Some(MetadataClass::SentFrameMetadata));
    let records=conn.spaces[SpaceId::Data].sent_packets.values().filter(|p|!p.stream_frames.is_empty()).collect::<Vec<_>>();
    assert_eq!(records.len(),1,"only the finished first packet is tracked");
    assert_eq!(records[0].stream_frames.iter().next().unwrap().id,first);
    assert_eq!(tx.size,buffer.len());assert_eq!(tx.size,conn.path.current_mtu() as usize);
    assert_eq!(tx.segment_size,None,"no empty second GSO datagram is reported");
    assert_eq!(buffer[0]&0x80,0,"returned prefix is the completed Data packet, not a replacement close");
    drop(records);
    let mut close=Vec::new();assert!(conn.poll_transmit(now,1,&mut close).is_some());
    assert!(!close.is_empty());
}
