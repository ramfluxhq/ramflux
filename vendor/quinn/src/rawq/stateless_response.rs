// SPDX-License-Identifier: MIT OR Apache-2.0
//! One cancellable endpoint sender; queue and active datagram retain proto permits.
use crate::{AsyncUdpSocket, Runtime, UdpPoller};
use std::{collections::VecDeque, future::Future, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll, Waker}};

#[derive(Debug)]
struct Queue { entries: VecDeque<proto::Response>, wake: Option<Waker>, cancelled: bool, done: bool, active: usize }
#[derive(Debug)]
struct Shared { queue: Mutex<Queue>, pool: Arc<proto::ResponsePool>, completion: tokio::sync::Notify }
/// Retained cancellation and join ownership for an endpoint's stateless sender.
#[derive(Clone, Debug)]
pub struct StatelessResponseSender(Arc<Shared>);
impl StatelessResponseSender {
    pub(crate) fn start(pool: Arc<proto::ResponsePool>, socket: Arc<dyn AsyncUdpSocket>, runtime: &dyn Runtime) -> Self {
        let handle = Self(Arc::new(Shared { queue: Mutex::new(Queue { entries: VecDeque::with_capacity(pool.capacity()), wake: None, cancelled: false, done: false, active: 0 }), pool, completion: Default::default() }));
        runtime.spawn(Box::pin(Sender { shared: handle.0.clone(), poller: socket.clone().create_io_poller(), socket, active: None }));
        handle
    }
    pub(crate) fn capacity(&self) -> usize { self.0.pool.capacity() }
    pub(crate) fn enqueue(&self, response: proto::Response) {
        let wake = { let mut q = self.0.queue.lock().unwrap(); if q.cancelled { return; } assert!(q.entries.len() < self.0.pool.capacity()); q.entries.push_back(response); q.wake.take() };
        if let Some(w) = wake { w.wake(); }
    }
    /// Reserved slab/item counters, including queued and active sends.
    pub fn stats(&self) -> proto::ResponseStats { self.0.pool.stats() }
    /// Queued responses, active sends and live sender tasks (always zero or one).
    pub fn ownership(&self) -> (usize, usize, usize) { let q=self.0.queue.lock().unwrap(); (q.entries.len(),q.active,usize::from(!q.done)) }
    /// Cancel queued and active work; join confirms destruction of sender-owned responses.
    pub fn cancel(&self) {
        self.0.pool.close();
        let wake = { let mut q=self.0.queue.lock().unwrap(); q.cancelled=true; q.entries.clear(); q.wake.take() };
        if let Some(w)=wake { w.wake(); }
    }
    /// Wait for sender destruction after cancellation or runtime shutdown.
    /// The endpoint/service scope owns any racing synchronous response producers.
    pub async fn join(&self) { loop { let done=self.0.completion.notified(); if self.0.queue.lock().unwrap().done { return; } done.await; } }
}
struct Sender { shared: Arc<Shared>, socket: Arc<dyn AsyncUdpSocket>, poller: Pin<Box<dyn UdpPoller>>, active: Option<proto::Response> }
impl Future for Sender {
    type Output=();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        for _ in 0..8 {
            { let mut q=self.shared.queue.lock().unwrap(); q.wake=Some(cx.waker().clone()); if q.cancelled { return Poll::Ready(()); } }
            if self.active.is_none() {
                let next=self.shared.queue.lock().unwrap().entries.pop_front();
                self.active=next;
                self.shared.queue.lock().unwrap().active=usize::from(self.active.is_some());
            }
            let Some(response)=self.active.as_ref() else { return Poll::Pending; };
            match self.socket.try_send(&crate::udp_transmit(response.transmit(),response.bytes())) {
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => {
                    match self.poller.as_mut().poll_writable(cx) {
                        Poll::Ready(Err(_)) => { self.active=None; self.shared.queue.lock().unwrap().active=0; continue; }
                        Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                    return Poll::Pending;
                }
                _ => { self.active=None; self.shared.queue.lock().unwrap().active=0; }
            }
        }
        cx.waker().wake_by_ref(); Poll::Pending
    }
}
impl Drop for Sender {
    fn drop(&mut self) {
        self.shared.pool.close();
        self.active=None;
        { let mut q=self.shared.queue.lock().unwrap(); q.cancelled=true; q.entries.clear(); q.active=0; q.done=true; }
        self.shared.completion.notify_waiters();
    }
}

pub(crate) enum Buffer { Legacy(Vec<u8>), Bounded(proto::ResponseBuffer, StatelessResponseSender) }
impl Buffer {
    pub(crate) fn new(sender: Option<&StatelessResponseSender>) -> Self { match sender { Some(s)=>Self::Bounded(proto::ResponseBuffer::new(s.0.pool.clone()),s.clone()),None=>Self::Legacy(Vec::new()) } }
    pub(crate) fn handle(&mut self, endpoint: &mut proto::Endpoint, now: crate::Instant, meta: &udp::RecvMeta, bytes: bytes::BytesMut, credit: Option<&Arc<crate::rawq::Credit>>) -> Option<proto::DatagramEvent> {
        match self {
            Self::Legacy(buf)=>match credit { Some(c)=>endpoint.handle_with_owner(now,meta.addr,meta.dst_ip,meta.ecn.map(crate::endpoint::proto_ecn),bytes,buf,c.clone()),None=>endpoint.handle(now,meta.addr,meta.dst_ip,meta.ecn.map(crate::endpoint::proto_ecn),bytes,buf) },
            Self::Bounded(buf,_)=>endpoint.handle_buffered(now,meta.addr,meta.dst_ip,meta.ecn.map(crate::endpoint::proto_ecn),bytes,buf,credit.map(|c|c.clone() as Arc<dyn std::any::Any+Send+Sync>)),
        }
    }
    pub(crate) fn refuse(&mut self, p:&mut proto::Endpoint, incoming:proto::Incoming)->Option<proto::Transmit> { match self { Self::Legacy(b)=>Some(p.refuse(incoming,b)),Self::Bounded(b,_)=>p.refuse_buffered(incoming,b) } }
    pub(crate) fn retry(&mut self, p:&mut proto::Endpoint, incoming:proto::Incoming)->Result<Option<proto::Transmit>,proto::RetryError> { match self { Self::Legacy(b)=>p.retry(incoming,b).map(Some),Self::Bounded(b,_)=>p.retry_buffered(incoming,b) } }
    #[allow(clippy::result_large_err)]
    pub(crate) fn accept(&mut self,p:&mut proto::Endpoint,incoming:proto::Incoming,now:crate::Instant,config:Option<Arc<proto::ServerConfig>>)->Result<(proto::ConnectionHandle,proto::Connection),proto::AcceptError> { match self { Self::Legacy(b)=>p.accept(incoming,now,b,config),Self::Bounded(b,_)=>p.accept_buffered(incoming,now,b,config) } }
    pub(crate) fn send(self, transmit: Option<proto::Transmit>, socket:&dyn AsyncUdpSocket) { if let Some(t)=transmit { match self { Self::Legacy(b)=>crate::endpoint::respond(t,&b,socket),Self::Bounded(b,s)=>if let Some(r)=b.finish(t) { s.enqueue(r); } } } }
}
