// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One socket owner; bounded channels never perform local-bus I/O.
use super::security;
use crate::{PrxAuthorization, PrxBridgeConfig, Result};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::{Notify, mpsc},
    time::Instant,
};

pub(super) const CAPACITY: usize = 256;
const MAX_FRAME: usize = 1_048_576;
pub(super) enum Command {
    Reconnect,
    Call { tag: String, method: String, params: Value, admission: Arc<AtomicU8> },
    Answer { generation: u64, id: Value, code: Option<i64> },
}
pub(super) enum Event {
    Connected,
    Disconnected,
    HelloRefused(i64),
    Backoff(u64),
    Request { generation: u64, frame: Value },
    Response { tag: String, result: Value, error: Option<i64> },
    Rejected { oversize: bool },
    LateAck,
}
struct Events {
    sender: mpsc::Sender<Event>,
    ready: Arc<Notify>,
}
impl Events {
    async fn send(&self, event: Event) -> std::result::Result<(), mpsc::error::SendError<Event>> {
        self.sender.send(event).await?;
        self.ready.notify_one();
        Ok(())
    }
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}
pub(super) struct Transport {
    pub commands: mpsc::Sender<Command>,
    pub events: mpsc::Receiver<Event>,
    task: tokio::task::JoinHandle<()>,
    pub ready: Arc<Notify>,
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Transport {
    pub fn start(config: PrxBridgeConfig, account: String) -> Result<Self> {
        security::validate(&config.socket_path)?;
        let (commands, rx) = mpsc::channel(CAPACITY);
        let (tx, events) = mpsc::channel(CAPACITY);
        let ready = Arc::new(Notify::new());
        let task = tokio::spawn(run(
            config,
            account,
            rx,
            Events { sender: tx, ready: Arc::clone(&ready) },
        ));
        Ok(Self { commands, events, task, ready })
    }
}
async fn run(
    config: PrxBridgeConfig,
    account: String,
    mut commands: mpsc::Receiver<Command>,
    events: Events,
) {
    let mut delay = 1u64;
    let mut removed = false;
    let mut generation = 0u64;
    loop {
        if commands.is_closed() || events.is_closed() {
            return;
        }
        let socket = match security::validate(&config.socket_path) {
            Ok(true) => UnixStream::connect(&config.socket_path).await.ok(),
            Ok(false) => None,
            Err(_) => {
                eprintln!("agent host bridge reconnect refused: socket_security");
                None
            }
        };
        if let Some(socket) = socket {
            generation = generation.saturating_add(1);
            let refusal = session(
                socket,
                &mut commands,
                &events,
                Session { config: &config, account: &account, removed: &mut removed, generation },
            )
            .await;
            if refusal {
                delay = 60;
            } else {
                delay = 1;
            }
            while commands.try_recv().is_ok() {}
            if events.send(Event::Disconnected).await.is_err() {
                return;
            }
        }
        if events.send(Event::Backoff(delay)).await.is_err() {
            return;
        }
        eprintln!("agent host bridge reconnecting; retry in {delay}s");
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = delay.saturating_mul(2).min(60);
    }
}
async fn write(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &Value,
) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(10), writer.write_all(&bytes))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)?
}
async fn line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    bytes: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let remaining = MAX_FRAME.saturating_add(1).saturating_sub(bytes.len());
    let mut bounded = (&mut *reader).take(u64::try_from(remaining).unwrap_or(0));
    bounded.read_until(b'\n', bytes).await
}
fn envelope(bytes: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let map = v.as_object()?;
    if map
        .keys()
        .any(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params" | "result" | "error"))
        || v["jsonrpc"] != "2.0"
        || !(v["id"].is_string() || v["id"].is_u64())
        || v["id"].as_str().is_some_and(|id| id.len() > 256)
        || (v["method"].is_string() && (map.contains_key("result") || map.contains_key("error")))
        || (!v["method"].is_string() && map.contains_key("result") == map.contains_key("error"))
    {
        return None;
    }
    Some(v)
}
struct Session<'a> {
    config: &'a PrxBridgeConfig,
    account: &'a str,
    removed: &'a mut bool,
    generation: u64,
}
async fn open(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    config: &PrxBridgeConfig,
    account: &str,
    removed: bool,
) -> bool {
    if removed {
        let added = json!({"jsonrpc":"2.0","id":"rf-added","method":"inbound.control",
            "params":{"conversation_id":"","kind":"agent_added","timestamp_ms":crate::bus::now_ms()}});
        if write(writer, &added).await.is_err() {
            return false;
        }
    }
    let mode = match config.authorization {
        PrxAuthorization::Full => "full",
        PrxAuthorization::Supervised => "supervised",
    };
    let hello = json!({"jsonrpc":"2.0","id":"rf-hello","method":"bridge.hello","params":{
        "protocol_version":"1","agent_account_id":account,"capabilities":["reply.text","reply.surface","tool.event","approval.request","inbound.message_deleted"],"authorization":mode}});
    if write(writer, &hello).await.is_err() {
        return false;
    }
    true
}
async fn session(
    socket: UnixStream,
    commands: &mut mpsc::Receiver<Command>,
    events: &Events,
    context: Session<'_>,
) -> bool {
    let Session { config, account, removed, generation } = context;
    let (read, mut writer) = socket.into_split();
    let mut reader = BufReader::new(read);
    if !open(&mut writer, config, account, *removed).await {
        return false;
    }
    let mut ready = false;
    let mut sequence = 0u64;
    let mut pending: BTreeMap<String, (String, Instant)> = BTreeMap::new();
    let mut bytes = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let opened = Instant::now();
    let mut ping = opened;
    loop {
        tokio::select! {
            read=line(&mut reader,&mut bytes)=>{
                match read {
                    Ok(0)|Err(_)=>return false,
                    Ok(_) if bytes.len()>MAX_FRAME=>{
                        let _=events.send(Event::Rejected{oversize:true}).await;return false;
                    },
                    Ok(_) if bytes.last()!=Some(&b'\n')=>continue,
                    Ok(_)=>{}
                }
                let parsed=envelope(&bytes);
                if parsed.is_none() {
                    let raw=serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
                    let id=if raw["id"].is_u64() || raw["id"].as_str().is_some_and(|id|id.len()<=256) {raw["id"].clone()} else {Value::Null};
                    let error=json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"invalid bridge frame"}});
                    if write(&mut writer,&error).await.is_err(){return false;}
                    if events.send(Event::Rejected{oversize:false}).await.is_err(){return false;}
                    bytes.clear();continue;
                }
                bytes.clear();
                let Some(frame)=parsed else {continue};
                if frame["method"].is_string() {
                    if events.send(Event::Request{generation,frame}).await.is_err(){return false;}
                } else if frame["id"]=="rf-hello" {
                    if frame["result"]["ok"]!=true {
                        let code=frame["error"]["code"].as_i64().unwrap_or(-32003);
                        *removed=code == -32003;
                        let _=events.send(Event::HelloRefused(code)).await;
                        return true;
                    }
                    *removed=false;ready=true;
                    if events.send(Event::Connected).await.is_err(){return false;}
                } else if frame["id"]=="rf-added" {
                    // A matching hello is still required after account-marker recovery.
                } else if let Some(id)=frame["id"].as_str() {
                    if let Some((tag,_))=pending.remove(id) {
                        if tag!="ping" && events.send(Event::Response{tag,result:frame["result"].clone(),error:frame["error"]["code"].as_i64()}).await.is_err(){return false;}
                    } else if events.send(Event::LateAck).await.is_err(){return false;}
                }
            },
            command=commands.recv(),if ready=>{
                let Some(command)=command else{return false;};
                let frame=match command {
                    Command::Reconnect=>return false,
                    Command::Call{tag,method,params,admission}=>{
                        if admission.compare_exchange(0,1,Ordering::SeqCst,Ordering::SeqCst).is_err() {
                            if events.send(Event::Response{tag,result:Value::Null,error:Some(-32800)}).await.is_err(){return false;}
                            continue;
                        }
                        if pending.len()>=CAPACITY {return false;}
                        sequence=sequence.saturating_add(1);let id=format!("rf-{sequence}");
                        pending.insert(id.clone(),(tag,Instant::now()));
                        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
                    },
                    Command::Answer{generation:source,id,code:None}=>{if source!=generation{events.ready.notify_one();continue;}json!({"jsonrpc":"2.0","id":id,"result":{"ok":true}})},
                    Command::Answer{generation:source,id,code:Some(code)}=>{if source!=generation{events.ready.notify_one();continue;}json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":"unsupported bridge method"}})},
                };
                if write(&mut writer,&frame).await.is_err(){return false;}
                events.ready.notify_one();
            },
            _=tick.tick()=>{
                if !ready && opened.elapsed()>=Duration::from_secs(10){return false;}
                if ready && ping.elapsed()>=Duration::from_secs(10) {
                    if pending.len()>=CAPACITY{return false;}
                    sequence=sequence.saturating_add(1);let id=format!("rf-{sequence}");
                    let frame=json!({"jsonrpc":"2.0","id":id,"method":"bridge.ping","params":{}});
                    pending.insert(id,("ping".into(),Instant::now()));ping=Instant::now();
                    if write(&mut writer,&frame).await.is_err(){return false;}
                }
                let expired=pending.iter().filter(|(_,(_,at))|at.elapsed()>=Duration::from_secs(10)).map(|(id,_)|id.clone()).collect::<Vec<_>>();
                for id in expired {
                    if let Some((tag,_))=pending.remove(&id) {
                        if tag=="ping"{return false;}
                        if events.send(Event::Response{tag,result:Value::Null,error:Some(-32000)}).await.is_err(){return false;}
                    }
                }
            }
        }
    }
}
