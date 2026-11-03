// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real Unix frames drive the real host loop; all output assertions observe the fake rfd.
use crate::{
    AgentBus, AgentHost, Config, EngineConfig, Error, PrxAuthorization, PrxBridgeConfig,
    PrxBridgeEngine, Result,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{Notify, mpsc},
};
pub(super) type TestResult<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Default)]
pub(super) struct Data {
    pub requests: Vec<(String, Value, Option<String>)>,
    pub messages: HashMap<String, Value>,
    pub receipts: HashMap<String, Value>,
    pub replies: Vec<Value>,
    pub surfaces: Vec<ramflux_protocol::A2uiConversationEvent>,
    pub surface_write_times: Vec<u64>,
    pub surface_states: HashMap<String, ramflux_protocol::SurfaceState>,
    pub task: Value,
    pub verified: bool,
    pub removed: bool,
    pub bus_down: bool,
    pub fail_after_task_read: Option<()>,
    pub fail_reply: Option<()>,
    pub clock: u64,
    pub polled_clock: u64,
}
pub(super) struct Bus {
    pub data: Arc<Mutex<Data>>,
    pub changed: Arc<Notify>,
    pub events: mpsc::Receiver<ramflux_sdk::LocalBusFrame>,
}
impl Bus {
    fn request_inner(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        let mut data = self.data.lock().map_err(|_| Error::State)?;
        data.requests.push((method.into(), body.clone(), operation.map(str::to_owned)));
        self.changed.notify_waiters();
        if data.bus_down || method == "message.submit" && data.fail_reply.is_some() {
            data.bus_down = true;
            return Err(Error::Bus);
        }
        Ok(match method {
            "account.status" => {
                json!({"principal_id":"agent-principal","principal_kind":"headless_ai","state":"unlocked","networking":"live","local_device_authorized":true})
            }
            "device.list" => {
                json!({"principal_id":"agent-principal","local_device_id":"agent-device","devices":[{"device_id":"agent-device"}]})
            }
            "identity.directory" => json!({"identities":[
                {"principal_id":"agent-principal","kind":"headless_ai","is_self":true,"contact_identity_commitment":"agent-root","devices":[{"device_id":"agent-device","signing_public_key":"agent-key"}]},
                {"principal_id":"human-principal","kind":"human","kind_verified":true,"is_self":false,"display_name":"Member","safety_state":if data.verified{"verified"}else{"unverified"},"contact_identity_commitment":"human-root","devices":[{"device_id":"human-device","target_delivery_id":"human-delivery"},{"device_id":"human-other","target_delivery_id":"other-delivery"}]}
            ]}),
            "conversation.directory" => {
                json!({"conversations":[{"id":"thread","kind":"direct","participants":["agent-principal","human-principal"],"removed":data.removed}],"next_cursor":null})
            }
            "group.list" => json!({"groups":[]}),
            "bus.subscribe" => json!({"head_seq":0,"subscribed":true}),
            "message.receive" => {
                data.polled_clock = data.clock;
                json!({})
            }
            "mcp.server.add" => json!({}),
            "message.read" => {
                json!({"messages":data.messages.values().cloned().collect::<Vec<_>>()})
            }
            "message.submit" | "group.send" | "surface.send" => {
                let id = operation.ok_or(Error::State)?;
                if method == "surface.send" {
                    let now = if data.clock == 0 { crate::bus::now_ms() } else { data.clock };
                    data.surface_write_times.push(now);
                }
                if let Some(prior) = data.receipts.get(id) {
                    if prior != &body {
                        return Err(Error::State);
                    }
                } else {
                    data.receipts.insert(id.into(), body.clone());
                    if method == "surface.send" {
                        let wire = ramflux_protocol::decode_base64url(
                            body["wire_base64"].as_str().ok_or(Error::State)?,
                        )
                        .map_err(|_| Error::State)?;
                        let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&wire)
                            .map_err(|_| Error::State)?;
                        let surface_id =
                            crate::runner_output::command_id(event.command()).to_owned();
                        let next = data
                            .surface_states
                            .entry(surface_id)
                            .or_default()
                            .apply(&event)
                            .map_err(|_| Error::State)?;
                        data.surface_states.insert(
                            crate::runner_output::command_id(event.command()).to_owned(),
                            next,
                        );
                        data.surfaces.push(event);
                    } else {
                        data.replies.push(body);
                    }
                }
                json!({"accepted":true})
            }
            "mcp.tool.started" => {
                json!({"status":"approval_required","approval":{"approval_id":"approval-human","details":{"requested_grant_id":"grant-human"}}})
            }
            "task.get" => {
                let task = data.task.clone();
                if data.fail_after_task_read.is_some() {
                    data.fail_after_task_read = None;
                    data.bus_down = true;
                }
                task
            }
            "task.propose" => {
                data.task = body.clone();
                data.task["state"] = json!("proposed");
                data.task["version"] = json!(1);
                data.task["accepted"] = json!(false);
                json!({"accepted":true})
            }
            "task.update" => {
                for (k, v) in body.as_object().ok_or(Error::State)? {
                    data.task[k] = v.clone();
                }
                json!({"accepted":true})
            }
            _ => return Err(Error::Unauthorized),
        })
    }
}
impl AgentBus for Bus {
    fn now_ms(&self) -> u64 {
        self.data.lock().map_or_else(
            |_| crate::bus::now_ms(),
            |d| if d.clock == 0 { crate::bus::now_ms() } else { d.clock },
        )
    }

    fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Value>> {
        std::future::ready(self.request_inner(method, body, operation))
    }

    async fn next_event(&mut self) -> Result<ramflux_sdk::LocalBusFrame> {
        self.events.recv().await.ok_or(Error::Bus)
    }
}
pub(super) enum Wire {
    Frame(Value),
    Raw(Vec<u8>),
    Disconnect,
}
pub(super) struct Server {
    pub path: PathBuf,
    pub calls: Arc<Mutex<Vec<Value>>>,
    pub changed: Arc<Notify>,
    pub erase_errors: Arc<Mutex<VecDeque<Option<i64>>>>,
    pub ack_inbound: Arc<std::sync::atomic::AtomicBool>,
    pub hello_code: Arc<std::sync::atomic::AtomicI64>,
    pub hello_answer: Arc<std::sync::atomic::AtomicBool>,
    pub disconnects: Arc<AtomicU64>,
    outgoing: mpsc::Sender<Wire>,
    task: tokio::task::JoinHandle<()>,
    next: AtomicU64,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    pub fn new(root: &std::path::Path) -> TestResult<Self> {
        let path = root.join("p.sock");
        let listener = tokio::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let (outgoing, mut incoming) = mpsc::channel::<Wire>(256);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let changed = Arc::new(Notify::new());
        let erase_errors = Arc::new(Mutex::new(VecDeque::<Option<i64>>::new()));
        let ack_inbound = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hello_code = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let hello_answer = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let disconnects = Arc::new(AtomicU64::new(0));
        let closed = Arc::clone(&disconnects);
        let hello_error = Arc::clone(&hello_code);
        let hello_reply = Arc::clone(&hello_answer);
        let (seen, notify, errors, ack) = (
            Arc::clone(&calls),
            Arc::clone(&changed),
            Arc::clone(&erase_errors),
            Arc::clone(&ack_inbound),
        );
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let (reader, mut writer) = socket.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                loop {
                    tokio::select! {
                        read=reader.read_line(&mut line)=>{
                            if !matches!(read,Ok(n) if n>0){break;}
                            let frame=serde_json::from_str::<Value>(&line);line.clear();
                            let Ok(frame)=frame else{break;};
                            if let Ok(mut frames)=seen.lock(){frames.push(frame.clone());}notify.notify_waiters();
                            let Some(method)=frame["method"].as_str() else{continue;};
                            if method=="inbound.message"&&!ack.load(Ordering::SeqCst){continue;}
                            if method=="bridge.hello"&&!hello_reply.load(Ordering::SeqCst){continue;}
                            let error=if method=="bridge.hello"&&hello_error.load(Ordering::SeqCst)!=0 {Some(hello_error.load(Ordering::SeqCst))}else if method=="inbound.message_deleted"{errors.lock().ok().and_then(|mut q|q.pop_front()).flatten()}else{None};
                            let response=if let Some(code)=error{json!({"jsonrpc":"2.0","id":frame["id"],"error":{"code":code,"message":"fixture refusal"}})}
                                else{json!({"jsonrpc":"2.0","id":frame["id"],"result":if method=="inbound.message_deleted"{json!({"erased":true})}else{json!({"ok":true})}})};
                            let Ok(mut bytes)=serde_json::to_vec(&response) else{break;};bytes.push(b'\n');
                            if writer.write_all(&bytes).await.is_err(){break;}
                        },
                        wire=incoming.recv()=>{
                            let Some(wire)=wire else{return;};
                            let bytes=match wire{Wire::Frame(value)=>{let Ok(mut bytes)=serde_json::to_vec(&value) else{break;};bytes.push(b'\n');bytes},Wire::Raw(bytes)=>bytes,Wire::Disconnect=>break};
                            if writer.write_all(&bytes).await.is_err(){break;}
                        }
                    }
                }
                closed.fetch_add(1, Ordering::SeqCst);
                notify.notify_waiters();
            }
        });
        Ok(Self {
            path,
            calls,
            changed,
            erase_errors,
            ack_inbound,
            hello_code,
            hello_answer,
            disconnects,
            outgoing,
            task,
            next: AtomicU64::new(1),
        })
    }
    pub fn stop_listener(&self) {
        self.task.abort();
    }
    pub async fn call(&self, method: &str, params: Value) -> TestResult<Value> {
        let id = format!("prx-{}", self.next.fetch_add(1, Ordering::SeqCst));
        self.outgoing
            .send(Wire::Frame(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})))
            .await?;
        let frames = Arc::clone(&self.calls);
        let found = id.clone();
        wait(&self.changed, move || {
            frames
                .lock()
                .ok()?
                .iter()
                .find(|f| f["id"] == found && f.get("method").is_none())
                .cloned()
        })
        .await
    }
    pub async fn raw(&self, bytes: Vec<u8>) -> TestResult {
        self.outgoing.send(Wire::Raw(bytes)).await?;
        Ok(())
    }
    pub async fn disconnect(&self) -> TestResult {
        self.outgoing.send(Wire::Disconnect).await?;
        Ok(())
    }
    pub async fn wait_method(&self, method: &str, after: usize) -> TestResult<Value> {
        let frames = Arc::clone(&self.calls);
        let method = method.to_owned();
        wait(&self.changed, move || {
            frames.lock().ok()?.iter().skip(after).find(|f| f["method"] == method).cloned()
        })
        .await
    }
}
pub(super) async fn wait<T>(
    changed: &Notify,
    mut check: impl FnMut() -> Option<T>,
) -> TestResult<T> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let notified = changed.notified();
            if let Some(value) = check() {
                return value;
            }
            notified.await;
        }
    })
    .await
    .map_err(Into::into)
}
pub(super) struct Stopped {
    pub host: AgentHost<PrxBridgeEngine>,
    pub root: tempfile::TempDir,
}
pub(super) struct Host {
    pub root: tempfile::TempDir,
    pub config: Config,
    pub data: Arc<Mutex<Data>>,
    pub changed: Arc<Notify>,
    pub events: mpsc::Sender<ramflux_sdk::LocalBusFrame>,
    task: tokio::task::JoinHandle<(AgentHost<PrxBridgeEngine>, Result<()>)>,
    sequence: u64,
}
impl Host {
    pub async fn start(server: &Server, authorization: PrxAuthorization) -> TestResult<Self> {
        let root =
            tempfile::Builder::new().prefix("rf-b-").tempdir_in(if cfg!(target_os = "macos") {
                PathBuf::from("/private/tmp")
            } else {
                std::env::temp_dir()
            })?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let bridge: PrxBridgeConfig = serde_json::from_value(
            json!({"socket_path":server.path,"authorization":authorization,"stream_flush_ms":100,"turn_timeout_s":1000}),
        )?;
        let config = Config {
            socket: root.path().join("rfd.sock"),
            state_file: root.path().join("checkpoint.json"),
            account_id: "agent".into(),
            rules: vec![],
            engine: Some(EngineConfig { prx: None, prx_bridge: Some(bridge.clone()) }),
            poll_interval_ms: 50,
            per_conversation_interval_ms: 100,
            max_conversations: 128,
        };
        Self::launch(root, config, Arc::new(Mutex::new(Data { verified: true, ..Data::default() })))
            .await
    }
    pub async fn resume(stopped: Stopped, data: Arc<Mutex<Data>>) -> TestResult<Self> {
        let config = stopped.host.config.clone();
        let root = stopped.root;
        drop(stopped.host);
        tokio::task::yield_now().await;
        Self::launch(root, config, data).await
    }
    async fn launch(
        root: tempfile::TempDir,
        config: Config,
        data: Arc<Mutex<Data>>,
    ) -> TestResult<Self> {
        let bridge =
            config.engine.as_ref().and_then(|e| e.prx_bridge.as_ref()).ok_or("bridge config")?;
        let engine = PrxBridgeEngine::new(bridge, "agent", 128)?;
        let mut host = AgentHost::new(config.clone(), engine)?;
        let changed = Arc::new(Notify::new());
        let (events, rx) = mpsc::channel(256);
        let mut bus = Bus { data: Arc::clone(&data), changed: Arc::clone(&changed), events: rx };
        host.start(&mut bus).await?;
        let sequence = host.state.cursor.unwrap_or(0);
        let task = tokio::spawn(async move {
            let result = host.run(&mut bus).await;
            (host, result)
        });
        Ok(Self { root, config, data, changed, events, task, sequence })
    }
    pub async fn event(&mut self, method: &str, body: Value) -> TestResult {
        self.sequence += 1;
        let mut frame = ramflux_sdk::LocalBusFrame::request(
            format!("event-{}", self.sequence),
            Some("agent".into()),
            "stream",
            method,
            body,
        );
        frame.kind = ramflux_sdk::LocalBusFrameKind::Event;
        frame.seq = Some(self.sequence);
        self.events.send(frame).await?;
        Ok(())
    }
    pub async fn enqueue(&mut self, id: &str) -> TestResult {
        self.enqueue_text(id, "bridge input").await
    }
    pub async fn enqueue_text(&mut self, id: &str, text: &str) -> TestResult {
        self.data.lock().map_err(|_|"data lock")?.messages.insert(id.into(),json!({"conversation_id":"thread","message_id":id,"sender_id":"human-principal",
            "sender_device_id":"human-device","sender_root_commitment":"human-root","body_utf8":text,"created_at":1000,"deleted":false}));
        self.event("message.received",json!({"message":{"conversation_id":"thread","message_id":id,"sender_id":"human-principal"}})).await?;
        self.applied().await
    }
    pub async fn poll_clock(&self) -> TestResult {
        let clock = self.data.lock().map_err(|_| "data")?.clock;
        let data = Arc::clone(&self.data);
        wait(&self.changed, move || {
            data.lock().ok().filter(|d| d.polled_clock == clock).map(|_| ())
        })
        .await
    }
    pub async fn input(&mut self, server: &Server, id: &str) -> TestResult<Value> {
        let after = server.calls.lock().map_err(|_| "calls lock")?.len();
        self.enqueue(id).await?;
        server.wait_method("inbound.message", after).await
    }
    pub async fn stop(mut self) -> TestResult<Stopped> {
        if !self.task.is_finished() {
            self.event("account.locked", json!({})).await?;
        }
        let (host, result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.task).await??;
        assert!(
            matches!(result, Err(Error::IdentityLost)),
            "host did not stop on identity loss: {result:?}"
        );
        Ok(Stopped { host, root: self.root })
    }
    pub async fn transport_failure(self) -> TestResult<Stopped> {
        let (host, result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.task).await??;
        if !matches!(result, Err(crate::Error::Bus)) {
            return Err("expected the injected bus disconnect".into());
        }
        Ok(Stopped { host, root: self.root })
    }
    pub async fn applied(&self) -> TestResult {
        let sequence = self.sequence;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let bytes = std::fs::read(&self.config.state_file).ok();
                let state = bytes.and_then(|b| serde_json::from_slice::<Value>(&b).ok());
                if state.is_some_and(|s| s["cursor"].as_u64().is_some_and(|n| n >= sequence)) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}
pub(super) async fn fixture() -> TestResult<(tempfile::TempDir, Server, Host)> {
    let root =
        tempfile::Builder::new().prefix("rf-p-").tempdir_in(if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        })?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    let host = Host::start(&server, PrxAuthorization::Supervised).await?;
    server.wait_method("bridge.hello", 0).await?;
    Ok((root, server, host))
}
pub(super) fn params(input: &Value, key: &str) -> Value {
    json!({"conversation_id":"thread","turn_id":input["params"]["turn_id"],"idempotency_key":format!("{}:{key}",input["params"]["turn_id"].as_str().unwrap_or(""))})
}
pub(super) async fn finish(server: &Server, input: &Value, text: &str) -> TestResult {
    let mut p = params(input, "final-text");
    p["text"] = json!(text);
    p["final"] = json!(true);
    assert_eq!(server.call("reply.text", p).await?["result"]["ok"], true);
    let mut p = params(input, "done");
    p["state"] = json!("done");
    assert_eq!(server.call("turn.status", p).await?["result"]["ok"], true);
    Ok(())
}
pub(super) fn texts(data: &Data) -> TestResult<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    data.replies
        .iter()
        .filter(|r| seen.insert(r["message_id"].clone().to_string()))
        .map(|r| {
            Ok(String::from_utf8(ramflux_protocol::decode_base64url(
                r["plaintext_body_base64"].as_str().ok_or("text")?,
            )?)?)
        })
        .collect()
}
