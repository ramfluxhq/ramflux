// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stream `--attach` files through prepare, then one conversation send.
//! Import writes plaintext only to the requested path.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ramflux_sdk::{LocalBusClient, LocalBusFrame, PlaintextDigester, SdkError};
use serde_json::{Value, json};

use crate::RfError;
use crate::cli::{
    AttachmentAction, AttachmentCommand, AttachmentEnable, AttachmentImport, DmSend, GroupSend,
};
use crate::utils::print_json;

const CHUNK: usize = 524_288;

/// # Errors
/// Returns a stable refusal code. A partial import file is removed.
pub(crate) async fn handle(socket: PathBuf, command: AttachmentCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        AttachmentAction::Import(import_command) => import(&mut bus, import_command).await,
        AttachmentAction::Enable(enable_command) => enable(&mut bus, enable_command).await,
    }
}

/// Pins the attachment authority for one account.
/// # Errors
/// Returns the stable refusal code.
pub(crate) async fn enable(
    bus: &mut LocalBusClient,
    command: AttachmentEnable,
) -> Result<(), RfError> {
    let mut seq = 0_u64;
    let response = ask(
        bus,
        &command.account,
        &mut seq,
        Route { api: "attachment", method: "attachment.enable", operation: "attachment-enable" },
        json!({
            "from_node": command.from_node,
            "source": command.source,
            "generation": command.generation,
            "public_key_hex": command.public_key_hex,
            "home_node_id": command.home_node_id,
        }),
    )
    .await?;
    print_json(&response)
}

/// Retired flags are a content refusal and are not read.
/// # Errors
/// Returns `content` when either retired flag is present.
pub(crate) fn refuse_retired(relay_url: bool, chunk_size: bool) -> Result<(), RfError> {
    if relay_url || chunk_size {
        return Err(RfError::Message("content".into()));
    }
    Ok(())
}

/// # Errors
/// Returns a stable refusal code. A partial import file is removed.
pub(crate) async fn send_dm(bus: &mut LocalBusClient, send: DmSend) -> Result<(), RfError> {
    send_files(Outgoing {
        bus,
        account: &send.account,
        message: &send.message,
        conversation: &send.conversation,
        caption: &send.body,
        files: &send.attach,
        kind: Kind::Dm { conversation: &send.conversation },
    })
    .await
}

/// # Errors
/// Returns a stable refusal code. A partial import file is removed.
pub(crate) async fn send_group(bus: &mut LocalBusClient, send: GroupSend) -> Result<(), RfError> {
    send_files(Outgoing {
        bus,
        account: &send.account,
        message: &send.message,
        conversation: &send.conversation,
        caption: &send.body,
        files: &send.attach,
        kind: Kind::Group { group: &send.group },
    })
    .await
}

enum Kind<'a> {
    Dm { conversation: &'a str },
    Group { group: &'a str },
}

struct Outgoing<'a> {
    bus: &'a mut LocalBusClient,
    account: &'a str,
    message: &'a str,
    conversation: &'a str,
    caption: &'a str,
    files: &'a [PathBuf],
    kind: Kind<'a>,
}

async fn send_files(outgoing: Outgoing<'_>) -> Result<(), RfError> {
    let Outgoing { bus, account, message, conversation, caption, files, kind } = outgoing;
    if files.is_empty() || files.len() > 16 {
        return Err(RfError::Message("layout_invalid".into()));
    }
    let mut prepares = Vec::with_capacity(files.len());
    let mut seq = 0_u64;
    for (index, path) in files.iter().enumerate() {
        let operation = format!("{message}:{index}");
        prepares.push(prepare_one(bus, account, &mut seq, &operation, path, &kind).await?);
    }
    let response = ask(
        bus,
        account,
        &mut seq,
        Route { api: "conversation", method: "conversation.send", operation: message },
        json!({
            "conversation_id": conversation,
            "group_id": match &kind { Kind::Group { group } => Some(*group), Kind::Dm { .. } => None },
            "text": caption,
            "prepares": prepares.iter().map(|id| json!({"prepare_id": id})).collect::<Vec<_>>(),
        }),
    )
    .await?;
    if response.get("delivery_state").and_then(Value::as_str) != Some("submitted") {
        return Err(RfError::Message(delivery_code(&response)));
    }
    print_json(&response)
}

async fn prepare_one(
    bus: &mut LocalBusClient,
    account: &str,
    seq: &mut u64,
    operation: &str,
    path: &Path,
    kind: &Kind<'_>,
) -> Result<String, RfError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RfError::Message("layout_invalid".into()))?;
    let mut body = json!({
        "operation_id": operation,
        "file_name": file_name,
        "mime": "application/octet-stream",
    });
    match kind {
        Kind::Dm { conversation } => {
            body["kind"] = json!("dm");
            body["peer"] = json!(conversation);
        }
        Kind::Group { group } => {
            body["kind"] = json!("group");
            body["group_id"] = json!(group);
        }
    }
    let begun = ask(
        bus,
        account,
        seq,
        Route { api: "attachment", method: "attachment.prepare.begin", operation },
        body,
    )
    .await?;
    let prepare_id = text(&begun, "prepare_id")?;
    let generation = number(&begun, "generation")?;
    if begun.get("state").and_then(Value::as_str) != Some("accepting") {
        // A retry of a send whose file the daemon already holds: the bytes must be the same
        // file, and nothing is streamed or finished a second time.
        let (length, digest) = digest_file(path)?;
        let same = begun.get("plaintext_length").and_then(Value::as_u64) == Some(length)
            && begun.get("plaintext_digest").and_then(Value::as_str)
                == Some(hex_bytes(&digest).as_str());
        return if same {
            Ok(prepare_id)
        } else {
            Err(RfError::Message("duplicate_operation".into()))
        };
    }
    let (length, digest) = stream_file(bus, account, seq, &prepare_id, generation, path).await?;
    ask(
        bus,
        account,
        seq,
        Route { api: "attachment", method: "attachment.prepare.finish", operation },
        json!({
            "prepare_id": prepare_id,
            "generation": generation,
            "plaintext_length": length,
            "plaintext_digest": hex_bytes(&digest),
        }),
    )
    .await?;
    Ok(prepare_id)
}

/// Length and digest of a local file, read in bounded chunks.
fn digest_file(path: &Path) -> Result<(u64, [u8; 32]), RfError> {
    let mut file = std::fs::File::open(path)?;
    let mut digester = PlaintextDigester::new();
    let mut total = 0_u64;
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let read = std::io::Read::read(&mut file, &mut buf)?;
        if read == 0 {
            return Ok((total, digester.finalize()));
        }
        digester.update(&buf[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
}

async fn stream_file(
    bus: &mut LocalBusClient,
    account: &str,
    seq: &mut u64,
    prepare_id: &str,
    generation: u64,
    path: &Path,
) -> Result<(u64, [u8; 32]), RfError> {
    let mut file = std::fs::File::open(path)?;
    let mut digester = PlaintextDigester::new();
    let mut offset = 0_u64;
    loop {
        let mut buf = vec![0_u8; CHUNK];
        let read = std::io::Read::read(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        digester.update(&buf[..read]);
        let taken = u64::try_from(read).map_err(|_| RfError::Message("file_too_large".into()))?;
        ask(
            bus,
            account,
            seq,
            Route { api: "attachment", method: "attachment.prepare.chunk", operation: prepare_id },
            json!({
                "prepare_id": prepare_id,
                "generation": generation,
                "offset": offset,
                "data_base64": ramflux_protocol::encode_base64url(&buf[..read]),
            }),
        )
        .await?;
        offset = offset.saturating_add(taken);
    }
    Ok((offset, digester.finalize()))
}

/// # Errors
/// Returns the stable code. A failed import removes only its own temporary file and never
/// touches an existing `--output`.
pub(crate) async fn import(
    bus: &mut LocalBusClient,
    command: AttachmentImport,
) -> Result<(), RfError> {
    let operation = format!("{}:import:{}", command.message, command.index);
    let mut seq = 0_u64;
    let begun = ask(
        bus,
        &command.account,
        &mut seq,
        Route { api: "attachment", method: "attachment.import.begin", operation: &operation },
        json!({"message_id": command.message, "index": command.index, "operation_id": operation}),
    )
    .await?;
    let import_id = text(&begun, "import_id")?;
    let generation = number(&begun, "generation")?;
    let expires = number(&begun, "expires_at")?;
    let result = stage_and_copy(
        bus,
        &command,
        &mut seq,
        &Handle { id: &import_id, generation, expires, operation: &operation },
    )
    .await;
    match result {
        Ok(staged) => staged.publish(),
        Err(error) => {
            // Best effort: free the daemon-side handle. The temporary file is already gone.
            let _ = ask(
                bus,
                &command.account,
                &mut seq,
                Route {
                    api: "attachment",
                    method: "attachment.import.cancel",
                    operation: &operation,
                },
                json!({"import_id": import_id}),
            )
            .await;
            Err(error)
        }
    }
}

struct Handle<'a> {
    id: &'a str,
    generation: u64,
    expires: u64,
    operation: &'a str,
}

async fn stage_and_copy(
    bus: &mut LocalBusClient,
    command: &AttachmentImport,
    seq: &mut u64,
    handle: &Handle<'_>,
) -> Result<StagedOutput, RfError> {
    wait_ready(bus, &command.account, seq, handle.id, handle.expires).await?;
    let staged = StagedOutput::create(&command.output)?;
    let staged = copy_out(bus, &command.account, seq, handle.id, handle.generation, staged).await?;
    ask(
        bus,
        &command.account,
        seq,
        Route {
            api: "attachment",
            method: "attachment.import.finish",
            operation: handle.operation,
        },
        json!({"import_id": handle.id}),
    )
    .await?;
    Ok(staged)
}

/// An owned temporary file beside the requested output. Only a finished import renames it
/// over `--output`; every failure removes this file and nothing else.
struct StagedOutput {
    file: Option<std::fs::File>,
    temp: PathBuf,
    target: PathBuf,
}

impl StagedOutput {
    fn create(target: &Path) -> Result<Self, RfError> {
        let parent = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        std::fs::create_dir_all(&parent)?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| RfError::Message("path_refused".into()))?;
        let mut attempt = 0_u32;
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| RfError::Message("expired".into()))?
                .subsec_nanos();
            let temp =
                parent.join(format!(".{name}.{}.{nanos}.{attempt}.rf-import", std::process::id()));
            match open_new(&temp) {
                Ok(file) => {
                    return Ok(Self { file: Some(file), temp, target: target.to_path_buf() });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                    attempt += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), RfError> {
        let file = self.file.as_mut().ok_or_else(|| RfError::Message("seal_failed".into()))?;
        std::io::Write::write_all(file, bytes)?;
        Ok(())
    }

    fn publish(mut self) -> Result<(), RfError> {
        let file = self.file.take().ok_or_else(|| RfError::Message("seal_failed".into()))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.temp, &self.target)?;
        if let Some(parent) = self.target.parent().filter(|parent| !parent.as_os_str().is_empty())
            && let Ok(directory) = std::fs::File::open(parent)
        {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

#[cfg(unix)]
fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

async fn wait_ready(
    bus: &mut LocalBusClient,
    account: &str,
    seq: &mut u64,
    import_id: &str,
    expires: u64,
) -> Result<(), RfError> {
    loop {
        let status = ask(
            bus,
            account,
            seq,
            Route { api: "attachment", method: "attachment.import.status", operation: import_id },
            json!({"import_id": import_id}),
        )
        .await?;
        if status.get("state").and_then(Value::as_str) == Some("ready") {
            return Ok(());
        }
        if unix_now()? >= expires {
            return Err(RfError::Message("expired".into()));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn copy_out(
    bus: &mut LocalBusClient,
    account: &str,
    seq: &mut u64,
    import_id: &str,
    generation: u64,
    mut staged: StagedOutput,
) -> Result<StagedOutput, RfError> {
    let mut offset = 0_u64;
    loop {
        let body = ask(
            bus,
            account,
            seq,
            Route { api: "attachment", method: "attachment.import.read", operation: import_id },
            json!({
                "import_id": import_id,
                "generation": generation,
                "offset": offset,
                "max_bytes": CHUNK,
            }),
        )
        .await?;
        let encoded = text(&body, "bytes")?;
        let bytes = ramflux_protocol::decode_base64url(&encoded)
            .map_err(|_| RfError::Message("seal_failed".into()))?;
        staged.write(&bytes)?;
        offset = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if body.get("eof").and_then(Value::as_bool).unwrap_or(false) {
            return Ok(staged);
        }
    }
}

struct Route<'a> {
    api: &'a str,
    method: &'a str,
    operation: &'a str,
}

async fn ask(
    bus: &mut LocalBusClient,
    account: &str,
    seq: &mut u64,
    route: Route<'_>,
    body: Value,
) -> Result<Value, RfError> {
    call(Call {
        bus,
        account,
        seq,
        api: route.api,
        method: route.method,
        operation: route.operation,
        body,
    })
    .await
}

struct Call<'a> {
    bus: &'a mut LocalBusClient,
    account: &'a str,
    seq: &'a mut u64,
    api: &'a str,
    method: &'a str,
    operation: &'a str,
    body: Value,
}

async fn call(mut input: Call<'_>) -> Result<Value, RfError> {
    let saved = input.body.clone();
    match send(&mut input).await {
        Ok(value) => Ok(value),
        Err(error @ RfError::Message(_)) => Err(error),
        Err(_) => {
            input.body = saved;
            send(&mut input).await
        }
    }
}

async fn send(call: &mut Call<'_>) -> Result<Value, RfError> {
    *call.seq = call.seq.saturating_add(1);
    let body = std::mem::take(&mut call.body);
    let mut frame = LocalBusFrame::request(
        format!("attach-{}-{}", call.method, call.seq),
        Some(call.account.to_owned()),
        call.api,
        call.method,
        body,
    );
    frame.operation_id = Some(call.operation.to_owned());
    match call.bus.request_frame_structured(frame).await {
        Ok(value) => Ok(value),
        Err(SdkError::LocalBusRefused { code, .. }) => Err(RfError::Message(code)),
        Err(other) => Err(other.into()),
    }
}

fn text(value: &Value, field: &str) -> Result<String, RfError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| RfError::Message("layout_invalid".into()))
}

fn number(value: &Value, field: &str) -> Result<u64, RfError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| RfError::Message("layout_invalid".into()))
}

fn delivery_code(response: &Value) -> String {
    response
        .get("deliveries")
        .and_then(Value::as_array)
        .and_then(|rows| rows.iter().find_map(|row| row.get("error_code").and_then(Value::as_str)))
        .unwrap_or("upload_rejected")
        .to_owned()
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn unix_now() -> Result<u64, RfError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RfError::Message("expired".into()))?;
    Ok(elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{StagedOutput, refuse_retired};

    #[test]
    fn retired_attach_flags_are_content_refusals() {
        assert!(refuse_retired(true, false).is_err());
        assert!(refuse_retired(false, true).is_err());
        assert!(refuse_retired(false, false).is_ok());
    }

    #[test]
    fn a_failed_import_keeps_the_existing_output() -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_test_support::TestPath::new()?.child("keep");
        std::fs::create_dir_all(&root)?;
        let target = root.join("report.bin");
        std::fs::write(&target, b"earlier file")?;
        let mut staged = StagedOutput::create(&target)?;
        staged.write(b"partial plaintext")?;
        drop(staged);
        assert_eq!(
            std::fs::read(&target)?,
            b"earlier file",
            "a failed import must not touch the earlier output"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".rf-import"))
            .collect();
        assert!(leftovers.is_empty(), "the temporary file is removed: {leftovers:?}");
        Ok(())
    }

    #[test]
    fn a_failure_before_any_output_creates_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_test_support::TestPath::new()?.child("absent");
        std::fs::create_dir_all(&root)?;
        let target = root.join("never.bin");
        drop(StagedOutput::create(&target)?);
        assert!(!target.exists(), "no output file exists after a failed import");
        Ok(())
    }

    #[test]
    fn a_finished_import_replaces_the_output_atomically() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = ramflux_test_support::TestPath::new()?.child("done");
        std::fs::create_dir_all(&root)?;
        let target = root.join("report.bin");
        std::fs::write(&target, b"older")?;
        let mut staged = StagedOutput::create(&target)?;
        staged.write(b"new bytes")?;
        staged.publish()?;
        assert_eq!(std::fs::read(&target)?, b"new bytes", "the finished import is published");
        Ok(())
    }
}
