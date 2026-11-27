// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hidden `debug.mls.*` bus methods (MLS-0c). The methods are registered in the method table so
//! the router knows them, but they are local-bus only (never in the C ABI policy) and every
//! handler answers the typed `debug_disabled` unless the SDK is built with `itest-mls-debug`.
//!
//! Blobs (`KeyPackages`, Welcomes, commits, proposals, messages) are file paths: the local bus
//! frame is 1 MiB. Input files must be regular files under the MLS size bound, output files are
//! created with `create_new` and mode 0600.

use crate::prelude::*;

/// Route one `debug.mls.*` request.
pub(crate) fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    #[cfg(feature = "itest-mls-debug")]
    {
        enabled::dispatch(request, state)
    }
    #[cfg(not(feature = "itest-mls-debug"))]
    {
        let _ = (request, state);
        Err(SdkError::LocalBusRefused {
            code: "debug_disabled".to_owned(),
            message: "debug.mls requires an itest-mls-debug build".to_owned(),
            body: Box::new(serde_json::json!({ "reason_code": "debug_disabled" })),
        })
    }
}

#[cfg(feature = "itest-mls-debug")]
mod enabled {
    use std::path::{Path, PathBuf};

    use ramflux_mls::debug::{KeyPackageTamper, read_blob, read_message_blob, write_blob};
    use ramflux_mls::{
        GroupKind, MAX_KEY_PACKAGE_BYTES, MemberSummary, MlsError, ReceivedMessage, Tier,
    };
    use serde_json::{Value, json};

    use super::*;

    const MAX_EXPORT_LEN: usize = 1024;
    const MAX_KAT_BYTES: usize = 8 * 1024 * 1024;
    const MAX_PATHS: usize = 64;

    pub(super) fn dispatch(
        request: &LocalBusFrame,
        state: &mut LocalBusDaemonState,
    ) -> Result<LocalBusDispatchResult, SdkError> {
        let account_id = request_account_id(request)?.to_owned();
        let account = local_bus_account_mut(state, &account_id)?;
        let body = &request.body;
        let method = request.method.as_str();
        let runtime = account.client.mls_runtime(&mut account.mls)?;
        let mls = runtime.mls();
        let value = run(mls, method, body).map_err(refused)?;
        Ok(local_bus_ok(value))
    }

    fn refused(error: MlsError) -> SdkError {
        let code = error.code();
        SdkError::LocalBusRefused {
            code: code.to_owned(),
            message: error.to_string(),
            body: Box::new(json!({ "reason_code": code })),
        }
    }

    fn bad(what: &str) -> MlsError {
        MlsError::PolicyRejected(format!("debug.mls request: {what}"))
    }

    type Facade = ramflux_mls::Mls<crate::mls::SqlMlsKv>;

    fn run(mls: &Facade, method: &str, body: &Value) -> Result<Value, MlsError> {
        match method {
            "debug.mls.key_package" => key_package(mls, body),
            "debug.mls.create" => create(mls, body),
            "debug.mls.add" => add(mls, body),
            "debug.mls.bulk_add" => bulk_add(mls, body),
            "debug.mls.join" => join(mls, body),
            "debug.mls.send" => send(mls, body),
            "debug.mls.receive" => receive(mls, body),
            "debug.mls.update" => update(mls, body),
            "debug.mls.leave" => leave(mls, body),
            "debug.mls.commit_pending" => commit_pending(mls, body),
            "debug.mls.remove" => remove(mls, body),
            "debug.mls.status" => status(mls, body),
            "debug.mls.export" => export(mls, body),
            "debug.mls.kat" => kat(body),
            "debug.mls.trust_pinned" => trust_pinned(mls, body),
            other => Err(bad(&format!("unknown method {other}"))),
        }
    }

    fn text<'a>(body: &'a Value, field: &str) -> Result<&'a str, MlsError> {
        body.get(field).and_then(Value::as_str).ok_or_else(|| bad(&format!("{field} is required")))
    }

    fn number(body: &Value, field: &str) -> Result<u64, MlsError> {
        body.get(field).and_then(Value::as_u64).ok_or_else(|| bad(&format!("{field} is required")))
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    fn from_hex(text: &str) -> Result<Vec<u8>, MlsError> {
        if text.len() % 2 != 0 || text.len() > 2 * 1024 * 1024 {
            return Err(bad("hex value has an invalid length"));
        }
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                    .ok_or_else(|| bad("hex value has a non-hex digit"))
            })
            .collect()
    }

    fn group_id(body: &Value) -> Result<Vec<u8>, MlsError> {
        from_hex(text(body, "group_id_hex")?)
    }

    fn abs_path(body: &Value, field: &str) -> Result<PathBuf, MlsError> {
        let path = PathBuf::from(text(body, field)?);
        if path.is_absolute() { Ok(path) } else { Err(bad(&format!("{field} must be absolute"))) }
    }

    /// An output path that does not exist yet (checked before the operation changes any state;
    /// the write itself uses `create_new`).
    fn out_path(body: &Value, field: &str) -> Result<PathBuf, MlsError> {
        let path = abs_path(body, field)?;
        if path.symlink_metadata().is_ok() {
            return Err(bad(&format!("{field} already exists")));
        }
        Ok(path)
    }

    fn write(path: &Path, bytes: &[u8]) -> Result<(), MlsError> {
        write_blob(path, bytes)
    }

    /// Wire format name of a TLS-encoded `MLSMessage` (RFC 9420 section 6: version, wire format).
    fn wire_format(message: &[u8]) -> &'static str {
        match message.get(2..4) {
            Some([0, 1]) => "PublicMessage",
            Some([0, 2]) => "PrivateMessage",
            Some([0, 3]) => "Welcome",
            Some([0, 4]) => "GroupInfo",
            Some([0, 5]) => "KeyPackage",
            _ => "unknown",
        }
    }

    fn kind(body: &Value) -> Result<GroupKind, MlsError> {
        match text(body, "kind")? {
            "device" | "dm" => Ok(GroupKind::Dm),
            "pseudonym" | "group" => Ok(GroupKind::Group),
            other => Err(bad(&format!("unknown kind {other}"))),
        }
    }

    fn members(list: &[MemberSummary]) -> Vec<Value> {
        list.iter()
            .map(|member| {
                let mut entry = json!({ "leaf": member.leaf, "revoked": member.revoked });
                if let Some(root) = &member.root_commitment {
                    entry["root_commitment"] = json!(root);
                }
                if let Some(device) = &member.device_id {
                    entry["device_id"] = json!(device);
                }
                entry
            })
            .collect()
    }

    fn key_package(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let out = out_path(body, "out_path")?;
        let tamper = match body.get("tamper").and_then(Value::as_str) {
            None => None,
            Some("credential") => Some(KeyPackageTamper::Credential),
            Some("transplant") => Some(KeyPackageTamper::Transplant),
            Some("suite") => Some(KeyPackageTamper::Suite),
            Some(other) => return Err(bad(&format!("unknown tamper {other}"))),
        };
        let output = mls.debug_key_package(kind(body)?, tamper)?.commit_plain()?;
        write(&out, &output.bytes)?;
        Ok(json!({
            "leaf_sig_pk_hex": to_hex(&output.leaf_sig_pk),
            "credential_bytes": output.credential_bytes,
        }))
    }

    fn create(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let kind = kind(body)?;
        let tier = match body.get("tier") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|members| u32::try_from(members).ok())
                    .and_then(Tier::from_members)
                    .ok_or_else(|| bad("tier must be 1000 or 5000"))?,
            ),
        };
        let output = mls.create(kind, tier)?.commit_plain()?;
        Ok(json!({
            "group_id_hex": to_hex(&output.group_id),
            "epoch": output.epoch,
            "leaf_cap": output.leaf_cap,
            "leaf_sig_pk_hex": to_hex(&output.leaf_sig_pk),
        }))
    }

    fn add(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let commit_path = out_path(body, "commit_path")?;
        let welcome_path = out_path(body, "welcome_path")?;
        let paths = body
            .get("key_package_paths")
            .and_then(Value::as_array)
            .filter(|paths| !paths.is_empty() && paths.len() <= MAX_PATHS)
            .ok_or_else(|| bad("key_package_paths needs 1 to 64 entries"))?;
        let mut key_packages = Vec::with_capacity(paths.len());
        for path in paths {
            let path = path.as_str().map(PathBuf::from).filter(|path| path.is_absolute());
            let path = path.ok_or_else(|| bad("key_package_paths entries must be absolute"))?;
            key_packages.push(read_blob(&path, MAX_KEY_PACKAGE_BYTES)?);
        }
        let output = mls.add(&gid, &key_packages)?.commit_plain()?;
        write(&commit_path, &output.commit)?;
        write(&welcome_path, &output.welcome)?;
        Ok(json!({
            "epoch": output.epoch,
            "commit_bytes": output.commit.len(),
            "welcome_bytes": output.welcome.len(),
        }))
    }

    fn bulk_add(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let count = usize::try_from(number(body, "count")?).map_err(|_| bad("count"))?;
        let batch = usize::try_from(number(body, "batch")?).map_err(|_| bad("batch"))?;
        // `commit_path` is accepted for card compatibility; the synthetic commits are not kept
        // (their Welcomes are discarded, so nobody could apply them).
        let output = mls.bulk_add(&gid, count, batch)?.commit_plain()?;
        Ok(json!({
            "epoch": output.epoch,
            "leaves": output.leaves,
            "commits": output.commits,
            "max_commit_bytes": output.max_commit_bytes,
            "max_welcome_bytes": output.max_welcome_bytes,
            "total_ms": u64::try_from(output.total_ms).unwrap_or(u64::MAX),
        }))
    }

    fn join(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let welcome = read_message_blob(&abs_path(body, "welcome_path")?)?;
        let output = mls.join(&welcome)?.commit_plain()?;
        Ok(json!({
            "group_id_hex": to_hex(&output.group_id),
            "kind": output.kind.as_str(),
            "epoch": output.epoch,
            "leaves": output.leaves,
            "members": members(&output.members),
        }))
    }

    fn send(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        let aad = match body.get("aad_hex").and_then(Value::as_str) {
            Some(hex) => from_hex(hex)?,
            None => Vec::new(),
        };
        let output = mls.send(&gid, text(body, "text")?.as_bytes(), &aad)?.commit_plain()?;
        write(&out, &output.message)?;
        Ok(json!({ "wire_format": wire_format(&output.message), "epoch": output.epoch }))
    }

    fn receive(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let message = read_message_blob(&abs_path(body, "message_path")?)?;
        // The plaintext is released only after the state was flushed.
        Ok(match mls.receive(&message)?.commit_plain()? {
            ReceivedMessage::Application { plaintext, aad, sender_leaf, epoch } => json!({
                "kind": "application",
                "text": String::from_utf8_lossy(&plaintext),
                "aad_hex": to_hex(&aad),
                "sender_leaf": sender_leaf,
                "epoch": epoch,
            }),
            ReceivedMessage::Commit { epoch, removed } => {
                json!({ "kind": "commit", "epoch": epoch, "removed": removed })
            }
            ReceivedMessage::Proposal { sender_leaf, epoch } => {
                json!({ "kind": "proposal", "sender_leaf": sender_leaf, "epoch": epoch })
            }
            ReceivedMessage::Own { epoch } => json!({ "kind": "own", "epoch": epoch }),
        })
    }

    fn commit_reply(output: &ramflux_mls::CommitOutput, out: &Path) -> Result<Value, MlsError> {
        write(out, &output.message)?;
        Ok(json!({
            "epoch": output.epoch,
            "commit_bytes": output.message.len(),
            "wire_format": wire_format(&output.message),
        }))
    }

    fn update(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        match body.get("tamper").and_then(Value::as_str) {
            None => commit_reply(&mls.update(&gid)?.commit_plain()?, &out),
            Some("credential") => commit_reply(&mls.tampered_update(&gid)?, &out),
            Some(other) => Err(bad(&format!("unknown tamper {other}"))),
        }
    }

    fn leave(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        let output = mls.leave(&gid)?.commit_plain()?;
        write(&out, &output.message)?;
        Ok(json!({}))
    }

    fn commit_pending(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        commit_reply(&mls.commit_pending(&gid)?.commit_plain()?, &out)
    }

    fn remove(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        let leaf = u32::try_from(number(body, "leaf")?).map_err(|_| bad("leaf"))?;
        commit_reply(&mls.remove(&gid, leaf)?.commit_plain()?, &out)
    }

    fn status(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let Some(gid) = body.get("group_id_hex").and_then(Value::as_str) else {
            let rows = mls.row_stats()?;
            return Ok(json!({
                "kv_rows": rows.rows,
                "largest_value_bytes": rows.largest_value_bytes,
            }));
        };
        let status = mls.status(&from_hex(gid)?)?;
        let mut reply = json!({
            "epoch": status.epoch,
            "kind": status.kind.as_str(),
            "leaf_cap": status.leaf_cap,
            "own_leaf": status.own_leaf,
            "own_sig_pk_hex": to_hex(&status.own_sig_pk),
            "leaves": status.leaves,
            "members": members(&status.members),
            "kv_rows": status.rows.rows,
            "largest_value_bytes": status.rows.largest_value_bytes,
        });
        if let Some(tier) = status.tier {
            reply["tier"] = json!(tier.members());
        }
        Ok(reply)
    }

    fn export(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let len = usize::try_from(number(body, "len")?).map_err(|_| bad("len"))?;
        if len == 0 || len > MAX_EXPORT_LEN {
            return Err(bad("len must be 1 to 1024"));
        }
        let context = match body.get("context_hex").and_then(Value::as_str) {
            Some(hex) => from_hex(hex)?,
            None => Vec::new(),
        };
        let secret = mls.export(&gid, text(body, "label")?, &context, len)?;
        // Secrets are never printed: only their BLAKE3 digest leaves the daemon.
        Ok(json!({ "blake3_hex": blake3::hash(&secret).to_hex().to_string() }))
    }

    fn kat(body: &Value) -> Result<Value, MlsError> {
        let json_bytes = read_blob(&abs_path(body, "path")?, MAX_KAT_BYTES)?;
        let handle = crate::mls::process_crypto()
            .map_err(|_| MlsError::Internal("crypto provider is not initialised".to_owned()))?;
        let report = ramflux_mls::kat::run_crypto_basics(handle.crypto(), &json_bytes)?;
        Ok(json!({
            "run": report.run,
            "passed": report.passed,
            "failed": report.failed,
        }))
    }

    fn trust_pinned(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let key = from_hex(text(body, "sig_pk_hex")?)?;
        if key.len() != 32 {
            return Err(bad("sig_pk_hex must be 32 bytes"));
        }
        mls.trust_pinned(&key)?;
        Ok(json!({}))
    }
}
