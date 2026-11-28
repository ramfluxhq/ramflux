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
pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    #[cfg(feature = "itest-mls-debug")]
    {
        enabled::dispatch(request, state).await
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

    use super::{
        LocalBusDaemonState, LocalBusDispatchResult, LocalBusFrame, SdkError,
        local_bus_account_mut, local_bus_ok, request_account_id,
    };

    const MAX_EXPORT_LEN: usize = 1024;
    const MAX_KAT_BYTES: usize = 8 * 1024 * 1024;
    const MAX_PATHS: usize = 64;

    pub(super) async fn dispatch(
        request: &LocalBusFrame,
        state: &mut LocalBusDaemonState,
    ) -> Result<LocalBusDispatchResult, SdkError> {
        let account_id = request_account_id(request)?.to_owned();
        let method = request.method.clone();
        let body = request.body.clone();
        let account = local_bus_account_mut(state, &account_id)?;
        if let Some(value) = d5::handle(account, &method, &body).await? {
            return Ok(local_bus_ok(value));
        }
        let runtime = account.client.mls_runtime(&mut account.mls)?;
        let mut value = run(runtime.mls(), &method, &body).map_err(|error| refused(&error))?;
        if method == "debug.mls.status" {
            d5::enrich_status(&account.client, &body, &mut value)?;
        }
        Ok(local_bus_ok(value))
    }

    fn refused(error: &MlsError) -> SdkError {
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
        if !text.len().is_multiple_of(2) || text.len() > 2 * 1024 * 1024 {
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
            "self" => Ok(GroupKind::Own),
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
        let merged = mls.merge_own(&gid)?.commit_plain()?;
        write(&commit_path, &output.commit)?;
        write(&welcome_path, &output.welcome)?;
        Ok(json!({
            "epoch": merged.epoch,
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

    /// Stage the own commit, then merge it. The reply epoch is the epoch after the merge.
    fn stage_then_merge(
        mls: &Facade,
        gid: &[u8],
        staged: ramflux_mls::CommitOutput,
        out: &Path,
    ) -> Result<Value, MlsError> {
        let merged = mls.merge_own(gid)?.commit_plain()?;
        write(out, &staged.message)?;
        Ok(json!({
            "epoch": merged.epoch,
            "commit_bytes": staged.message.len(),
            "wire_format": wire_format(&staged.message),
        }))
    }

    fn update(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        match body.get("tamper").and_then(Value::as_str) {
            None => stage_then_merge(mls, &gid, mls.update(&gid)?.commit_plain()?, &out),
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
        stage_then_merge(mls, &gid, mls.commit_pending(&gid)?.commit_plain()?, &out)
    }

    fn remove(mls: &Facade, body: &Value) -> Result<Value, MlsError> {
        let gid = group_id(body)?;
        let out = out_path(body, "out_path")?;
        let leaf = u32::try_from(number(body, "leaf")?).map_err(|_| bad("leaf"))?;
        stage_then_merge(mls, &gid, mls.remove(&gid, leaf)?.commit_plain()?, &out)
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

    mod d5 {
        use ramflux_mls::{GroupKind, MlsError, WriteBatch, WriteOp};
        use ramflux_protocol::custody::DeviceRef;
        use serde_json::{Value, json};

        use super::{
            Facade, LocalBusAccountState, SdkError, bad, from_hex, group_id, number, text, to_hex,
        };
        use crate::mls::order::{
            CommitOutcome, ConvStore, DmGroupKind, DmOrderOp, DmSubmit, DmSubmitFlag, Scope,
        };
        use crate::mls::{SqlMlsKv, lifecycle};
        use crate::prelude::RamfluxClient;

        const SELF_UPDATE_CAP: u64 = 128;
        const DELIVER_CAP: usize = 256;
        const CONV_LABEL: &str = "mls/conv";
        const CONV_GROUP_LABEL: &str = "mls/conv_group";
        const DELIVER_PREFIX: &str = "mls-deliver-order/";

        pub(super) async fn handle(
            account: &mut LocalBusAccountState,
            method: &str,
            body: &Value,
        ) -> Result<Option<Value>, SdkError> {
            let value = match method {
                "debug.mls.welcome" => welcome(account, body).map_err(sdk_mls)?,
                "debug.mls.check_leaf" => check_leaf(account, body)?,
                "debug.mls.refresh_heads" => refresh_heads(account)?,
                "debug.mls.self_update" => self_update(account, body).await?,
                "debug.mls.drop_state" => drop_state(account, body).await?,
                "debug.mls.submit_at" => submit_at(account, body).await?,
                "debug.mls.create_as" => create_as(account, body).await?,
                "debug.mls.submit_garbage" => submit_garbage(account, body).await?,
                "debug.mls.leaf_age" => leaf_age(account, body)?,
                "debug.mls.deliver_reordered" => deliver_reordered(account, body)?,
                "debug.mls.seal_count" => seal_count(account, body)?,
                _ => return Ok(None),
            };
            Ok(Some(value))
        }

        pub(super) fn enrich_status(
            client: &RamfluxClient,
            body: &Value,
            reply: &mut Value,
        ) -> Result<(), SdkError> {
            let Some(hex_id) = body.get("group_id_hex").and_then(Value::as_str) else {
                return Ok(());
            };
            let gid = from_hex(hex_id).map_err(sdk_mls)?;
            let kv = open_kv(client)?;
            let store = ConvStore::new(&kv);
            let Some(scope_id) = store.scope_of(&gid)? else {
                insert_absent(reply);
                return Ok(());
            };
            let Some(state) = store.get(&scope_id)? else {
                insert_absent(reply);
                return Ok(());
            };
            let replaced_by = if state.group_id == gid {
                Value::Null
            } else if state.old.iter().any(|old| old.group_id == gid) {
                json!(to_hex(&state.group_id))
            } else {
                Value::Null
            };
            if let Some(object) = reply.as_object_mut() {
                object.insert("log_seq".to_owned(), json!(state.log_seq));
                object.insert("replaced_by".to_owned(), replaced_by);
                object.insert("generation".to_owned(), json!(state.generations));
            }
            Ok(())
        }

        fn insert_absent(reply: &mut Value) {
            if let Some(object) = reply.as_object_mut() {
                object.insert("log_seq".to_owned(), Value::Null);
                object.insert("replaced_by".to_owned(), Value::Null);
                object.insert("generation".to_owned(), Value::Null);
            }
        }

        fn sdk_mls(error: MlsError) -> SdkError {
            let code = error.code();
            SdkError::LocalBusRefused {
                code: code.to_owned(),
                message: error.to_string(),
                body: Box::new(json!({ "reason_code": code })),
            }
        }

        fn mls_err(error: SdkError) -> MlsError {
            MlsError::PolicyRejected(error.to_string())
        }

        fn open_kv(client: &RamfluxClient) -> Result<SqlMlsKv, SdkError> {
            Ok(SqlMlsKv::new(client.account_db()?.mls_kv()))
        }

        fn now_u64() -> u64 {
            u64::try_from(crate::time::now_unix_timestamp()).unwrap_or(0)
        }

        fn welcome(account: &LocalBusAccountState, body: &Value) -> Result<Value, MlsError> {
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot).map_err(mls_err)?;
            let mls = runtime.mls();
            match text(body, "tamper")? {
                "self_as_dm" => {
                    let anchor = account.client.own_account_anchor().map_err(mls_err)?;
                    let binding = ramflux_mls::RfConversation::own(&anchor);
                    let _created = mls
                        .create_with(GroupKind::Dm, None, Some(&binding), None)?
                        .commit_plain()?;
                    Err(bad("self_as_dm was accepted"))
                }
                "conversation_id" => welcome_other_conversation(mls, &account.client, body),
                other => Err(bad(&format!("unknown tamper {other}"))),
            }
        }

        fn welcome_other_conversation(
            mls: &Facade,
            client: &RamfluxClient,
            body: &Value,
        ) -> Result<Value, MlsError> {
            let own = client.own_account_anchor().map_err(mls_err)?;
            let peer = text(body, "peer")?;
            let other = text(body, "other")?;
            let binding = ramflux_mls::RfConversation::dm(&own, peer)?;
            let created =
                mls.create_with(GroupKind::Dm, None, Some(&binding), None)?.commit_plain()?;
            let package = mls.debug_key_package(GroupKind::Dm, None)?.commit_plain()?;
            let added = mls.add(&created.group_id, &[package.bytes])?.commit_plain()?;
            let expected = ramflux_mls::ExpectedPrincipals::dm(&own, other)?;
            let joined = mls.join_expecting(&added.welcome, &expected);
            let _ = mls.delete_group(&created.group_id).and_then(|staged| staged.commit_plain());
            match joined {
                Err(error) => Err(error),
                Ok(_staged) => Err(bad("welcome binding was accepted")),
            }
        }

        fn check_leaf(account: &LocalBusAccountState, body: &Value) -> Result<Value, SdkError> {
            let at = number(body, "at").map_err(sdk_mls)?;
            let anchor = account.client.own_account_anchor()?;
            let Some(branch) = account.client.device_branch.as_ref() else {
                return Ok(json!({ "state": "credential_expired" }));
            };
            let reference = DeviceRef {
                account_anchor: anchor.clone(),
                device_id: branch.device_id.clone(),
                device_epoch: branch.device_epoch,
            };
            let Some(record) = account.client.current_custody_authority(&anchor, at)? else {
                return Ok(json!({ "state": "credential_expired" }));
            };
            let state = if record.authorize(&reference, "message", at).is_ok() {
                "ok"
            } else {
                "credential_expired"
            };
            Ok(json!({ "state": state }))
        }

        fn refresh_heads(account: &mut LocalBusAccountState) -> Result<Value, SdkError> {
            account.mls = None;
            *account.client.verified_durable_authority.borrow_mut() = Default::default();
            let keys = account.client.account_db()?.actor_state_keys("identity/custody/")?;
            for key in &keys {
                account.client.account_db()?.remove_actor_state(key)?;
            }
            let _runtime = account.client.mls_runtime(&mut account.mls)?;
            Ok(json!({}))
        }

        async fn self_update(
            account: &mut LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let count = number(body, "count").map_err(sdk_mls)?;
            if count > SELF_UPDATE_CAP {
                return Err(sdk_mls(bad("count is above 128")));
            }
            let mut engine = account.session_client().await?;
            let (done, stopped) = {
                let kv = open_kv(&account.client)?;
                let store = ConvStore::new(&kv);
                let runtime = account.client.mls_runtime(&mut account.mls)?;
                let mls = runtime.mls();
                let gid = match body.get("group_id_hex").and_then(Value::as_str) {
                    Some(hex_id) => from_hex(hex_id).map_err(sdk_mls)?,
                    None => self_group_id(mls, &account.client)?,
                };
                let scope = scope_for(&store, mls, &gid)?;
                let mut done = 0_u64;
                let mut stopped = None;
                let now = now_u64();
                for _ in 0..count {
                    match lifecycle::update_own_leaf(&mut engine, mls, &store, &scope, now).await? {
                        CommitOutcome::Accepted { .. } => done = done.saturating_add(1),
                        other => {
                            stopped = Some(outcome_name(&other));
                            break;
                        }
                    }
                }
                (done, stopped)
            };
            account.apply_session_metadata(engine);
            match stopped {
                Some(stopped) => Ok(json!({ "updates": done, "stopped": stopped })),
                None => Ok(json!({ "updates": done })),
            }
        }

        fn self_group_id(mls: &Facade, client: &RamfluxClient) -> Result<Vec<u8>, SdkError> {
            let anchor = client.own_account_anchor()?;
            let scope = Scope::own(&anchor);
            let kv = open_kv(client)?;
            let store = ConvStore::new(&kv);
            let state = store.get(&scope.conversation_id)?.ok_or_else(|| SdkError::Mls {
                code: "not_found",
                detail: "the self group is absent".to_owned(),
            })?;
            let _ = mls.status(&state.group_id).map_err(sdk_mls)?;
            Ok(state.group_id)
        }

        fn scope_for(
            store: &ConvStore<'_, SqlMlsKv>,
            mls: &Facade,
            gid: &[u8],
        ) -> Result<Scope, SdkError> {
            let conversation_id = store.scope_of(gid)?.ok_or_else(|| SdkError::Mls {
                code: "not_found",
                detail: "the group has no conversation".to_owned(),
            })?;
            let kind = match mls.status(gid).map_err(sdk_mls)?.kind {
                GroupKind::Dm => DmGroupKind::Dm,
                GroupKind::Own => DmGroupKind::SelfGroup,
                GroupKind::Group => {
                    return Err(SdkError::Mls {
                        code: "policy_rejected",
                        detail: "debug.mls does not order a group".to_owned(),
                    });
                }
            };
            Ok(Scope { kind, conversation_id, anchors: Vec::new() })
        }

        fn outcome_name<T>(outcome: &CommitOutcome<T>) -> &'static str {
            match outcome {
                CommitOutcome::Accepted { .. } => "accepted",
                CommitOutcome::NotCurrent(_) => "not_current",
                CommitOutcome::EarlierPending => "earlier_pending",
                CommitOutcome::Pending { .. } => "pending",
                CommitOutcome::Lost => "lost",
                CommitOutcome::Forked => "forked",
                CommitOutcome::Replaced { .. } => "replaced",
            }
        }

        async fn drop_state(
            account: &mut LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let gid = gid_of(body).map_err(sdk_mls)?;
            {
                let mut slot = None;
                let runtime = account.client.mls_runtime(&mut slot)?;
                if let Err(error) =
                    runtime.mls().delete_group(&gid).and_then(|staged| staged.commit_plain())
                {
                    if error.code() != "not_found" {
                        return Err(sdk_mls(error));
                    }
                }
            }
            delete_conv_row(&account.client, &gid)?;
            account.client.seal_cache.borrow_mut().evict_group(&gid);
            account.mls = None;
            Ok(json!({}))
        }

        fn delete_conv_row(client: &RamfluxClient, gid: &[u8]) -> Result<(), SdkError> {
            let kv = open_kv(client)?;
            let store = ConvStore::new(&kv);
            let Some(scope_id) = store.scope_of(gid)? else {
                return Ok(());
            };
            let Some(state) = store.get(&scope_id)? else {
                return Ok(());
            };
            let mut ops = vec![WriteOp::Delete { label: CONV_LABEL.to_owned(), key: scope_id }];
            ops.push(WriteOp::Delete {
                label: CONV_GROUP_LABEL.to_owned(),
                key: state.group_id.clone(),
            });
            for old in &state.old {
                ops.push(WriteOp::Delete {
                    label: CONV_GROUP_LABEL.to_owned(),
                    key: old.group_id.clone(),
                });
            }
            kv.commit_batch(WriteBatch { ops, epoch_changed: false }, |_| Ok(()))
                .map_err(|error| SdkError::Mls { code: "internal", detail: error.to_string() })
        }

        async fn submit_at(
            account: &mut LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let gid = gid_of(body).map_err(sdk_mls)?;
            let offset = body.get("epoch_offset").and_then(Value::as_i64).unwrap_or(0);
            let tamper = body.get("header_tamper").and_then(Value::as_str);
            let (kind, scope_id, epoch) = head_of(account, &gid)?;
            let submit_epoch = apply_offset(epoch, offset).map_err(sdk_mls)?;
            let header_group = if tamper == Some("group_id") { flipped(&gid) } else { gid.clone() };
            let content_type = if tamper == Some("content_type") { 1 } else { 3 };
            let commit =
                private_commit(&header_group, submit_epoch, content_type).map_err(sdk_mls)?;
            let request = DmSubmit {
                group_id: gid,
                kind,
                scope_id,
                epoch: submit_epoch,
                commit,
                flag: None,
                nonce: Vec::new(),
                anchors: Vec::new(),
            };
            order_submit(account, DmOrderOp::Submit(request)).await
        }

        async fn submit_garbage(
            account: &mut LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let gid = gid_of(body).map_err(sdk_mls)?;
            let (kind, scope_id, epoch) = head_of(account, &gid)?;
            let mut commit = private_commit(&gid, epoch, 3).map_err(sdk_mls)?;
            commit.extend_from_slice(b"mls-debug-garbage");
            let request = DmSubmit {
                group_id: gid,
                kind,
                scope_id,
                epoch,
                commit,
                flag: None,
                nonce: Vec::new(),
                anchors: Vec::new(),
            };
            order_submit(account, DmOrderOp::Submit(request)).await
        }

        async fn create_as(
            account: &mut LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let scope_text = text(body, "scope").map_err(sdk_mls)?;
            let gid = gid_of(body).map_err(sdk_mls)?;
            let nonce = from_hex(text(body, "nonce").map_err(sdk_mls)?).map_err(sdk_mls)?;
            let kind = match body.get("kind").and_then(Value::as_str).unwrap_or("dm") {
                "dm" => DmGroupKind::Dm,
                "self" => DmGroupKind::SelfGroup,
                _ => return Err(sdk_mls(bad("kind must be dm or self"))),
            };
            let anchors = body
                .get("anchors")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter().filter_map(Value::as_str).map(str::to_owned).take(8).collect()
                })
                .unwrap_or_default();
            let commit = private_commit(&gid, 0, 3).map_err(sdk_mls)?;
            let request = DmSubmit {
                group_id: gid,
                kind,
                scope_id: scope_text.as_bytes().to_vec(),
                epoch: 0,
                commit,
                flag: Some(DmSubmitFlag::Create),
                nonce,
                anchors,
            };
            order_submit(account, DmOrderOp::Submit(request)).await
        }

        fn head_of(
            account: &mut LocalBusAccountState,
            gid: &[u8],
        ) -> Result<(DmGroupKind, Vec<u8>, u64), SdkError> {
            let kv = open_kv(&account.client)?;
            let store = ConvStore::new(&kv);
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot)?;
            let scope = scope_for(&store, runtime.mls(), gid)?;
            let epoch = runtime.mls().status(gid).map_err(sdk_mls)?.epoch;
            Ok((scope.kind, scope.conversation_id, epoch))
        }

        fn apply_offset(epoch: u64, offset: i64) -> Result<u64, MlsError> {
            if offset >= 0 {
                let shift = u64::try_from(offset).map_err(|_| bad("epoch_offset"))?;
                epoch.checked_add(shift).ok_or_else(|| bad("epoch_offset"))
            } else {
                let shift =
                    u64::try_from(offset.saturating_neg()).map_err(|_| bad("epoch_offset"))?;
                epoch.checked_sub(shift).ok_or_else(|| bad("epoch_offset"))
            }
        }

        fn flipped(gid: &[u8]) -> Vec<u8> {
            let mut copy = gid.to_vec();
            if let Some(first) = copy.first_mut() {
                *first ^= 0x01;
            }
            copy
        }

        fn gid_of(body: &Value) -> Result<Vec<u8>, MlsError> {
            if body.get("group_id_hex").and_then(Value::as_str).is_some() {
                return group_id(body);
            }
            from_hex(text(body, "group_id")?)
        }

        fn private_commit(
            group_id: &[u8],
            epoch: u64,
            content_type: u8,
        ) -> Result<Vec<u8>, MlsError> {
            let len = u8::try_from(group_id.len()).ok().filter(|len| *len > 0 && *len < 64);
            let Some(len) = len else {
                return Err(bad("group id length"));
            };
            let mut out = Vec::with_capacity(usize::from(len).saturating_add(16));
            out.extend_from_slice(&1_u16.to_be_bytes());
            out.extend_from_slice(&2_u16.to_be_bytes());
            out.push(len);
            out.extend_from_slice(group_id);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.push(content_type);
            out.extend_from_slice(&[0_u8, 0, 0, 1]);
            Ok(out)
        }

        async fn order_submit(
            account: &mut LocalBusAccountState,
            request: DmOrderOp,
        ) -> Result<Value, SdkError> {
            let mut engine = account.session_client().await?;
            let reply =
                crate::gateway::access::MlsFrameAccess::dm_order(&mut engine, request).await?;
            account.apply_session_metadata(engine);
            serde_json::to_value(reply)
                .map_err(|error| SdkError::Mls { code: "internal", detail: error.to_string() })
        }

        fn leaf_age(account: &mut LocalBusAccountState, body: &Value) -> Result<Value, SdkError> {
            let gid = gid_of(body).map_err(sdk_mls)?;
            let set_s = number(body, "set_s").map_err(sdk_mls)?;
            let kv = open_kv(&account.client)?;
            let store = ConvStore::new(&kv);
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot)?;
            let scope = scope_for(&store, runtime.mls(), &gid)?;
            let mut state = store.get(&scope.conversation_id)?.ok_or_else(|| SdkError::Mls {
                code: "not_found",
                detail: "the conversation has no MLS group".to_owned(),
            })?;
            state.leaf_updated_at = now_u64().saturating_sub(set_s);
            store.put(&scope.conversation_id, &state)?;
            Ok(json!({ "leaf_updated_at": state.leaf_updated_at }))
        }

        fn seal_count(account: &LocalBusAccountState, body: &Value) -> Result<Value, SdkError> {
            let gid = gid_of(body).map_err(sdk_mls)?;
            let kv = open_kv(&account.client)?;
            let store = ConvStore::new(&kv);
            let scope_id = store.scope_of(&gid)?.ok_or_else(|| SdkError::Mls {
                code: "not_found",
                detail: "the group has no conversation".to_owned(),
            })?;
            let state = store.get(&scope_id)?.ok_or_else(|| SdkError::Mls {
                code: "not_found",
                detail: "the conversation has no MLS group".to_owned(),
            })?;
            Ok(json!({ "generations": state.generations }))
        }

        fn deliver_reordered(
            account: &LocalBusAccountState,
            body: &Value,
        ) -> Result<Value, SdkError> {
            let conversation = text(body, "conversation").map_err(sdk_mls)?;
            let swap =
                body.get("swap").and_then(Value::as_array).ok_or_else(|| sdk_mls(bad("swap")))?;
            let first = swap.first().and_then(Value::as_u64).ok_or_else(|| sdk_mls(bad("swap")))?;
            let second = swap.get(1).and_then(Value::as_u64).ok_or_else(|| sdk_mls(bad("swap")))?;
            let key = format!("{DELIVER_PREFIX}{conversation}");
            let mut ids = if let Some(seed) = body.get("ids").and_then(Value::as_array) {
                seed.iter().filter_map(Value::as_str).map(str::to_owned).take(DELIVER_CAP).collect()
            } else {
                account
                    .client
                    .account_db()?
                    .load_actor_state::<DeliverOrder>(&key)?
                    .map(|row| row.ids)
                    .unwrap_or_default()
            };
            if ids.len() > DELIVER_CAP {
                ids.truncate(DELIVER_CAP);
            }
            swap_ids(&mut ids, first, second).map_err(sdk_mls)?;
            let expires_at = crate::time::now_unix_timestamp().saturating_add(86_400);
            account
                .client
                .account_db()?
                .persist_actor_state(&key, &DeliverOrder { ids: ids.clone(), expires_at })?;
            Ok(json!({ "order": ids }))
        }

        fn swap_ids(ids: &mut [String], first: u64, second: u64) -> Result<(), MlsError> {
            let left = usize::try_from(first).map_err(|_| bad("swap"))?;
            let right = usize::try_from(second).map_err(|_| bad("swap"))?;
            if left >= ids.len() || right >= ids.len() {
                return Err(bad("swap is outside the delivery order"));
            }
            if left == right {
                return Ok(());
            }
            let saved_left = ids.get(left).cloned().ok_or_else(|| bad("swap"))?;
            let saved_right = ids.get(right).cloned().ok_or_else(|| bad("swap"))?;
            if let Some(slot) = ids.get_mut(left) {
                *slot = saved_right;
            }
            if let Some(slot) = ids.get_mut(right) {
                *slot = saved_left;
            }
            Ok(())
        }

        #[derive(serde::Serialize, serde::Deserialize)]
        struct DeliverOrder {
            ids: Vec<String>,
            expires_at: i64,
        }
    }
}
