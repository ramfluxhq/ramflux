// SPDX-License-Identifier: BSD-3-Clause
//! Render each case through the signed library and compare the committed files.
use crate::cases::{self, Case};
use ramflux_card::{AcceptancePolicy, CardSession, CardSpec, SignedPackage};
use ramflux_protocol::a2ui::{SurfaceSnapshot, SurfaceState};
use serde_json::{Map, Value, json};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_FILE: usize = 256 * 1024;
const README: &str = "README.md";

struct Rendered {
    input_path: String,
    input: Vec<u8>,
    expected_path: String,
    expected: Vec<u8>,
    row: Value,
}

pub(crate) fn signed_library() -> Result<SignedPackage, String> {
    let bytecode = include_bytes!("../../../../ramflux-sdk/include/card/library.qjb");
    let descriptor = include_bytes!("../../../../ramflux-sdk/include/card/library.descriptor.json");
    let signature = exact::<64>(
        include_bytes!("../../../../ramflux-sdk/include/card/library.sig"),
        "signature",
    )?;
    let key = exact::<32>(
        include_bytes!("../../../../ramflux-sdk/include/card/library.pub"),
        "public key",
    )?;
    let policy: AcceptancePolicy =
        serde_json::from_slice(include_bytes!("../../../../ramflux-sdk/include/card/policy.json"))
            .map_err(|error| error.to_string())?;
    SignedPackage::verify(bytecode, descriptor, &signature, &key, &policy)
        .map_err(|error| error.to_string())
}

pub(crate) fn write_all(package: &SignedPackage, catalog: &[Case]) -> Result<(), String> {
    let rendered = render_all(package, catalog)?;
    let dir = fixtures_dir();
    for item in &rendered {
        write_generated(&dir, &item.input_path, &item.input)?;
        write_generated(&dir, &item.expected_path, &item.expected)?;
    }
    write_generated(&dir, "index.json", &index_bytes(&rendered)?)?;
    remove_stale(&dir, &allowed(&rendered))?;
    Ok(())
}

pub(crate) fn check_all(package: &SignedPackage, catalog: &[Case]) -> Result<(), String> {
    let rendered = render_all(package, catalog)?;
    let dir = fixtures_dir();
    for item in &rendered {
        compare(&dir, &item.input_path, &item.input)?;
        compare(&dir, &item.expected_path, &item.expected)?;
    }
    compare(&dir, "index.json", &index_bytes(&rendered)?)?;
    let extra = unexpected(&dir, &allowed(&rendered))?;
    if extra.is_empty() {
        Ok(())
    } else {
        Err(format!("unexpected fixture files: {}", extra.join(", ")))
    }
}

fn render_all(package: &SignedPackage, catalog: &[Case]) -> Result<Vec<Rendered>, String> {
    catalog.iter().map(|case| render_one(package, case)).collect()
}

fn render_one(package: &SignedPackage, case: &Case) -> Result<Rendered, String> {
    let snapshot = snapshot(&case.components, &case.data_model);
    match case.expect.as_str() {
        "tree" => render_tree(package, case, snapshot),
        "refused" => render_refusal(case, &snapshot),
        _ => Err(format!("{}: expect is tree or refused", case.kind)),
    }
}

fn render_tree(
    package: &SignedPackage,
    case: &Case,
    snapshot: SurfaceSnapshot,
) -> Result<Rendered, String> {
    let label = label(case);
    let state = SurfaceState::from_authorized_snapshot("conversation", 1, snapshot)
        .map_err(|error| format!("{label}: {error}"))?;
    let hash = state.hash().ok_or_else(|| format!("{label}: missing hash"))?.to_owned();
    let admitted = state.content().ok_or_else(|| format!("{label}: missing snapshot"))?.clone();
    let input = envelope(&admitted, &hash)?;
    let spec = CardSpec::parse(&input).map_err(|error| format!("{label}: {error}"))?;
    let (session, _) =
        CardSession::open(spec, package.clone()).map_err(|error| format!("{label}: {error}"))?;
    let tree = session.tree().ok_or_else(|| format!("{label}: missing tree"))?;
    let mut value = serde_json::to_value(tree).map_err(|error| error.to_string())?;
    canonicalize(&mut value, 0)?;
    let expected = document(&serde_json::to_vec(&value).map_err(|error| error.to_string())?);
    Ok(rendered(case, document(&input), "tree.json", expected, "tree"))
}

fn render_refusal(case: &Case, snapshot: &SurfaceSnapshot) -> Result<Rendered, String> {
    let label = label(case);
    let hash = snapshot.hash().map_err(|error| format!("{label}: {error}"))?;
    let input = envelope(snapshot, &hash)?;
    let error = match CardSpec::parse(&input) {
        Ok(_) => return Err(format!("{label}: admission succeeded")),
        Err(error) => error.to_string(),
    };
    let body = serde_json::to_vec(&json!({"error": error, "outcome": "refused"}))
        .map_err(|error| error.to_string())?;
    Ok(rendered(case, document(&input), "refusal.json", document(&body), "refused"))
}

fn rendered(
    case: &Case,
    input: Vec<u8>,
    suffix: &str,
    expected: Vec<u8>,
    outcome: &str,
) -> Rendered {
    let stem = cases::stem(case);
    let input_path = format!("{stem}.input.json");
    let expected_path = format!("{stem}.{suffix}");
    let row = json!({
        "kind": case.kind,
        "variant": case.variant,
        "fixture": input_path,
        "expected": expected_path,
        "outcome": outcome,
    });
    Rendered { input_path, input, expected_path, expected, row }
}

fn snapshot(components: &[Value], data_model: &Value) -> SurfaceSnapshot {
    let mut components = components.to_vec();
    components.sort_by(|left, right| component_id(left).cmp(component_id(right)));
    SurfaceSnapshot {
        surface_id: "surface".into(),
        catalog_id: ramflux_protocol::a2ui::CATALOG_ID.into(),
        fallback_text: "Card example".into(),
        metadata: None,
        components,
        data_model: data_model.clone(),
        final_: Vec::new(),
        closed: false,
    }
}

fn envelope(snapshot: &SurfaceSnapshot, hash: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({
        "author_principal_id": "own-agent",
        "conversation_id": "conversation",
        "render_allowed": true,
        "signed_hash": hash,
        "signed_version": 1,
        "snapshot": snapshot,
        "surface_ref": "surface",
    }))
    .map_err(|error| error.to_string())
}

fn index_bytes(rendered: &[Rendered]) -> Result<Vec<u8>, String> {
    let rows = rendered.iter().map(|item| item.row.clone()).collect::<Vec<_>>();
    let mut index = Map::new();
    index.insert("schema".into(), json!("ramflux.card.host_fixtures.v1"));
    index.insert("abi".into(), json!(ramflux_card::HOST_ABI));
    index.insert("catalog".into(), json!(ramflux_protocol::a2ui::CATALOG_ID));
    index.insert("locale".into(), json!(cases::LOCALE_FIXTURE_HOOK));
    index.insert(
        "locale_hook".into(),
        json!(
            "LOCALE_FIXTURE_HOOK stays en. Add launch-locale rows only after the resolver accepts them."
        ),
    );
    index.insert("cases".into(), Value::Array(rows));
    let bytes = serde_json::to_vec(&Value::Object(index)).map_err(|error| error.to_string())?;
    Ok(document(&bytes))
}

fn canonicalize(value: &mut Value, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("resolved tree is too deep".into());
    }
    match value {
        Value::Array(items) => {
            for item in items {
                canonicalize(item, depth + 1)?;
            }
        }
        Value::Object(map) => canonicalize_object(map, depth)?,
        _ => {}
    }
    Ok(())
}

fn canonicalize_object(map: &mut Map<String, Value>, depth: usize) -> Result<(), String> {
    if let Some(session) = map.get_mut("session")
        && session.is_number()
    {
        *session = json!(1);
    }
    if let Some(Value::String(raw)) = map.get("request_id").cloned() {
        let mut parsed =
            serde_json::from_str(&raw).map_err(|_| "request_id is not JSON".to_owned())?;
        canonicalize(&mut parsed, depth + 1)?;
        let next = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
        map.insert("request_id".into(), Value::String(next));
    }
    for (key, child) in map.iter_mut() {
        if key != "request_id" {
            canonicalize(child, depth + 1)?;
        }
    }
    Ok(())
}

fn write_generated(dir: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn compare(dir: &Path, relative: &str, expected: &[u8]) -> Result<(), String> {
    let path = dir.join(relative);
    let actual = read_bounded(&path)?;
    if actual == expected { Ok(()) } else { Err(format!("fixture drift: {relative}")) }
}

fn allowed(rendered: &[Rendered]) -> Vec<String> {
    let mut paths = vec![README.to_owned(), "index.json".to_owned()];
    for item in rendered {
        paths.push(item.input_path.clone());
        paths.push(item.expected_path.clone());
    }
    paths.sort();
    paths
}

fn unexpected(dir: &Path, allowed: &[String]) -> Result<Vec<String>, String> {
    Ok(list_files(dir)?.into_iter().filter(|path| !allowed.contains(path)).collect())
}

fn remove_stale(dir: &Path, allowed: &[String]) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for relative in unexpected(dir, allowed)? {
        fs::remove_file(dir.join(&relative)).map_err(|error| format!("{relative}: {error}"))?;
    }
    Ok(())
}

fn list_files(dir: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    if dir.exists() {
        walk(dir, dir, &mut found, 0)?;
    }
    found.sort();
    Ok(found)
}

fn walk(root: &Path, dir: &Path, found: &mut Vec<String>, depth: usize) -> Result<(), String> {
    if depth > 4 || found.len() > 200 {
        return Err("fixture directory is unbounded".into());
    }
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            walk(root, &path, found, depth + 1)?;
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            found.push(relative.to_str().ok_or("fixture path")?.replace('\\', "/"));
        } else {
            return Err("fixture entry is not a file".into());
        }
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let limit = u64::try_from(MAX_FILE + 1).map_err(|_| "file bound".to_owned())?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_FILE {
        return Err(format!("{} exceeds {MAX_FILE} bytes", path.display()));
    }
    Ok(bytes)
}

fn document(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.last() != Some(&b'\n') {
        out.push(b'\n');
    }
    out
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("host-fixtures")
}

fn component_id(value: &Value) -> &str {
    value.get("id").and_then(Value::as_str).unwrap_or("")
}

fn label(case: &Case) -> String {
    match &case.variant {
        Some(variant) => format!("{}:{variant}", case.kind),
        None => case.kind.clone(),
    }
}

fn exact<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("{name} length"))
}
