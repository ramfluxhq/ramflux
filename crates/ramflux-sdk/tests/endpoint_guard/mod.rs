// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Syntax boundaries for the endpoint guard; no macro expansion or name resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use syn::parse::{ParseStream, Parser};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Lit, Meta, Token};

const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_FILES: usize = 10_000;
const SCHEMA_FILE: &str = "crates/ramflux-protocol/src/a2ui/schema.rs";
const CATALOG: &str = "https://a2ui.org/specification/v1_0/catalog.json";
const VALIDATION: &str = "https://a2ui.org/specification/v1_0/validation.json";
const COMMON: &str = "https://a2ui.org/specification/v1_0/common_types.json";
const BASIC_COMMON: &str = "https://a2ui.org/specification/v1_0/catalogs/basic/common_types.json";

pub fn read(path: &Path) -> Result<String, String> {
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_SOURCE_BYTES + 1).read_to_string(&mut text))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > MAX_SOURCE_BYTES {
        return Err(format!("{}: source exceeds limit", path.display()));
    }
    Ok(text)
}

pub fn rust_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES {
        return Err(format!("{}: source traversal limit", dir.display()));
    }
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        let path = entry.path();
        if kind.is_symlink() {
            return Err(format!("{}: symlink cannot establish source ownership", path.display()));
        }
        if kind.is_dir() {
            rust_files(&path, out, depth + 1)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            if out.len() >= MAX_FILES {
                return Err("source file limit".into());
            }
            out.push(path);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Truth {
    Yes,
    No,
    Unknown,
}

fn predicate(meta: &Meta) -> Result<Truth, String> {
    predicate_at(meta, 0)
}

fn predicate_at(meta: &Meta, depth: usize) -> Result<Truth, String> {
    if depth > MAX_DEPTH {
        return Err("cfg nesting limit".into());
    }
    match meta {
        Meta::Path(path) => Ok(if path.is_ident("test") { Truth::No } else { Truth::Unknown }),
        Meta::NameValue(value) if matches!(&value.value, Expr::Lit(lit) if matches!(lit.lit, Lit::Str(_))) => {
            Ok(Truth::Unknown)
        }
        Meta::List(list) => {
            let values = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|error| error.to_string())?
                .iter()
                .map(|meta| predicate_at(meta, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            if list.path.is_ident("not") && values.len() == 1 {
                return Ok(match values.first() {
                    Some(Truth::Yes) => Truth::No,
                    Some(Truth::No) => Truth::Yes,
                    _ => Truth::Unknown,
                });
            }
            if list.path.is_ident("all") {
                return Ok(if values.contains(&Truth::No) {
                    Truth::No
                } else if values.contains(&Truth::Unknown) {
                    Truth::Unknown
                } else {
                    Truth::Yes
                });
            }
            if list.path.is_ident("any") {
                return Ok(if values.contains(&Truth::Yes) {
                    Truth::Yes
                } else if values.contains(&Truth::Unknown) {
                    Truth::Unknown
                } else {
                    Truth::No
                });
            }
            Err("unsupported cfg predicate".into())
        }
        Meta::NameValue(_) => Err("unsupported cfg predicate".into()),
    }
}

fn meta_active(meta: &Meta, depth: usize) -> Result<bool, String> {
    if depth > MAX_DEPTH {
        return Err("attribute nesting limit".into());
    }
    if depth > 0 && meta.path().is_ident("path") {
        return Err("conditional module paths are unsupported".into());
    }
    if meta.path().is_ident("cfg") {
        let Meta::List(list) = meta else { return Err("malformed cfg".into()) };
        let condition = list.parse_args::<Meta>().map_err(|error| error.to_string())?;
        return Ok(predicate(&condition)? != Truth::No);
    }
    if meta.path().is_ident("cfg_attr") {
        let Meta::List(list) = meta else { return Err("malformed cfg_attr".into()) };
        let args = list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_err(|error| error.to_string())?;
        let Some(condition) = args.first() else { return Err("empty cfg_attr".into()) };
        if args.len() < 2 {
            return Err("cfg_attr without attributes".into());
        }
        let applies = predicate(condition)?;
        let mut active = true;
        for attr in args.iter().skip(1) {
            active &= meta_active(attr, depth + 1)?;
        }
        return Ok(applies != Truth::Yes || active);
    }
    Ok(true)
}

fn active(attrs: &[Attribute]) -> Result<bool, String> {
    let mut result = true;
    for attr in attrs {
        result &= meta_active(&attr.meta, 0)?;
    }
    Ok(result)
}

fn item_attrs(item: &Item) -> Result<&[Attribute], String> {
    Ok(match item {
        Item::Const(v) => &v.attrs,
        Item::Enum(v) => &v.attrs,
        Item::ExternCrate(v) => &v.attrs,
        Item::Fn(v) => &v.attrs,
        Item::ForeignMod(v) => &v.attrs,
        Item::Impl(v) => &v.attrs,
        Item::Macro(v) => &v.attrs,
        Item::Mod(v) => &v.attrs,
        Item::Static(v) => &v.attrs,
        Item::Struct(v) => &v.attrs,
        Item::Trait(v) => &v.attrs,
        Item::TraitAlias(v) => &v.attrs,
        Item::Type(v) => &v.attrs,
        Item::Union(v) => &v.attrs,
        Item::Use(v) => &v.attrs,
        _ => return Err("unsupported item syntax".into()),
    })
}

fn expr_attrs(expr: &Expr) -> Result<&[Attribute], String> {
    Ok(match expr {
        Expr::Array(v) => &v.attrs,
        Expr::Assign(v) => &v.attrs,
        Expr::Async(v) => &v.attrs,
        Expr::Await(v) => &v.attrs,
        Expr::Binary(v) => &v.attrs,
        Expr::Block(v) => &v.attrs,
        Expr::Break(v) => &v.attrs,
        Expr::Call(v) => &v.attrs,
        Expr::Cast(v) => &v.attrs,
        Expr::Closure(v) => &v.attrs,
        Expr::Const(v) => &v.attrs,
        Expr::Continue(v) => &v.attrs,
        Expr::Field(v) => &v.attrs,
        Expr::ForLoop(v) => &v.attrs,
        Expr::Group(v) => &v.attrs,
        Expr::If(v) => &v.attrs,
        Expr::Index(v) => &v.attrs,
        Expr::Infer(v) => &v.attrs,
        Expr::Let(v) => &v.attrs,
        Expr::Lit(v) => &v.attrs,
        Expr::Loop(v) => &v.attrs,
        Expr::Macro(v) => &v.attrs,
        Expr::Match(v) => &v.attrs,
        Expr::MethodCall(v) => &v.attrs,
        Expr::Paren(v) => &v.attrs,
        Expr::Path(v) => &v.attrs,
        Expr::Range(v) => &v.attrs,
        Expr::RawAddr(v) => &v.attrs,
        Expr::Reference(v) => &v.attrs,
        Expr::Repeat(v) => &v.attrs,
        Expr::Return(v) => &v.attrs,
        Expr::Struct(v) => &v.attrs,
        Expr::Try(v) => &v.attrs,
        Expr::TryBlock(v) => &v.attrs,
        Expr::Tuple(v) => &v.attrs,
        Expr::Unary(v) => &v.attrs,
        Expr::Unsafe(v) => &v.attrs,
        Expr::While(v) => &v.attrs,
        Expr::Yield(v) => &v.attrs,
        _ => return Err("unsupported expression syntax".into()),
    })
}

/// Follow declarations even in excluded modules to distinguish test-only files from orphans.
struct ModuleGraph {
    root: PathBuf,
    files: BTreeMap<PathBuf, syn::File>,
    texts: BTreeMap<PathBuf, String>,
    seen: BTreeSet<(PathBuf, bool)>,
}

#[derive(Default)]
struct LocalModules(bool);

impl<'ast> Visit<'ast> for LocalModules {
    fn visit_item_mod(&mut self, _module: &'ast syn::ItemMod) {
        self.0 = true;
    }
}

impl ModuleGraph {
    fn walk(
        &mut self,
        items: &[Item],
        dirs: (&Path, &Path),
        included: bool,
        depth: usize,
    ) -> Result<(), String> {
        let (dir, explicit_dir) = dirs;
        if depth > MAX_DEPTH {
            return Err("module nesting limit".into());
        }
        for item in items {
            let Item::Mod(module) = item else {
                if included && active(item_attrs(item)?)? {
                    let mut local = LocalModules::default();
                    local.visit_item(item);
                    if local.0 {
                        return Err("local module declarations are unsupported".into());
                    }
                }
                continue;
            };
            if module.attrs.iter().filter(|attr| attr.path().is_ident("path")).count() > 1 {
                return Err("multiple module path overrides are unsupported".into());
            }
            let enabled = included && active(&module.attrs)?;
            if let Some((_, children)) = &module.content {
                if module.attrs.iter().any(|attr| attr.path().is_ident("path")) {
                    return Err("inline module path overrides are unsupported".into());
                }
                self.walk(
                    children,
                    (&dir.join(module.ident.to_string()), &dir.join(module.ident.to_string())),
                    enabled,
                    depth + 1,
                )?;
            } else {
                let name = module.ident.to_string();
                let explicit = module.attrs.iter().find(|attr| attr.path().is_ident("path"));
                let candidates = if let Some(attr) = explicit {
                    let Meta::NameValue(value) = &attr.meta else {
                        return Err("unsupported module path".into());
                    };
                    let Expr::Lit(lit) = &value.value else {
                        return Err("nonliteral module path".into());
                    };
                    let Lit::Str(path) = &lit.lit else {
                        return Err("non-string module path".into());
                    };
                    vec![explicit_dir.join(path.value())]
                } else {
                    vec![dir.join(format!("{name}.rs")), dir.join(&name).join("mod.rs")]
                };
                let candidates: Vec<_> = candidates
                    .into_iter()
                    .filter(|path| path.is_file())
                    .map(|path| {
                        path.canonicalize().map_err(|error| format!("{}: {error}", path.display()))
                    })
                    .collect::<Result<_, _>>()?;
                if candidates.len() != 1 {
                    return Err(format!(
                        "{}: module {name} has {} source candidates",
                        dir.display(),
                        candidates.len()
                    ));
                }
                let path = candidates.first().ok_or("missing module source")?;
                if !path.starts_with(&self.root) {
                    return Err("module source escapes workspace".into());
                }
                if !self.files.contains_key(path) {
                    if self.files.len() >= MAX_FILES {
                        return Err("source file limit".into());
                    }
                    let text = read(path)?;
                    let file = syn::parse_file(&text)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    self.files.insert(path.clone(), file);
                    self.texts.insert(path.clone(), text);
                }
                let file = self.files.get(path).ok_or("module source not parsed")?.clone();
                let enabled = enabled && active(&file.attrs)?;
                if self.seen.insert((path.clone(), enabled)) {
                    let child_dir = if path.file_name().is_some_and(|name| name == "mod.rs") {
                        path.parent().ok_or("module parent missing")?.to_owned()
                    } else {
                        path.with_extension("")
                    };
                    self.walk(
                        &file.items,
                        (&child_dir, path.parent().ok_or("module parent missing")?),
                        enabled,
                        depth + 1,
                    )?;
                }
            }
        }
        Ok(())
    }
}

pub fn sources(root: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    sources_under(root, super::CLIENT_SOURCE_ROOTS)
}

pub fn sources_under(root: &Path, roots: &[&str]) -> Result<Vec<(PathBuf, String)>, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let mut paths = Vec::new();
    for dir in roots {
        rust_files(&root.join(dir), &mut paths, 0)?;
    }
    let mut parsed = BTreeMap::new();
    let mut texts = BTreeMap::new();
    for path in paths {
        let text = read(&path)?;
        let file =
            syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        parsed.insert(path.clone(), file);
        texts.insert(path, text);
    }
    let mut graph = ModuleGraph { root: root.clone(), files: parsed, texts, seen: BTreeSet::new() };
    for dir in roots {
        let dir = root.join(dir);
        let entries: Vec<_> = graph
            .files
            .keys()
            .filter(|path| {
                let entry = path.parent() == Some(dir.as_path())
                    && path.file_name().is_some_and(|name| name == "lib.rs" || name == "main.rs");
                let binary = path.parent() == Some(dir.join("bin").as_path());
                entry || binary
            })
            .cloned()
            .collect();
        for path in entries {
            let file = graph.files.get(&path).ok_or("entry source missing")?.clone();
            let enabled = active(&file.attrs)?;
            graph.seen.insert((path.clone(), enabled));
            graph.walk(
                &file.items,
                (
                    path.parent().ok_or("entry parent missing")?,
                    path.parent().ok_or("entry parent missing")?,
                ),
                enabled,
                0,
            )?;
        }
    }
    // Unknown owners can reference files also reached through test-only declarations.
    // Traverse them conservatively before deciding which external files to exclude.
    let orphans: Vec<_> = graph
        .files
        .keys()
        .filter(|path| {
            !graph.seen.contains(&((*path).clone(), false))
                && !graph.seen.contains(&((*path).clone(), true))
        })
        .cloned()
        .collect();
    for path in orphans {
        let file = graph.files.get(&path).ok_or("orphan source missing")?.clone();
        let included = active(&file.attrs)?;
        graph.seen.insert((path.clone(), included));
        let parent = path.parent().ok_or("orphan parent missing")?;
        let child = if path
            .file_name()
            .is_some_and(|name| name == "mod.rs" || name == "lib.rs" || name == "main.rs")
        {
            parent.to_owned()
        } else {
            path.with_extension("")
        };
        graph.walk(&file.items, (&child, parent), included, 0)?;
    }
    let ModuleGraph { texts, seen, .. } = graph;
    // Unreferenced files are scanned, never presumed to be tests from their names.
    Ok(texts
        .into_iter()
        .filter(|(path, _)| {
            !seen.contains(&(path.clone(), false)) || seen.contains(&(path.clone(), true))
        })
        .collect())
}

fn literal(expr: &Expr) -> Option<&syn::LitStr> {
    if let Expr::Lit(lit) = expr
        && lit.attrs.is_empty()
        && let Lit::Str(text) = &lit.lit
    {
        Some(text)
    } else {
        None
    }
}

fn path_is(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident(name))
}

fn resource(expr: &Expr, variable: &str, clone: bool) -> bool {
    let Expr::Call(call) = expr else { return false };
    let Expr::Path(path) = call.func.as_ref() else { return false };
    let segments: Vec<_> = path.path.segments.iter().map(|v| v.ident.to_string()).collect();
    if segments != ["jsonschema", "Resource", "from_contents"] || call.args.len() != 1 {
        return false;
    }
    let Some(arg) = call.args.first() else { return false };
    if clone {
        matches!(arg, Expr::MethodCall(call) if call.method == "clone" && call.args.is_empty() && path_is(&call.receiver, variable))
    } else {
        path_is(arg, variable)
    }
}

fn schema_builder(expr: &Expr, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match expr {
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Path(path)
            if path.path.segments.len() == 2 && path.path.segments.iter()
                .map(|v| v.ident.to_string()).eq(["jsonschema", "options"]))
                && call.args.is_empty()
        }
        Expr::MethodCall(call) => {
            ["with_base_uri", "with_resource", "should_validate_formats"]
                .iter()
                .any(|name| call.method == *name)
                && schema_builder(&call.receiver, depth + 1)
        }
        _ => false,
    }
}

fn catalog_overlay(call: &syn::ExprMethodCall) -> bool {
    call.method == "insert"
        && path_is(&call.receiver, "map")
        && call.args.len() == 2
        && matches!(call.args.first(), Some(Expr::MethodCall(key))
                if key.method == "into" && key.args.is_empty()
                && literal(&key.receiver).is_some_and(|v| v.value() == "$id"))
        && matches!(call.args.iter().nth(1), Some(Expr::Macro(value))
                if value.attrs.is_empty() && value.mac.path.is_ident("json") && value.mac.tokens.to_string() == "BASE")
}

#[derive(Default)]
struct ResourceContract {
    registrations: BTreeSet<String>,
    catalog_id: bool,
    decoded: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ResourceContract {
    fn visit_item(&mut self, item: &'ast Item) {
        if item_attrs(item).and_then(active).is_ok_and(|enabled| enabled) {
            visit::visit_item(self, item);
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if expr_attrs(expr).and_then(active).is_ok_and(|enabled| enabled) {
            visit::visit_expr(self, expr);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if schema_builder(&call.receiver, 0) {
            if call.method == "with_resource" && call.args.len() == 2 {
                if call.args.first().is_some_and(|arg| path_is(arg, "BASE"))
                    && call.args.iter().nth(1).is_some_and(|arg| resource(arg, "catalog", false))
                {
                    self.registrations.insert(CATALOG.into());
                }
                if let Some(id) = call.args.first().and_then(literal).map(syn::LitStr::value)
                    && matches!(id.as_str(), COMMON | BASIC_COMMON)
                    && call.args.iter().nth(1).is_some_and(|arg| resource(arg, "common", true))
                {
                    self.registrations.insert(id);
                }
            }
            if call.method == "with_base_uri"
                && call.args.len() == 1
                && call.args.first().and_then(literal).is_some_and(|v| v.value() == VALIDATION)
            {
                self.registrations.insert(VALIDATION.into());
            }
        }
        if catalog_overlay(call) {
            self.catalog_id = true;
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(call.func.as_ref(), Expr::Path(path) if path.path.segments.iter()
            .map(|v| v.ident.to_string()).eq(["serde_json", "from_str"]))
            && call.args.len() == 1
        {
            for name in ["PROFILE", "COMMON"] {
                if call.args.first().is_some_and(|arg| path_is(arg, name)) {
                    self.decoded.insert(name.into());
                }
            }
        }
        visit::visit_expr_call(self, call);
    }
}

/// Validate the embedded data and disabled resolvers before any syntax-specific allowances.
pub fn embedded_resources(root: &Path) -> Result<(), String> {
    let protocol = root.join("crates/ramflux-protocol");
    let common: serde_json::Value = serde_json::from_str(&read(
        &protocol.join("vendor/a2ui/specification/v1_0/json/common_types.json"),
    )?)
    .map_err(|error| error.to_string())?;
    let profile: serde_json::Value =
        serde_json::from_str(&read(&protocol.join("catalogs/rf-card-v1.json"))?)
            .map_err(|error| error.to_string())?;
    if common.get("$id").and_then(|v| v.as_str()) != Some(COMMON)
        || profile.get("$id").and_then(|v| v.as_str()) != Some("urn:ramflux:catalog:rf-card:1.0")
    {
        return Err("embedded resource identity changed".into());
    }
    let manifest = read(&protocol.join("Cargo.toml"))?;
    let rows: Vec<_> =
        manifest.lines().filter(|line| line.trim_start().starts_with("jsonschema")).collect();
    let disabled = rows.first().is_some_and(|row| {
        let compact: String = row.chars().filter(|v| !v.is_ascii_whitespace()).collect();
        let Some(fields) = compact.strip_prefix("jsonschema={").and_then(|v| v.strip_suffix('}'))
        else {
            return false;
        };
        let fields: Vec<_> = fields.split(',').collect();
        fields.len() == 2
            && fields.contains(&"default-features=false")
            && fields.iter().any(|field| {
                field
                    .strip_prefix("version=")
                    .is_some_and(|version| syn::parse_str::<syn::LitStr>(version).is_ok())
            })
    });
    if rows.len() != 1 || !disabled {
        return Err("cannot establish disabled jsonschema resolvers".into());
    }
    let source = read(&root.join(SCHEMA_FILE))?;
    let tree = syn::parse_file(&source).map_err(|error| error.to_string())?;
    for (name, expected) in [
        ("COMMON", "../../vendor/a2ui/specification/v1_0/json/common_types.json"),
        ("PROFILE", "../../catalogs/rf-card-v1.json"),
    ] {
        let item = tree
            .items
            .iter()
            .find_map(|item| match item {
                Item::Const(item) if item.ident == name => Some(item),
                _ => None,
            })
            .ok_or_else(|| format!("missing embedded {name}"))?;
        let Expr::Macro(expr) = item.expr.as_ref() else {
            return Err(format!("{name} is not embedded"));
        };
        let path = syn::parse2::<syn::LitStr>(expr.mac.tokens.clone())
            .map_err(|error| error.to_string())?;
        if !expr.mac.path.is_ident("include_str") || path.value() != expected {
            return Err(format!("unexpected embedded {name} source"));
        }
    }
    let mut contract = ResourceContract::default();
    contract.visit_file(&tree);
    if !contract.catalog_id
        || contract.decoded.len() != 2
        || contract.registrations
            != [CATALOG, COMMON, BASIC_COMMON, VALIDATION].into_iter().map(str::to_owned).collect()
    {
        return Err(
            "embedded identifiers no longer match resource construction and registration".into()
        );
    }
    Ok(())
}

struct Scan<'a> {
    source: &'a str,
    schema: bool,
    errors: Vec<String>,
    depth: usize,
    item_depth: usize,
}

impl Scan<'_> {
    fn enabled(&mut self, attrs: Result<&[Attribute], String>) -> bool {
        match attrs.and_then(active) {
            Ok(enabled) => enabled,
            Err(error) => {
                self.errors.push(error);
                false
            }
        }
    }

    fn text(&mut self, value: &str, spelling: &str) {
        let lower = value.to_ascii_lowercase();
        let mut errors = Vec::new();
        for fragment in super::FORBIDDEN_HOST_FRAGMENTS {
            if lower.contains(fragment) {
                errors.push(format!("vendor host `{fragment}`"));
            }
        }
        for host in super::url_hosts(value) {
            if !super::host_is_not_a_service(host) {
                errors.push(format!("endpoint `{host}`"));
            }
        }
        if !errors.is_empty() {
            let line = self.source.find(spelling).map_or(1, |offset| {
                self.source[..offset].bytes().filter(|v| *v == b'\n').count() + 1
            });
            self.errors.extend(errors.into_iter().map(|error| format!("{line}: {error}")));
        }
    }

    fn attribute_meta(&mut self, meta: &Meta, depth: usize) {
        if depth > MAX_DEPTH {
            self.errors.push("attribute nesting limit".into());
            return;
        }
        if meta.path().is_ident("doc") {
            return;
        }
        if meta.path().is_ident("cfg") {
            if let Err(error) = meta_active(meta, 0) {
                self.errors.push(error);
            }
            return;
        }
        if meta.path().is_ident("cfg_attr") {
            let result = (|| {
                meta_active(meta, 0)?;
                let Meta::List(list) = meta else { return Err("malformed cfg_attr".into()) };
                let args = list
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    .map_err(|error| error.to_string())?;
                if predicate(args.first().ok_or("empty cfg_attr")?)? != Truth::No {
                    for attr in args.iter().skip(1) {
                        self.attribute_meta(attr, depth + 1);
                    }
                }
                Ok::<_, String>(())
            })();
            if let Err(error) = result {
                self.errors.push(error);
            }
            return;
        }
        // Non-doc attribute arguments may be input to procedural macros.
        match meta {
            Meta::List(list) => {
                let parser = |input: ParseStream<'_>| self.tokens(input, 0);
                if let Err(error) = parser.parse2(list.tokens.clone()) {
                    self.errors.push(error.to_string());
                }
            }
            Meta::NameValue(value) => self.visit_expr(&value.value),
            Meta::Path(_) => {}
        }
    }

    fn token_text(&mut self, token: &str) {
        if self.schema && token.strip_prefix("r#").unwrap_or(token) == "BASE" {
            self.errors.push(
                "schema BASE used outside resource registration or catalog identity construction"
                    .into(),
            );
        }
        self.text(token, token);
    }

    fn tokens(&mut self, input: ParseStream<'_>, depth: usize) -> syn::Result<()> {
        if depth > MAX_DEPTH {
            return Err(input.error("macro nesting limit"));
        }
        while !input.is_empty() {
            if input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in input);
                self.tokens(&content, depth + 1)?;
            } else if input.peek(syn::token::Brace) {
                let content;
                syn::braced!(content in input);
                self.tokens(&content, depth + 1)?;
            } else if input.peek(syn::token::Bracket) {
                let content;
                syn::bracketed!(content in input);
                self.tokens(&content, depth + 1)?;
            } else if input.peek(Lit) {
                self.visit_lit(&input.parse::<Lit>()?);
            } else {
                input.step(|cursor| {
                    cursor
                        .token_tree()
                        .map(|(token, next)| {
                            self.token_text(&token.to_string());
                            ((), next)
                        })
                        .ok_or_else(|| cursor.error("unsupported macro token"))
                })?;
            }
        }
        Ok(())
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(item) => Ok(item.attrs.as_slice()),
            syn::ImplItem::Fn(item) => Ok(item.attrs.as_slice()),
            syn::ImplItem::Type(item) => Ok(item.attrs.as_slice()),
            syn::ImplItem::Macro(item) => Ok(item.attrs.as_slice()),
            _ => Err("unsupported impl item syntax".into()),
        };
        if self.enabled(attrs) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = match item {
            syn::TraitItem::Const(item) => Ok(item.attrs.as_slice()),
            syn::TraitItem::Fn(item) => Ok(item.attrs.as_slice()),
            syn::TraitItem::Type(item) => Ok(item.attrs.as_slice()),
            syn::TraitItem::Macro(item) => Ok(item.attrs.as_slice()),
            _ => Err("unsupported trait item syntax".into()),
        };
        if self.enabled(attrs) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        let attrs = match item {
            syn::ForeignItem::Fn(item) => Ok(item.attrs.as_slice()),
            syn::ForeignItem::Static(item) => Ok(item.attrs.as_slice()),
            syn::ForeignItem::Type(item) => Ok(item.attrs.as_slice()),
            syn::ForeignItem::Macro(item) => Ok(item.attrs.as_slice()),
            _ => Err("unsupported foreign item syntax".into()),
        };
        if self.enabled(attrs) {
            visit::visit_foreign_item(self, item);
        }
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if !self.enabled(item_attrs(item)) {
            return;
        }
        if self.schema
            && self.item_depth == 0
            && let Item::Const(item) = item
            && item.ident == "BASE"
            && literal(&item.expr).is_some_and(|value| value.value() == CATALOG)
        {
            for attr in &item.attrs {
                self.visit_attribute(attr);
            }
            self.visit_type(&item.ty);
            return;
        }
        self.item_depth += 1;
        visit::visit_item(self, item);
        self.item_depth -= 1;
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if !self.enabled(expr_attrs(expr)) {
            return;
        }
        if self.depth >= MAX_DEPTH {
            self.errors.push("expression nesting limit".into());
            return;
        }
        self.depth += 1;
        visit::visit_expr(self, expr);
        self.depth -= 1;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if self.enabled(Ok(&local.attrs)) {
            visit::visit_local(self, local);
        }
    }

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        self.attribute_meta(&attr.meta, 0);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.schema && call.attrs.is_empty() && catalog_overlay(call) {
            self.visit_expr(&call.receiver);
            for arg in call.args.iter().take(1) {
                self.visit_expr(arg);
            }
            return;
        }
        if self.schema && call.attrs.is_empty() && schema_builder(&call.receiver, 0) {
            let first = call.args.first().and_then(literal).map(syn::LitStr::value);
            let allowed = if call.method == "with_base_uri" && call.args.len() == 1 {
                first.as_deref() == Some(VALIDATION)
            } else if call.method == "with_resource" && call.args.len() == 2 {
                (matches!(first.as_deref(), Some(COMMON | BASIC_COMMON))
                    && call.args.iter().nth(1).is_some_and(|arg| resource(arg, "common", true)))
                    || (call.args.first().is_some_and(|arg| path_is(arg, "BASE"))
                        && call
                            .args
                            .iter()
                            .nth(1)
                            .is_some_and(|arg| resource(arg, "catalog", false)))
            } else {
                false
            };
            if allowed {
                self.visit_expr(&call.receiver);
                for arg in call.args.iter().skip(1) {
                    self.visit_expr(arg);
                }
                return;
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let parser = |input: ParseStream<'_>| self.tokens(input, 0);
        if let Err(error) = parser.parse2(mac.tokens.clone()) {
            self.errors.push(error.to_string());
        }
    }

    fn visit_lit(&mut self, lit: &'ast Lit) {
        match lit {
            Lit::Str(value) => self.text(&value.value(), &value.token().to_string()),
            Lit::ByteStr(value) => {
                self.text(&String::from_utf8_lossy(&value.value()), &value.token().to_string());
            }
            Lit::CStr(value) => {
                self.text(&value.value().to_string_lossy(), &value.token().to_string());
            }
            _ => {}
        }
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.token_text(&ident.to_string());
    }
}

pub fn scan(file: &Path, source: &str) -> Result<Vec<String>, String> {
    let tree = syn::parse_file(source).map_err(|error| format!("{}: {error}", file.display()))?;
    if !active(&tree.attrs)? {
        return Ok(Vec::new());
    }
    let mut scanner = Scan {
        source,
        schema: file == Path::new(SCHEMA_FILE),
        errors: Vec::new(),
        depth: 0,
        item_depth: 0,
    };
    scanner.visit_file(&tree);
    Ok(scanner.errors)
}
