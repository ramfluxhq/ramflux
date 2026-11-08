// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::Visit;
use syn::{Expr, GenericArgument, Item, Type, UseTree};

const REGISTRY: &str = "ijson_decode_sites.registry";
const PLANTED_SOURCE: &str = r#"
    use serde::de::DeserializeOwned;
    use serde_json::{from_slice as decode_bytes, value::RawValue as JsonRawValue};
    struct Wrapper { envelope: ramflux_protocol::Envelope }
    fn inferred(b: &[u8]) -> Result<ramflux_protocol::Envelope, Error> {
        let e = serde_json::from_slice(b)?;
        Ok(e)
    }
    fn multiline(b: &[u8]) -> Result<ramflux_protocol::Envelope, Error> {
        serde_json::from_slice::<
            ramflux_protocol::Envelope
        >(b)
    }
    fn wrapper(b: &[u8]) -> Result<Wrapper, Error> {
        serde_json::from_slice::<Wrapper>(b)
    }
    fn strict_wrapper(b: &[u8]) -> Result<ramflux_protocol::Envelope, Error> {
        ramflux_protocol::decode_signed_envelope_ijson(b)
    }
    fn generic<T: DeserializeOwned>(b: &[u8]) -> Result<T, Error> {
        serde_json::from_slice::<T>(b)
    }
    fn alias(b: &[u8]) -> Result<ramflux_protocol::Envelope, Error> {
        decode_bytes(b)
    }
    fn raw_value(b: &[u8]) -> Result<Box<JsonRawValue>, Error> {
        serde_json::from_slice(b)
    }
    fn function_value(b: &[u8]) {
        let _ = Some(b).map(serde_json::from_slice::<ramflux_protocol::Envelope>);
    }
    #[cfg(not(test))]
    fn production_cfg(b: &[u8]) {
        let _ = serde_json::from_slice::<ramflux_protocol::Envelope>(b);
    }
    #[cfg(any(test, feature = "itest-http"))]
    fn feature_cfg_is_not_test_only(b: &[u8]) {
        let _ = serde_json::from_slice::<ramflux_protocol::Envelope>(b);
    }
    #[cfg(test)]
    mod inline {
        fn fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
    }
    #[test]
    fn test_fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
    #[tokio::test]
    async fn async_fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
    #[cfg(test)]
    mod external;
"#;
const DECODERS: [&str; 8] = [
    "from_slice",
    "from_str",
    "from_value",
    "from_reader",
    "parse_i_json",
    "decode_signed_envelope_ijson",
    "decode_signed_ack_ijson",
    "decode_signed_nack_ijson",
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    path: String,
    function: String,
    ordinal: usize,
}

#[derive(Clone, Debug)]
struct Site {
    key: Key,
    spelling: String,
    target: String,
    closure_hit: bool,
    generic_deserialize: bool,
    strict: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryRow {
    class: char,
    evidence: String,
}

#[test]
fn ijson_decode_site_guard() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sites = scan_tree(&root)?;
    let registry = read_registry(&root.join(REGISTRY))?;
    validate_registry(&sites, &registry)?;
    Ok(())
}

#[test]
fn deleting_a_class_a_row_reports_the_exact_unregistered_verdict()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sites = scan_tree(&root)?;
    let mut registry = read_registry(&root.join(REGISTRY))?;
    let key = registry
        .iter()
        .find_map(|(key, row)| (row.class == 'A').then_some(key.clone()))
        .ok_or("registry has no class A row")?;
    registry.remove(&key);
    assert_eq!(
        validate_registry(&sites, &registry).err(),
        Some(format!("unregistered decoder: {}", display_key(&key)))
    );
    Ok(())
}

#[test]
fn test_path_exemptions_match_only_the_card_patterns() {
    for path in [
        "tests/fixture.rs",
        "crates/demo/src/generated_tests/decode.rs",
        "crates/demo/src/decode_tests.rs",
    ] {
        assert!(is_test_path(path), "expected test path exemption: {path}");
    }
    for path in [
        "crates/demo/src/fixture.rs",
        "crates/demo/src/test_support.rs",
        "crates/demo/examples/decode.rs",
        "crates/demo/benches/decode.rs",
        "crates/demo/src/decode_test.rs",
        "crates/demo/src/tests.rs",
    ] {
        assert!(!is_test_path(path), "unexpected broad test path exemption: {path}");
    }
}

#[test]
fn planted_decode_site_spellings_and_exemptions_are_detected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_tree("planted")?;
    write_source(&root, "crates/demo/src/decode.rs", PLANTED_SOURCE)?;
    write_source(
        &root,
        "crates/demo/src/decode/external.rs",
        "fn external_fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }",
    )?;
    let sites = scan_tree(&root)?;
    let keys = sites.iter().map(|site| site.key.clone()).collect::<BTreeSet<_>>();
    assert_eq!(sites.len(), 10, "function values and non-test cfg items are registered");
    assert!(sites.iter().any(|site| site.key.function == "inferred" && site.closure_hit));
    assert!(sites.iter().any(|site| site.key.function == "multiline" && site.closure_hit));
    assert!(sites.iter().any(|site| site.key.function == "wrapper" && site.closure_hit));
    assert!(sites.iter().any(|site| site.key.function == "strict_wrapper" && site.strict));
    assert!(sites.iter().any(|site| site.key.function == "generic" && site.generic_deserialize));
    assert!(sites.iter().any(|site| site.key.function == "alias" && site.spelling == "from_slice"));
    assert!(
        sites
            .iter()
            .any(|site| site.key.function == "raw_value" && site.target.contains("RawValue"))
    );
    assert!(sites.iter().any(|site| site.key.function == "function_value"));
    assert!(sites.iter().any(|site| site.key.function == "production_cfg"));
    assert!(sites.iter().any(|site| site.key.function == "feature_cfg_is_not_test_only"));
    assert!(!sites.iter().any(|site| site.key.function == "fixture"));
    assert!(!sites.iter().any(|site| site.key.function == "external_fixture"));

    let rows = sites
        .iter()
        .map(|site| {
            (
                site.key.clone(),
                RegistryRow { class: 'E', evidence: "excluded=planted fixture".to_owned() },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut missing = rows.clone();
    let missing_key = keys.first().ok_or("no planted call sites")?;
    missing.remove(missing_key);
    assert_registry_verdict(
        &sites,
        &missing,
        format!("unregistered decoder: {}", display_key(missing_key)),
    );
    let mut stale = rows.clone();
    let stale_key =
        Key { path: "crates/demo/src/stale.rs".to_owned(), function: "old".to_owned(), ordinal: 1 };
    stale.insert(
        stale_key.clone(),
        RegistryRow { class: 'E', evidence: "excluded=stale fixture".to_owned() },
    );
    assert_registry_verdict(
        &sites,
        &stale,
        format!("stale decoder row: {}", display_key(&stale_key)),
    );
    for function in ["function_value", "production_cfg", "feature_cfg_is_not_test_only"] {
        let key = sites
            .iter()
            .find(|site| site.key.function == function)
            .ok_or("missing planted decoder")?
            .key
            .clone();
        let mut missing_row = rows.clone();
        missing_row.remove(&key);
        assert_registry_verdict(
            &sites,
            &missing_row,
            format!("unregistered decoder: {}", display_key(&key)),
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_registry_verdict(sites: &[Site], rows: &BTreeMap<Key, RegistryRow>, expected: String) {
    assert_eq!(validate_registry(sites, rows).err(), Some(expected));
}

#[test]
fn registry_guard_rejects_class_a_or_b_without_a_strict_call()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_tree("strict")?;
    write_source(
        &root,
        "apps/ramflux-router/src/handlers.rs",
        "fn ingress(b: &[u8]) { let _: Envelope = serde_json::from_slice(b).unwrap(); let _ = ramflux_protocol::parse_i_json::<Envelope>(b); }",
    )?;
    let sites = scan_tree(&root)?;
    let site =
        sites.iter().find(|site| !site.strict).ok_or("missing planted lenient ingress site")?;
    let registry = sites
        .iter()
        .map(|site| {
            (site.key.clone(), RegistryRow { class: 'A', evidence: "admission=planted".to_owned() })
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        validate_registry(&sites, &registry).err().as_deref(),
        Some(
            format!(
                "class A lacks strict parse_i_json call: {} (from_slice)",
                display_key(&site.key)
            )
            .as_str()
        ),
        "a lenient A call has the stable strictness verdict"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
#[ignore = "registry maintenance only; run explicitly to regenerate reviewed rows"]
fn regenerate_ijson_decode_site_registry() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sites = scan_tree(&root)?;
    let previous = read_registry(&root.join(REGISTRY)).unwrap_or_default();
    let text = registry_text(&sites, &previous);
    fs::write(root.join(REGISTRY), text)?;
    Ok(())
}

fn scan_tree(root: &Path) -> Result<Vec<Site>, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    for top in ["apps", "crates"] {
        let dir = root.join(top);
        if dir.is_dir() {
            collect_sources(root, &dir, &mut sources)?;
        }
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));

    let parsed = sources
        .iter()
        .map(|(path, text)| Ok((path.clone(), syn::parse_file(text)?)))
        .collect::<Result<Vec<_>, syn::Error>>()?;
    let closure = type_closure(&parsed);
    let test_modules = test_module_paths(&parsed);
    let mut sites = Vec::new();
    for (path, file) in &parsed {
        if test_modules.contains(path) {
            continue;
        }
        let mut visitor = SiteVisitor::new(path.clone(), &closure);
        visitor.visit_file(file);
        sites.extend(visitor.sites);
    }
    sites.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(sites)
}

fn test_module_paths(parsed: &[(String, syn::File)]) -> BTreeSet<String> {
    let known_paths = parsed.iter().map(|(path, _)| path.as_str()).collect::<BTreeSet<_>>();
    let mut test_paths = BTreeSet::new();
    for (path, file) in parsed {
        let file_path = Path::new(path);
        let parent = file_path.parent().unwrap_or_else(|| Path::new(""));
        let module_dir = if file_path.file_stem().is_some_and(|stem| stem == "mod") {
            parent.to_path_buf()
        } else {
            parent.join(file_path.file_stem().unwrap_or_default())
        };
        collect_test_module_paths(&file.items, &module_dir, &known_paths, &mut test_paths);
    }
    test_paths
}

fn collect_test_module_paths(
    items: &[Item],
    module_dir: &Path,
    known_paths: &BTreeSet<&str>,
    test_paths: &mut BTreeSet<String>,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        if is_test_cfg(&module.attrs) {
            if module.content.is_none() {
                let explicit_path = module.attrs.iter().find_map(|attr| {
                    if !attr.path().is_ident("path") {
                        return None;
                    }
                    match &attr.meta {
                        syn::Meta::NameValue(value) => match &value.value {
                            Expr::Lit(expr) => match &expr.lit {
                                syn::Lit::Str(path) => Some(module_dir.join(path.value())),
                                _ => None,
                            },
                            _ => None,
                        },
                        _ => None,
                    }
                });
                let candidates = explicit_path.map_or_else(
                    || {
                        let stem = module.ident.to_string();
                        vec![
                            module_dir.join(format!("{stem}.rs")),
                            module_dir.join(stem).join("mod.rs"),
                        ]
                    },
                    |path| vec![path],
                );
                for candidate in candidates {
                    let normalized = candidate.to_string_lossy().replace('\\', "/");
                    if known_paths.contains(normalized.as_str()) {
                        test_paths.insert(normalized);
                    }
                }
            }
            continue;
        }
        if let Some((_, nested)) = &module.content {
            collect_test_module_paths(
                nested,
                &module_dir.join(module.ident.to_string()),
                known_paths,
                test_paths,
            );
        }
    }
}

fn collect_sources(
    root: &Path,
    dir: &Path,
    sources: &mut Vec<(String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_sources(root, &path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
            if is_test_path(&relative) {
                continue;
            }
            sources.push((relative, fs::read_to_string(path)?));
        }
    }
    Ok(())
}

fn is_test_path(path: &str) -> bool {
    path.split('/').any(|part| part == "tests" || part.ends_with("_tests"))
        || path.ends_with("_tests.rs")
}

fn type_closure(files: &[(String, syn::File)]) -> BTreeSet<String> {
    let mut fields = Vec::<(String, Vec<String>, bool)>::new();
    for (_, file) in files {
        for item in &file.items {
            match item {
                Item::Struct(item) => {
                    let names =
                        item.fields.iter().flat_map(|field| type_identifiers(&field.ty)).collect();
                    fields.push((item.ident.to_string(), names, !item.generics.params.is_empty()));
                }
                Item::Enum(item) => {
                    let names = item
                        .variants
                        .iter()
                        .flat_map(|variant| {
                            variant.fields.iter().flat_map(|field| type_identifiers(&field.ty))
                        })
                        .collect();
                    fields.push((item.ident.to_string(), names, !item.generics.params.is_empty()));
                }
                _ => {}
            }
        }
    }
    let mut closure = BTreeSet::from([
        "Envelope".to_owned(),
        "Ack".to_owned(),
        "Nack".to_owned(),
        "GatewayQuicRequest".to_owned(),
    ]);
    loop {
        let before = closure.len();
        for (name, referenced, generic) in &fields {
            if *generic && name == "Envelope" {
                continue;
            }
            if referenced.iter().any(|field| closure.contains(field)) {
                closure.insert(name.clone());
            }
        }
        if closure.len() == before {
            return closure;
        }
    }
}

fn type_identifiers(ty: &Type) -> Vec<String> {
    struct Idents(Vec<String>);
    impl<'ast> Visit<'ast> for Idents {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            if let Some(segment) = path.path.segments.last() {
                self.0.push(segment.ident.to_string());
            }
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut idents = Idents(Vec::new());
    idents.visit_type(ty);
    idents.0
}

struct SiteVisitor<'a> {
    path: String,
    closure: &'a BTreeSet<String>,
    modules: Vec<String>,
    functions: Vec<String>,
    return_types: Vec<Option<String>>,
    generic_deserialize: Vec<bool>,
    expected_types: Vec<Option<String>>,
    ordinals: HashMap<String, usize>,
    aliases: HashMap<String, String>,
    raw_value_aliases: BTreeSet<String>,
    sites: Vec<Site>,
}

impl<'a> SiteVisitor<'a> {
    fn new(path: String, closure: &'a BTreeSet<String>) -> Self {
        Self {
            path,
            closure,
            modules: Vec::new(),
            functions: Vec::new(),
            return_types: Vec::new(),
            generic_deserialize: Vec::new(),
            expected_types: Vec::new(),
            ordinals: HashMap::new(),
            aliases: HashMap::new(),
            raw_value_aliases: BTreeSet::new(),
            sites: Vec::new(),
        }
    }

    fn enclosing_function(&self) -> String {
        let mut path = self.modules.clone();
        path.extend(self.functions.clone());
        if path.is_empty() { "<module>".to_owned() } else { path.join("::") }
    }

    fn visit_use_tree(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.visit_use_tree(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(name) => {
                let mut full = prefix.clone();
                full.push(name.ident.to_string());
                self.register_import(&full, name.ident.to_string());
            }
            UseTree::Rename(rename) => {
                let mut full = prefix.clone();
                full.push(rename.ident.to_string());
                self.register_import(&full, rename.rename.to_string());
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.visit_use_tree(item, prefix);
                }
            }
            UseTree::Glob(_) => {}
        }
    }

    fn register_import(&mut self, full: &[String], local: String) {
        if full.first().is_some_and(|part| part == "serde_json")
            && let Some(last) = full.last()
        {
            if DECODERS.contains(&last.as_str()) || (full.len() > 2 && last == "RawValue") {
                self.aliases.insert(local.clone(), full.join("::"));
            }
            if full.len() > 2 && last == "RawValue" {
                self.raw_value_aliases.insert(local.clone());
            }
            if full.len() == 1 && local != "serde_json" {
                self.aliases.insert(local.clone(), "serde_json".to_owned());
            }
        }
        if full.first().is_some_and(|part| part == "ramflux_protocol")
            && full
                .last()
                .is_some_and(|last| last == "parse_i_json" || last.starts_with("decode_signed_"))
        {
            self.aliases.insert(local.clone(), full.join("::"));
        }
        if full.len() == 2 && full[0] == "serde_json" && full[1] == "self" {
            self.aliases.insert(local, "serde_json".to_owned());
        }
    }

    fn call_spelling(&self, expression: &Expr) -> Option<String> {
        let Expr::Path(path) = expression else { return None };
        let parts =
            path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>();
        if parts.is_empty() {
            return None;
        }
        let mut normalized = parts.clone();
        if let Some(alias) = self.aliases.get(&parts[0]) {
            let mut prefix = alias.split("::").map(str::to_owned).collect::<Vec<_>>();
            prefix.extend(parts.iter().skip(1).cloned());
            normalized = prefix;
        }
        let last = normalized.last()?.as_str();
        if DECODERS.contains(&last) {
            let is_json_decoder = normalized.first().is_some_and(|part| part == "serde_json")
                || last == "parse_i_json"
                || last.starts_with("decode_signed_");
            if is_json_decoder {
                return Some(last.to_owned());
            }
        }
        None
    }

    fn record_call<'b>(&mut self, expression: &Expr, args: impl IntoIterator<Item = &'b Expr>) {
        let Some(spelling) = self.call_spelling(expression) else {
            self.visit_expr(expression);
            for argument in args {
                self.visit_expr(argument);
            }
            return;
        };
        let function = self.enclosing_function();
        let ordinal = self.ordinals.entry(function.clone()).or_default();
        *ordinal += 1;
        let ordinal = *ordinal;
        let turbofish = match expression {
            Expr::Path(path) => {
                path.path.segments.last().and_then(|segment| match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => {
                        arguments.args.iter().find_map(|argument| {
                            if let GenericArgument::Type(ty) = argument {
                                Some(type_debug(ty))
                            } else {
                                None
                            }
                        })
                    }
                    _ => None,
                })
            }
            _ => None,
        };
        let mut target = turbofish
            .or_else(|| self.expected_types.last().cloned().flatten())
            .or_else(|| self.return_types.last().cloned().flatten())
            .or_else(|| match spelling.as_str() {
                "decode_signed_envelope_ijson" => Some("Envelope".to_owned()),
                "decode_signed_ack_ijson" => Some("Ack".to_owned()),
                "decode_signed_nack_ijson" => Some("Nack".to_owned()),
                _ => None,
            })
            .unwrap_or_else(|| "INFERRED".to_owned());
        if target_identifiers(&target).iter().any(|name| self.raw_value_aliases.contains(name)) {
            target.push_str(" RawValue");
        }
        let identifiers = target_identifiers(&target);
        let closure_hit = identifiers.iter().any(|name| self.closure.contains(name));
        let generic_deserialize = !self.generic_deserialize.is_empty()
            && *self.generic_deserialize.last().unwrap_or(&false)
            && target_identifiers(&target).iter().any(|name| name == "T");
        let strict = spelling == "parse_i_json" || spelling.starts_with("decode_signed_");
        let key = Key { path: self.path.clone(), function, ordinal };
        self.sites.push(Site { key, spelling, target, closure_hit, generic_deserialize, strict });
        for argument in args {
            self.visit_expr(argument);
        }
    }
}

impl<'ast> Visit<'ast> for SiteVisitor<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.visit_use_tree(&item.tree, &mut Vec::new());
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if is_test_cfg(&item.attrs) {
            return;
        }
        self.modules.push(item.ident.to_string());
        syn::visit::visit_item_mod(self, item);
        self.modules.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if is_test_fn(&item.attrs) {
            return;
        }
        let return_type = match &item.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, ty) => Some(type_debug(ty)),
        };
        let generic = item.sig.generics.type_params().any(|param| {
            param.bounds.iter().any(|bound| type_debug(bound).contains("DeserializeOwned"))
        });
        self.functions.push(item.sig.ident.to_string());
        self.return_types.push(return_type);
        self.generic_deserialize.push(generic);
        syn::visit::visit_item_fn(self, item);
        self.generic_deserialize.pop();
        self.return_types.pop();
        self.functions.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_fn(&item.attrs) {
            return;
        }
        let return_type = match &item.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, ty) => Some(type_debug(ty)),
        };
        let generic = item.sig.generics.type_params().any(|param| {
            param.bounds.iter().any(|bound| type_debug(bound).contains("DeserializeOwned"))
        });
        self.functions.push(item.sig.ident.to_string());
        self.return_types.push(return_type);
        self.generic_deserialize.push(generic);
        syn::visit::visit_impl_item_fn(self, item);
        self.generic_deserialize.pop();
        self.return_types.pop();
        self.functions.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if is_test_fn(&item.attrs) {
            return;
        }
        let return_type = match &item.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, ty) => Some(type_debug(ty)),
        };
        let generic = item.sig.generics.type_params().any(|param| {
            param.bounds.iter().any(|bound| type_debug(bound).contains("DeserializeOwned"))
        });
        self.functions.push(item.sig.ident.to_string());
        self.return_types.push(return_type);
        self.generic_deserialize.push(generic);
        syn::visit::visit_trait_item_fn(self, item);
        self.generic_deserialize.pop();
        self.return_types.pop();
        self.functions.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let expected = match &local.pat {
            syn::Pat::Type(pat_type) => Some(type_debug(&pat_type.ty)),
            _ => None,
        };
        self.expected_types.push(expected);
        syn::visit::visit_local(self, local);
        self.expected_types.pop();
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.record_call(&call.func, call.args.iter());
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if self.call_spelling(&Expr::Path(path.clone())).is_some() {
            self.record_call(&Expr::Path(path.clone()), std::iter::empty());
        } else {
            syn::visit::visit_expr_path(self, path);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "from_slice"
            || call.method == "from_str"
            || call.method == "from_value"
            || call.method == "from_reader"
        {
            let function = self.enclosing_function();
            let ordinal = self.ordinals.entry(function.clone()).or_default();
            *ordinal += 1;
            let target = call
                .turbofish
                .as_ref()
                .and_then(|args| {
                    args.args.iter().find_map(|arg| {
                        if let GenericArgument::Type(ty) = arg {
                            Some(type_debug(ty))
                        } else {
                            None
                        }
                    })
                })
                .or_else(|| self.expected_types.last().cloned().flatten())
                .unwrap_or_else(|| "INFERRED".to_owned());
            let closure_hit =
                target_identifiers(&target).iter().any(|name| self.closure.contains(name));
            let key = Key { path: self.path.clone(), function, ordinal: *ordinal };
            let spelling = call.method.to_string();
            self.sites.push(Site {
                key,
                spelling,
                target,
                closure_hit,
                generic_deserialize: false,
                strict: false,
            });
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tokens = mac.tokens.clone();
        if let Ok(expression) = syn::parse2::<Expr>(tokens.clone()) {
            self.visit_expr(&expression);
        } else if let Ok(block) = syn::parse2::<syn::Block>(tokens) {
            self.visit_block(&block);
        }
    }
}

fn type_debug(ty: &impl ToTokens) -> String {
    ty.to_token_stream().to_string()
}

fn target_identifiers(target: &str) -> Vec<String> {
    target
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test")
    })
}

fn is_test_fn(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_some_and(|segment| segment.ident == "test")
            || (attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test"))
    })
}

fn validate_registry(sites: &[Site], rows: &BTreeMap<Key, RegistryRow>) -> Result<(), String> {
    let mut errors = Vec::new();
    let expected = sites.iter().map(|site| site.key.clone()).collect::<BTreeSet<_>>();
    let actual = rows.keys().cloned().collect::<BTreeSet<_>>();
    for missing in expected.difference(&actual) {
        errors.push(format!("unregistered decoder: {}", display_key(missing)));
    }
    for stale in actual.difference(&expected) {
        errors.push(format!("stale decoder row: {}", display_key(stale)));
    }
    for site in sites {
        let Some(row) = rows.get(&site.key) else { continue };
        if !matches!(row.class, 'A' | 'B' | 'C' | 'D' | 'E') {
            errors.push(format!(
                "invalid registry class for {}: {}",
                display_key(&site.key),
                row.class
            ));
        }
        if row.evidence.trim().is_empty() {
            errors.push(format!(
                "missing admission provenance/exclusion reason: {}",
                display_key(&site.key)
            ));
        }
        if matches!(row.class, 'A' | 'B')
            && !sites.iter().any(|candidate| {
                candidate.key.path == site.key.path
                    && candidate.key.function == site.key.function
                    && candidate.key.ordinal <= site.key.ordinal
                    && candidate.strict
            })
        {
            errors.push(format!(
                "class {} lacks strict parse_i_json call: {} ({})",
                row.class,
                display_key(&site.key),
                site.spelling
            ));
        }
        if row.class == 'C' {
            let Some(provenance) = row.evidence.strip_prefix("admission=") else {
                errors.push(format!(
                    "class C lacks admission call provenance: {}",
                    display_key(&site.key)
                ));
                continue;
            };
            let valid_admissions = provenance.split(',').all(|reference| {
                let mut parts = reference.split('#');
                let admission = match (parts.next(), parts.next(), parts.next(), parts.next()) {
                    (Some(path), Some(function), Some(ordinal), None) => {
                        ordinal.parse::<usize>().ok().map(|ordinal| Key {
                            path: path.to_owned(),
                            function: function.to_owned(),
                            ordinal,
                        })
                    }
                    _ => None,
                };
                admission.is_some_and(|key| {
                    sites.iter().any(|candidate| candidate.key == key && candidate.strict)
                })
            });
            if !valid_admissions {
                errors.push(format!(
                    "class C names no real admitting call: {} (admission={provenance})",
                    display_key(&site.key),
                ));
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
}

fn read_registry(path: &Path) -> Result<BTreeMap<Key, RegistryRow>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let mut rows = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let parts = line.splitn(5, '|').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(format!("invalid registry row {}", index + 1).into());
        }
        let ordinal = parts[2].parse::<usize>()?;
        let mut class_chars = parts[3].chars();
        let class = class_chars.next().ok_or("empty class")?;
        if class.is_ascii_whitespace() || class_chars.next().is_some() {
            return Err(format!("invalid registry class at row {}", index + 1).into());
        }
        let key = Key { path: parts[0].to_owned(), function: parts[1].to_owned(), ordinal };
        let row = RegistryRow { class, evidence: parts[4].to_owned() };
        if rows.insert(key, row).is_some() {
            return Err(format!("duplicate registry key at row {}", index + 1).into());
        }
    }
    Ok(rows)
}

fn registry_text(sites: &[Site], previous: &BTreeMap<Key, RegistryRow>) -> String {
    let mut output = String::from(
        "# path | enclosing fn | ordinal | class | admission provenance or exclusion reason\n",
    );
    for site in sites {
        let Some(row) = previous.get(&site.key) else { continue };
        let _ = writeln!(
            output,
            "{} | {} | {} | {} | {}",
            site.key.path, site.key.function, site.key.ordinal, row.class, row.evidence
        );
    }
    output
}

fn display_key(key: &Key) -> String {
    format!("{} | {} | {}", key.path, key.function, key.ordinal)
}

fn temp_tree(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root =
        std::env::temp_dir().join(format!("ramflux-ijson-site-{}-{label}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;
    fs::create_dir_all(root.join("apps"))?;
    fs::create_dir_all(root.join("crates"))?;
    Ok(root)
}

fn write_source(root: &Path, relative: &str, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
    fs::write(path, text)?;
    Ok(())
}
