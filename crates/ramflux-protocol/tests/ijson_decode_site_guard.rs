// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::parse::Parser;
use syn::visit::Visit;
use syn::{Expr, GenericArgument, Item, Meta, Type, UseTree};

const REGISTRY: &str = "ijson_decode_sites.registry";
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
    class: char,
    evidence: String,
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
fn planted_decode_site_spellings_and_exemptions_are_detected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_tree("planted")?;
    write_source(
        &root,
        "crates/demo/src/decode.rs",
        r"
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
            #[cfg(test)]
            mod inline {
                fn fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
            }
            #[test]
            fn test_fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
            #[tokio::test]
            async fn async_fixture(b: &[u8]) { let _ = serde_json::from_slice::<Envelope>(b); }
        ",
    )?;
    let sites = scan_tree(&root)?;
    let keys = sites.iter().map(|site| site.key.clone()).collect::<BTreeSet<_>>();
    assert_eq!(sites.len(), 7, "all decoder spellings except test code are registered");
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
    assert!(!sites.iter().any(|site| site.key.function == "fixture"));

    let rows = sites
        .iter()
        .map(|site| {
            (site.key.clone(), RegistryRow { class: site.class, evidence: site.evidence.clone() })
        })
        .collect::<BTreeMap<_, _>>();
    let mut missing = rows.clone();
    missing.remove(keys.first().ok_or("no planted call sites")?);
    assert!(validate_registry(&sites, &missing).is_err(), "a missing row is rejected");
    let mut stale = rows;
    stale.insert(
        Key { path: "crates/demo/src/stale.rs".to_owned(), function: "old".to_owned(), ordinal: 1 },
        RegistryRow { class: 'E', evidence: "excluded=stale fixture".to_owned() },
    );
    assert!(validate_registry(&sites, &stale).is_err(), "a stale row is rejected");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn registry_guard_rejects_class_a_or_b_without_a_strict_call()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_tree("strict")?;
    write_source(
        &root,
        "apps/ramflux-router/src/handlers.rs",
        "fn ingress(b: &[u8]) { let _: Envelope = serde_json::from_slice(b).unwrap(); }",
    )?;
    let sites = scan_tree(&root)?;
    let site = sites.first().ok_or("missing planted ingress site")?;
    assert_eq!(site.class, 'A');
    let registry = BTreeMap::from([(
        site.key.clone(),
        RegistryRow { class: 'A', evidence: "strict=serde_json::from_slice".to_owned() },
    )]);
    assert!(validate_registry(&sites, &registry).is_err(), "lenient A call is rejected");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
#[ignore = "registry maintenance only; run explicitly to regenerate reviewed rows"]
fn regenerate_ijson_decode_site_registry() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sites = scan_tree(&root)?;
    let text = registry_text(&sites);
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
    let mut sites = Vec::new();
    for (path, file) in &parsed {
        let mut visitor = SiteVisitor::new(path.clone(), &closure);
        visitor.visit_file(file);
        sites.extend(visitor.sites);
    }
    sites.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(sites)
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
        || path.ends_with("_test.rs")
        || path.ends_with("_tests.rs")
        || path.ends_with("/tests.rs")
        || path.contains("test_support")
        || path.contains("fixture")
        || path.contains("/benches/")
        || path.contains("/examples/")
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
            && full.last().is_some_and(|last| last.starts_with("decode_signed_"))
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
        let (class, evidence) = classify(Classification {
            path: &key.path,
            function: &key.function,
            spelling: &spelling,
            closure: closure_hit,
            generic: generic_deserialize,
            strict,
            target: &target,
        });
        self.sites.push(Site {
            key,
            spelling,
            target,
            closure_hit,
            generic_deserialize,
            strict,
            class,
            evidence,
        });
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
            let (class, evidence) = classify(Classification {
                path: &key.path,
                function: &key.function,
                spelling: &spelling,
                closure: closure_hit,
                generic: false,
                strict: false,
                target: &target,
            });
            self.sites.push(Site {
                key,
                spelling,
                target,
                closure_hit,
                generic_deserialize: false,
                strict: false,
                class,
                evidence,
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
    attrs.iter().any(|attr| attr.path().is_ident("cfg") && meta_has_test(&attr.meta))
}

fn is_test_fn(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_some_and(|segment| segment.ident == "test")
            || (attr.path().is_ident("cfg") && meta_has_test(&attr.meta))
    })
}

fn meta_has_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let parser = syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated;
            parser.parse2(list.tokens.clone()).is_ok_and(|nested| nested.iter().any(meta_has_test))
        }
        Meta::NameValue(_) => false,
    }
}

const A_PATHS: [&str; 11] = [
    "apps/ramflux-router/src/handlers.rs",
    "apps/ramflux-router/src/handlers/session_push.rs",
    "apps/ramflux-router/src/serve.rs",
    "apps/ramflux-gateway/src/itest_http.rs",
    "apps/ramflux-gateway/src/session.rs",
    "apps/ramflux-federation/src/mesh.rs",
    "apps/ramflux-federation/src/admin_http.rs",
    "apps/ramflux-federation/src/itest_http.rs",
    "crates/ramflux-transport/src/loopback.rs",
    "crates/ramflux-sdk/src/gateway/host_frames.rs",
    "crates/ramflux-sdk/src/gateway/session_push.rs",
];

const B_PATHS: [&str; 9] = [
    "crates/ramflux-transport/src/mesh_quic.rs",
    "crates/ramflux-transport/src/compio_mesh.rs",
    "crates/ramflux-transport/src/mesh_quic_limited.rs",
    "crates/ramflux-transport/src/mesh_http.rs",
    "crates/ramflux-transport/src/backend.rs",
    "crates/ramflux-transport/src/quic_gateway.rs",
    "crates/ramflux-transport/src/compio_gateway.rs",
    "crates/ramflux-node-core/src/http_support.rs",
    "apps/ramflux-router/src/forward_http.rs",
];

#[derive(Clone, Copy)]
struct Classification<'a> {
    path: &'a str,
    function: &'a str,
    spelling: &'a str,
    closure: bool,
    generic: bool,
    strict: bool,
    target: &'a str,
}

fn classify(facts: Classification<'_>) -> (char, String) {
    let Classification { path, function, spelling, closure, generic, strict, target } = facts;
    let ingress = A_PATHS.contains(&path);
    let reader = B_PATHS.contains(&path);
    let strict_value_admission = (path == "apps/ramflux-federation/src/mesh.rs"
        && function == "handle_federation_mesh_quic_request")
        || (path == "apps/ramflux-router/src/handlers/session_push.rs"
            && matches!(function, "bound_ack" | "bound_nack"));
    let outbound_response =
        path == "apps/ramflux-gateway/src/session.rs" && function == "handle_gateway_submit";
    if strict_value_admission && strict {
        return ('A', format!("strict={spelling}; admission=A byte ingress"));
    }
    let a_candidate = ingress && (closure || generic || target == "INFERRED");
    let b_candidate = reader
        && !target.contains("RawBodyOnly")
        && !target.contains("RawRequest")
        && (strict || closure || generic || target == "INFERRED");
    if (a_candidate || b_candidate) && !strict_value_admission && !outbound_response {
        let class = if a_candidate { 'A' } else { 'B' };
        let evidence = if strict {
            format!("strict={spelling}; admission={class} ingress boundary")
        } else {
            format!("STRICT-REQUIRED; {class} ingress/reader site")
        };
        return (class, evidence);
    }
    if is_stored_path(path) && closure {
        return ('D', "admitted-before-persist; stored row is not an ingress decoder".to_owned());
    }
    if strict_value_admission && closure {
        return ('C', "admission=previous parse_i_json of the enclosing frame/value".to_owned());
    }
    if outbound_response {
        return (
            'E',
            "excluded=router response decoding; not a received signed-envelope ingress".to_owned(),
        );
    }
    if closure && strict {
        return ('C', format!("admission={spelling} at {function}"));
    }
    let reason = if target.contains("RawValue") {
        "excluded=RawValue peek; classify-only, never admits"
    } else if closure {
        "excluded=decode is not an ingress admission; no signed envelope is admitted here"
    } else if target == "INFERRED" {
        "excluded=target type is not in Envelope/Ack/Nack containment closure"
    } else {
        "excluded=target type is outside Envelope/Ack/Nack containment closure"
    };
    ('E', reason.to_owned())
}

fn is_stored_path(path: &str) -> bool {
    path.contains("/router_store")
        || path.contains("router_store/")
        || path.contains("router_wal/")
        || path.contains("federation_store")
        || path.contains("home_migration_store")
        || path.contains("custody_authority/")
        || path.contains("/bus/")
        || path.contains("/client/")
        || path.contains("account_db/receive/")
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
        if row.class != site.class {
            errors.push(format!(
                "class changed for {}: registry {}, detected {}",
                display_key(&site.key),
                row.class,
                site.class
            ));
        }
        if row.evidence.trim().is_empty() {
            errors.push(format!(
                "missing admission provenance/exclusion reason: {}",
                display_key(&site.key)
            ));
        }
        if matches!(row.class, 'A' | 'B') && !site.strict {
            errors.push(format!(
                "class {} lacks strict parse_i_json call: {} ({})",
                row.class,
                display_key(&site.key),
                site.spelling
            ));
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

fn registry_text(sites: &[Site]) -> String {
    let mut output = String::from(
        "# path | enclosing fn | ordinal | class | admission provenance or exclusion reason\n",
    );
    for site in sites {
        let _ = writeln!(
            output,
            "{} | {} | {} | {} | {}",
            site.key.path, site.key.function, site.key.ordinal, site.class, site.evidence
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
