// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source guard for the agent-master vault seam. `vault_seed` and `from_vault_seed` carry the
//! raw seed; production code may name them only inside the vault implementations. The scan is
//! syntax-based (`syn`): it finds method calls and paths, skips `#[cfg(test)]` and `#[test]`
//! items, and skips test-only files (`tests`, `fixture` names).
use std::path::{Path, PathBuf};
use syn::visit::Visit;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The seed-carrying names. Both are also methods on `SelfSigningKey`, which the vault layer uses
/// legitimately, so the rule below targets the agent master (`MasterKey`).
const SEAM_NAMES: [&str; 2] = ["vault_seed", "from_vault_seed"];

/// Files allowed to name the seam, as repository-relative prefixes.
const ALLOWED_PREFIXES: [&str; 5] = [
    "crates/ramflux-crypto/src/custody/keys.rs",
    "crates/ramflux-sdk/src/custody/vault",
    "crates/ramflux-sdk/src/custody/memory_vault",
    "crates/ramflux-sdk/src/c_abi/v2/custody.rs",
    // Unconditionally compiled test vault that implements `PrimaryVault` for account tests.
    "crates/ramflux-sdk/src/bus/account_runtime/testing_calls.rs",
];

/// Bound on directory depth while walking the repository.
const MAX_DEPTH: usize = 24;

/// What one file does with the seam.
#[derive(Default)]
struct SeamUse {
    /// `MasterKey::vault_seed` or `MasterKey::from_vault_seed` written as a path, in any code.
    master_path: bool,
    /// `.vault_seed()` on a receiver named like the agent master, in production (non-test) code.
    master_call: bool,
    /// Depth of enclosing test-only items.
    in_test: usize,
}

fn is_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().contains("test"))
    })
}

impl SeamUse {
    fn enter(&mut self, test: bool) {
        if test {
            self.in_test += 1;
        }
    }
    fn leave(&mut self, test: bool) {
        if test {
            self.in_test -= 1;
        }
    }
    fn offends(&self) -> bool {
        self.master_path || self.master_call
    }
}

fn seam(name: &str) -> bool {
    SEAM_NAMES.contains(&name)
}

/// Receivers that name the agent master (`master`, `agent_master`, `self.master`). A receiver
/// without that name (for example a primary self-signing key) is the vault's own primary seam.
fn names_master(receiver: &syn::Expr) -> bool {
    match receiver {
        syn::Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment.ident.to_string().to_ascii_lowercase().contains("master")
        }),
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => name.to_string().to_ascii_lowercase().contains("master"),
            syn::Member::Unnamed(_) => false,
        },
        syn::Expr::Paren(paren) => names_master(&paren.expr),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for SeamUse {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_item_mod(self, item);
        self.leave(test);
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_item_fn(self, item);
        self.leave(test);
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_item_impl(self, item);
        self.leave(test);
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_impl_item_fn(self, item);
        self.leave(test);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if seam(&call.method.to_string()) && self.in_test == 0 && names_master(&call.receiver) {
            self.master_call = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let names: Vec<String> =
            path.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
        if names.windows(2).any(|pair| pair[0] == "MasterKey" && seam(&pair[1])) {
            self.master_path = true;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, depth + 1, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn is_test_file(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.contains("tests.rs")
        || relative.contains("_tests")
        || relative.contains("fixture")
}

#[test]
fn vault_seam_names_stay_inside_the_vault_layer() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let mut files = Vec::new();
    collect(&root.join("crates"), 0, &mut files)?;
    collect(&root.join("apps"), 0, &mut files)?;
    assert!(files.len() > 100, "the guard must see the whole source tree, saw {}", files.len());

    let mut offenders = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root)?.to_string_lossy().replace('\\', "/");
        if ALLOWED_PREFIXES.iter().any(|prefix| relative.starts_with(prefix))
            || is_test_file(&relative)
        {
            continue;
        }
        let source = std::fs::read_to_string(file)?;
        let parsed = syn::parse_file(&source)?;
        let mut visitor = SeamUse::default();
        visitor.visit_file(&parsed);
        if visitor.offends() {
            offenders.push(relative);
        }
    }
    assert!(
        offenders.is_empty(),
        "agent master seed seam used outside the vault layer (a seed must never leave a vault): {offenders:?}"
    );
    Ok(())
}

/// The detector must flag the forms it guards and must not flag test-only or primary-key uses.
#[test]
fn guard_detector_flags_master_seam_uses_only() -> TestResult {
    let flagged = |source: &str| -> Result<bool, Box<dyn std::error::Error>> {
        let parsed = syn::parse_file(source)?;
        let mut visitor = SeamUse::default();
        visitor.visit_file(&parsed);
        Ok(visitor.offends())
    };
    assert!(flagged("fn f(master: MasterKey) { let _ = master.vault_seed(); }")?);
    assert!(flagged("fn f() { let _ = MasterKey::from_vault_seed(&seed); }")?);
    assert!(flagged(
        "struct S { agent_master: MasterKey } impl S { fn f(&self) { let _ = self.agent_master.vault_seed(); } }"
    )?);
    assert!(!flagged("fn f(primary: SelfSigningKey) { let _ = primary.vault_seed(); }")?);
    assert!(!flagged(
        "#[cfg(test)] mod t { fn f(master: MasterKey) { let _ = master.vault_seed(); } }"
    )?);
    Ok(())
}

/// The one production file allowed to read a rebind's stored agent without the custodian check.
const STORED_AGENT_READER: &str = "crates/ramflux-sdk/src/custody/agent_creation/rebind_commit.rs";

/// The unverified stored-agent read. Only `rebind_commit` may call it (stage D R2b).
const UNVERIFIED_READ: &str = "stored_record_unverified";

/// Counts calls of [`UNVERIFIED_READ`] outside test-only items.
#[derive(Default)]
struct ReadCalls {
    in_test: usize,
    production_calls: usize,
}

impl ReadCalls {
    fn enter(&mut self, test: bool) {
        if test {
            self.in_test += 1;
        }
    }
    fn leave(&mut self, test: bool) {
        if test {
            self.in_test -= 1;
        }
    }
}

impl<'ast> Visit<'ast> for ReadCalls {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_item_mod(self, item);
        self.leave(test);
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_item_fn(self, item);
        self.leave(test);
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let test = is_test_only(&item.attrs);
        self.enter(test);
        syn::visit::visit_impl_item_fn(self, item);
        self.leave(test);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.in_test == 0
            && let syn::Expr::Path(path) = call.func.as_ref()
            && path.path.segments.last().is_some_and(|segment| segment.ident == UNVERIFIED_READ)
        {
            self.production_calls += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// The unverified stored-agent read has exactly one production caller, the commit of a rebind.
#[test]
fn stored_agent_read_has_one_production_caller() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let mut files = Vec::new();
    collect(&root.join("crates"), 0, &mut files)?;
    collect(&root.join("apps"), 0, &mut files)?;
    let mut callers = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root)?.to_string_lossy().replace('\\', "/");
        if is_test_file(&relative) {
            continue;
        }
        let source = std::fs::read_to_string(file)?;
        let parsed = syn::parse_file(&source)?;
        let mut visitor = ReadCalls::default();
        visitor.visit_file(&parsed);
        for _ in 0..visitor.production_calls {
            callers.push(relative.clone());
        }
    }
    assert_eq!(
        callers,
        vec![STORED_AGENT_READER.to_owned()],
        "the unverified stored-agent read must be called from rebind_commit only"
    );
    Ok(())
}
