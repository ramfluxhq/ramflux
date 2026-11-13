// SPDX-License-Identifier: BSD-3-Clause
use crate::{
    CardError, CardSpec, SignedPackage, Tree,
    budget::{Budget, HEAP, Resident, STACK},
    tree::MAX_TREE,
};
use rquickjs::{
    Context, Function, Module, Persistent, Runtime, context::intrinsic, object::Property,
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

type Commit = Rc<RefCell<Option<Result<Tree, CardError>>>>;
/// A synchronous, thread-affine VM. No JS values or contexts cross the bridge.
pub struct CardRuntime {
    render: Persistent<Function<'static>>,
    context: Context,
    _runtime: Runtime,
    budget: Rc<RefCell<Budget>>,
    spec: Rc<RefCell<CardSpec>>,
    commit: Commit,
    count: Rc<Cell<u32>>,
    failed: bool,
    _resident: Resident,
}
impl CardRuntime {
    /// Construct an interpreter with all three budgets and a verified module.
    /// # Errors
    /// Fails on VM capacity, budgets, engine errors or an invalid module export.
    pub fn new(package: &SignedPackage, spec: CardSpec) -> Result<Self, CardError> {
        Self::with_budget(package, spec, Budget::new())
    }
    pub(crate) fn with_budget(
        package: &SignedPackage,
        spec: CardSpec,
        budget: Rc<RefCell<Budget>>,
    ) -> Result<Self, CardError> {
        spec.validate()?;
        let resident = Resident::acquire()?;
        let runtime = Runtime::new()?;
        runtime.set_memory_limit(HEAP);
        runtime.set_max_stack_size(STACK);
        let interrupt = Rc::clone(&budget);
        runtime.set_interrupt_handler(Some(Box::new(move || interrupt.borrow_mut().interrupted())));
        // Eval is deliberately absent, including Function constructor compilation.
        let context = Context::custom::<(intrinsic::Json, intrinsic::Promise)>(&runtime)?;
        let spec = Rc::new(RefCell::new(spec));
        let commit: Commit = Rc::new(RefCell::new(None));
        let count = Rc::new(Cell::new(0_u32));
        budget.borrow_mut().begin()?;
        let loaded = context.with(|ctx| -> Result<Persistent<Function<'static>>, CardError> {
            let shared = Rc::clone(&commit);
            let current = Rc::clone(&spec);
            let calls = Rc::clone(&count);
            let host = Function::new(
                ctx.clone(),
                move |value: rquickjs::String<'_>| -> rquickjs::Result<()> {
                    calls.set(calls.get().saturating_add(1));
                    if calls.get() != 1 {
                        *shared.borrow_mut() = Some(Err(CardError::Invalid("multiple commits")));
                        return Ok(());
                    }
                    // CString conversion stays in the VM allocator; bound before copying into Rust.
                    let value = value.to_cstring()?;
                    let result = if value.len() > MAX_TREE {
                        Err(CardError::Limit("commit bytes"))
                    } else {
                        Tree::parse(value.as_str().as_bytes(), &current.borrow())
                    };
                    *shared.borrow_mut() = Some(result);
                    Ok(())
                },
            )?;
            ctx.globals().prop("__rf_commit", Property::from(host))?;
            let bootstrap = load_bootstrap(ctx.clone()).map_err(|_| CardError::Hardening)?;
            let (_, done) = bootstrap.eval().map_err(|_| CardError::Hardening)?;
            done.result::<()>().ok_or(CardError::Hardening)?.map_err(|_| CardError::Hardening)?;
            let module = load_verified(ctx.clone(), package)?;
            let (module, promise) = module.eval().map_err(|error| classify_error(&ctx, &error))?;
            promise
                .result::<()>()
                .ok_or(CardError::Invalid("asynchronous module"))?
                .map_err(|error| classify_error(&ctx, &error))?;
            if count.get() != 0 {
                return Err(CardError::Invalid("module startup commit"));
            }
            let render: Function<'_> =
                module.get("render").map_err(|error| classify_error(&ctx, &error))?;
            Ok(Persistent::save(&ctx, render))
        });
        let elapsed = budget.borrow_mut().finish();
        elapsed?;
        let render = loaded?;
        Ok(Self {
            render,
            context,
            _runtime: runtime,
            budget,
            spec,
            commit,
            count,
            failed: false,
            _resident: resident,
        })
    }
    pub(crate) const fn has_failed(&self) -> bool {
        self.failed
    }
    /// Evaluate a complete new declarative snapshot, validating before publication.
    /// # Errors
    /// A failed evaluation disables this VM; callers must dispose or suspend it.
    pub fn render(&mut self, spec: &CardSpec) -> Result<Tree, CardError> {
        if self.failed {
            return Err(CardError::Inactive);
        }
        spec.validate()?;
        let input = spec.render_input()?;
        self.budget.borrow_mut().begin()?;
        *self.spec.borrow_mut() = spec.clone();
        self.commit.borrow_mut().take();
        self.count.set(0);
        let result = self.context.with(|ctx| -> Result<(), CardError> {
            let render = self.render.clone().restore(&ctx)?;
            let result: rquickjs::Value<'_> =
                render.call((input,)).map_err(|error| classify_error(&ctx, &error))?;
            if !result.is_undefined() {
                return Err(CardError::Invalid("non-synchronous render"));
            }
            Ok(())
        });
        let elapsed = self.budget.borrow_mut().finish();
        let committed = self.commit.borrow_mut().take().ok_or(CardError::Invalid("missing commit"));
        let result = elapsed.and(result).and(committed).and_then(std::convert::identity);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn classify_error(ctx: &rquickjs::Ctx<'_>, error: &rquickjs::Error) -> CardError {
    match error {
        rquickjs::Error::Allocation => CardError::Memory,
        rquickjs::Error::Exception => {
            let thrown = ctx.catch();
            let kind = ctx
                .globals()
                .get::<_, Function<'_>>("__rf_error_kind")
                .and_then(|function| function.call::<_, String>((thrown,)));
            match kind.as_deref() {
                Ok("memory") => CardError::Memory,
                Ok("stack") => CardError::Stack,
                _ => CardError::Script,
            }
        }
        _ => CardError::Engine,
    }
}
#[allow(unsafe_code)]
fn load_bootstrap(ctx: rquickjs::Ctx<'_>) -> Result<Module<'_>, CardError> {
    // SAFETY: bytes are generated only by build.rs from the host-owned bootstrap
    // using the same exact engine pin and shared little-endian compiler path.
    Ok(unsafe { Module::load(ctx, include_bytes!(concat!(env!("OUT_DIR"), "/bootstrap.qjb"))) }?)
}

// Package bytecode is admitted only through the verified descriptor/policy type.
#[allow(unsafe_code)]
fn load_verified<'js>(
    ctx: rquickjs::Ctx<'js>,
    package: &SignedPackage,
) -> Result<Module<'js>, CardError> {
    // SAFETY: SignedPackage is constructed only after verifying a project trust key,
    // canonical descriptor, exact engine/catalog/ABI, bytecode digest and host release
    // acceptance policy. The signer uses the same pinned little-endian compiler.
    // Bytecode is trusted executable code; a signature does not sanitize malicious code.
    unsafe { Module::load(ctx.clone(), &package.bytecode) }
        .map_err(|error| classify_error(&ctx, &error))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::compiler::{PackageRelease, compile_and_sign};
    use ed25519_dalek::SigningKey;
    pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(crate) fn guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(crate) fn release() -> PackageRelease {
        PackageRelease {
            app_id: "org.ramflux.card".into(),
            package_id: "ramflux-card-library".into(),
            security_epoch: 1,
            version: 2,
        }
    }
    pub(crate) fn artifact(source: &str) -> crate::compiler::CompiledPackage {
        compile_and_sign(source.as_bytes(), &SigningKey::from_bytes(&[7; 32]), &release())
            .expect("test: compile and sign project source")
    }
    pub(crate) fn package(source: &str) -> SignedPackage {
        let p = artifact(source);
        SignedPackage::verify(
            &p.bytecode,
            &p.descriptor,
            &p.signature,
            &p.public_key,
            &release().policy(),
        )
        .expect("test: signed accepted package")
    }
    pub(crate) fn fixture() -> CardSpec {
        CardSpec::parse(include_bytes!("../fixtures/form.json")).expect("test: card fixture")
    }
    pub(crate) fn library() -> SignedPackage {
        package(include_str!("../library/form.js"))
    }

    #[test]
    fn rejects_infinite_loop_recursion_heap_and_ambient_authority() {
        let _guard = guard();
        let spec = fixture();
        let valid = library();
        for (source, expected) in [
            ("export function render(){for(;;){}}", "budget"),
            ("export function render(){function f(){return 1+f()} f()}", "stack"),
            (
                "export function render(){const value='x'.repeat(67108864);__rf_commit(value)}",
                "memory",
            ),
            ("export function render(){eval('1')}", "script"),
            ("export function render(){Function('return 1')()}", "script"),
            ("export function render(){(function(){}).constructor('return 1')()}", "script"),
            ("export function render(){fetch('https://example.invalid')}", "script"),
            ("export function render(){__rf_commit('{}');__rf_commit('{}')}", "commit"),
        ] {
            let p = package(source);
            let mut vm = CardRuntime::new(&p, spec.clone()).expect("test: signed module setup");
            let error = vm.render(&spec).expect_err("test: hostile evaluation must reject");
            assert!(
                matches!(
                    (expected, &error),
                    ("budget", CardError::Budget)
                        | ("stack", CardError::Stack)
                        | ("memory", CardError::Memory)
                        | ("script", CardError::Script)
                        | ("commit", CardError::Invalid("multiple commits"))
                ),
                "wrong rejection for {expected}: {error:?}"
            );
            assert!(
                matches!(vm.render(&spec), Err(CardError::Inactive)),
                "failed VM must remain disabled"
            );
            drop(vm);
            let mut first =
                CardRuntime::new(&valid, spec.clone()).expect("test: released VM capacity first");
            let mut second =
                CardRuntime::new(&valid, spec.clone()).expect("test: released VM capacity second");
            first.render(&spec).expect("test: replacement renders");
            second.render(&spec).expect("test: second replacement renders");
        }
    }
    #[test]
    fn startup_limits_have_the_same_typed_errors_as_render() {
        let _guard = guard();
        for (source, kind) in [
            ("while(true){};export function render(){}", "budget"),
            ("const huge='x'.repeat(67108864);export function render(){}", "memory"),
            ("function f(){return 1+f()}f();export function render(){}", "stack"),
        ] {
            let result = CardRuntime::new(&package(source), fixture());
            assert!(
                matches!(
                    (kind, result),
                    ("budget", Err(CardError::Budget))
                        | ("memory", Err(CardError::Memory))
                        | ("stack", Err(CardError::Stack))
                ),
                "startup {kind} must preserve the engine-reported limit category"
            );
        }
    }
    #[test]
    fn host_bootstrap_freezes_reachable_intrinsics_before_package() {
        let _guard = guard();
        let probe = r"function probe(){
            const roots=[Object,JSON,Array,Object.getPrototypeOf([]),Object.getPrototypeOf({}),String,Object.getPrototypeOf(''),Number,Object.getPrototypeOf(0),Boolean,Object.getPrototypeOf(true),Promise,Object.getPrototypeOf(Promise.resolve()),Reflect,Object.getPrototypeOf(function(){}),Object.getPrototypeOf(async function(){}),Object.getPrototypeOf(function*(){}),Object.getPrototypeOf(async function*(){})];
            for(const root of roots){let value=root;while(value!==null){if(!Object.isFrozen(value))throw new Error('mutable intrinsic');value=Object.getPrototypeOf(value)}}
            const prototype=Object.getPrototypeOf([]);const originalMap=prototype.map;let refused=false;
            try{Object.defineProperty(prototype,'map',{value:function(){return []}})}catch(error){refused=true}
            if(!refused || prototype.map!==originalMap || !Object.isFrozen(globalThis))throw new Error('descriptor write accepted');
        }";
        let source = include_str!("../library/form.js")
            .replace("function render(", "function renderForm(")
            + probe
            + "\nfunction render(input){probe();renderForm(input)}";
        let spec = fixture();
        let mut vm =
            CardRuntime::new(&package(&source), spec.clone()).expect("test: hardened module");
        let first = vm.render(&spec).expect("test: first hardened render");
        assert_eq!(
            vm.render(&spec).expect("test: second hardened render"),
            first,
            "prototype changes cannot persist across renders"
        );
    }
    #[test]
    fn rejects_async_commit_even_with_a_valid_tree() {
        let _guard = guard();
        let source = include_str!("../library/form.js")
            .replace("function render(", "async function render(");
        let spec = fixture();
        let mut vm =
            CardRuntime::new(&package(&source), spec.clone()).expect("test: async module setup");
        assert!(
            vm.render(&spec).is_err(),
            "a synchronous commit must not admit an asynchronous renderer"
        );
    }
    #[test]
    fn signature_tampering_is_rejected_before_load() {
        let p = artifact(include_str!("../library/form.js"));
        let mut bytes = p.bytecode.clone();
        bytes.push(0);
        assert!(
            SignedPackage::verify(
                &bytes,
                &p.descriptor,
                &p.signature,
                &p.public_key,
                &release().policy()
            )
            .is_err(),
            "changed bytecode must never reach loader"
        );
        assert!(
            SignedPackage::verify(
                &p.bytecode,
                &p.descriptor,
                &p.signature,
                &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
                &release().policy()
            )
            .is_err(),
            "wrong release key must reject"
        );
    }
}
