// SPDX-License-Identifier: BSD-3-Clause
use crate::{
    CardError, CardSpec, SignedPackage, Tree,
    budget::{Budget, HEAP, Resident, STACK},
    tree::MAX_TREE,
};
use rquickjs::{Context, Function, Module, Runtime, context::intrinsic, object::Property};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

type Commit = Rc<RefCell<Option<Result<Tree, CardError>>>>;
/// A synchronous, thread-affine VM. No JS values or contexts cross the bridge.
pub struct CardRuntime {
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
        let loaded = context.with(|ctx| -> Result<(), CardError> {
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
            let module = load_verified(ctx.clone(), package)?;
            let (module, promise) = module.eval()?;
            promise.result::<()>().ok_or(CardError::Invalid("asynchronous module"))??;
            if count.get() != 0 {
                return Err(CardError::Invalid("module startup commit"));
            }
            let render: Function<'_> = module.get("render")?;
            ctx.globals().prop("__rf_render", Property::from(render))?;
            Ok(())
        });
        let elapsed = budget.borrow_mut().finish();
        elapsed?;
        loaded?;
        Ok(Self {
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
            let render: Function<'_> = ctx.globals().get("__rf_render")?;
            let result: rquickjs::Value<'_> = render.call((input,))?;
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

// The sole bytecode safety boundary. No unchecked or public load API exists.
#[allow(unsafe_code)]
fn load_verified<'js>(
    ctx: rquickjs::Ctx<'js>,
    package: &SignedPackage,
) -> Result<Module<'js>, CardError> {
    // SAFETY: SignedPackage is constructed only after verifying a project trust key,
    // the pinned engine/domain and bounded bytes. The signer must use this exact engine.
    // Bytecode is trusted executable code; a signature does not sanitize malicious code.
    Ok(unsafe { Module::load(ctx, &package.bytecode) }?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rquickjs::module::WriteOptions;
    pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(crate) fn package(source: &str) -> SignedPackage {
        let rt = Runtime::new().expect("test: compiler VM");
        rt.set_memory_limit(HEAP);
        rt.set_max_stack_size(STACK);
        let deadline = std::time::Instant::now();
        rt.set_interrupt_handler(Some(Box::new(move || {
            deadline.elapsed() >= std::time::Duration::from_millis(50)
        })));
        let ctx = Context::full(&rt).expect("test: compiler context");
        let bytes = ctx
            .with(|ctx| {
                Module::declare(ctx, "rf-library", source)
                    .and_then(|m| m.write(WriteOptions::default()))
            })
            .expect("test: compile project source");
        let key = SigningKey::from_bytes(&[7; 32]);
        let sig = key.sign(&crate::package::signing_message(&bytes));
        SignedPackage::verify(&bytes, &sig.to_bytes(), &key.verifying_key().to_bytes())
            .expect("test: signed package")
    }
    pub(crate) fn fixture() -> CardSpec {
        CardSpec::parse(include_bytes!("../fixtures/form.json")).expect("test: card fixture")
    }
    pub(crate) fn library() -> SignedPackage {
        package(include_str!("../library/form.js"))
    }

    #[test]
    fn rejects_infinite_loop_recursion_heap_and_ambient_authority() {
        let _guard = TEST_LOCK.lock().expect("test: serial VM capacity");
        let spec = fixture();
        for source in [
            "export function render(){for(;;){}}",
            "export function render(){function f(){return 1+f()} f()}",
            "export function render(){let a=[];for(;;)a.push('x'.repeat(1048576))}",
            "export function render(){eval('1')}",
            "export function render(){Function('return 1')()}",
            "export function render(){(function(){}).constructor('return 1')()}",
            "export function render(){fetch('https://example.invalid')}",
            "export function render(){__rf_commit('{}'); __rf_commit('{}')}",
        ] {
            let p = package(source);
            let mut vm = CardRuntime::new(&p, spec.clone()).expect("test: signed module setup");
            assert!(vm.render(&spec).is_err(), "hostile evaluation must fail: {source}");
            assert!(vm.render(&spec).is_err(), "failed VM must remain disabled");
        }
    }
    #[test]
    fn rejects_async_commit_even_with_a_valid_tree() {
        let _guard = TEST_LOCK.lock().expect("test: serial VM capacity");
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
        let p = library();
        let key = SigningKey::from_bytes(&[7; 32]);
        let sig = key.sign(&crate::package::signing_message(&p.bytecode));
        let mut bytes = p.bytecode.clone();
        bytes.push(0);
        assert!(
            SignedPackage::verify(&bytes, &sig.to_bytes(), &key.verifying_key().to_bytes())
                .is_err(),
            "changed bytecode must never reach loader"
        );
        assert!(
            SignedPackage::verify(
                &p.bytecode,
                &sig.to_bytes(),
                &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
            )
            .is_err(),
            "peer-selected key cannot replace pinned key"
        );
    }
}
