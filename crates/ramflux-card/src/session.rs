// SPDX-License-Identifier: BSD-3-Clause
use crate::{
    CardError, CardRuntime, CardSpec, Component, FieldKind, Mutation, MutationBatch, Scalar,
    SignedPackage, Tree,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_QUEUED_EVENTS: usize = 32;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
/// Scoped to one session and one committed tree. Keys alone never authorize events.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventToken {
    pub session: u64,
    pub version: u64,
    pub key: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    Text { value: String },
    Number { value: i64 },
    Select { value: String },
    Toggle { value: bool },
    Submit,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub token: EventToken,
    pub event: EventKind,
}
#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum EventResult {
    StaleDropped,
    Validation {
        batch: MutationBatch,
    },
    Edited {
        batch: MutationBatch,
    },
    /// Declarative intent only. The host SDK must authorize and send it.
    Submit {
        action: String,
        fields: BTreeMap<String, Scalar>,
        batch: MutationBatch,
    },
}
/// A host-owned lifecycle; suspend releases VM capacity and invalidates all tokens.
pub struct CardSession {
    id: u64,
    version: u64,
    mounted_version: u64,
    spec: CardSpec,
    package: SignedPackage,
    vm: Option<CardRuntime>,
    tree: Option<Tree>,
    queue: VecDeque<Event>,
    budget: std::rc::Rc<std::cell::RefCell<crate::budget::Budget>>,
}
impl CardSession {
    /// Open only from validated declarative JSON and a verified package.
    /// # Errors
    /// Returns validation, engine, capacity or budget errors without a partial session.
    pub fn open(
        spec: CardSpec,
        package: SignedPackage,
    ) -> Result<(Self, MutationBatch), CardError> {
        let id = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| CardError::Limit("session identifiers"))?;
        let budget = crate::budget::Budget::new();
        let mut vm = CardRuntime::with_budget(&package, spec.clone(), std::rc::Rc::clone(&budget))?;
        let tree = vm.render(&spec)?;
        let mut batch = tree.diff(None, 0, 1);
        batch.host_slots = spec.slots();
        Ok((
            Self {
                id,
                version: 1,
                mounted_version: 1,
                spec,
                package,
                vm: Some(vm),
                tree: Some(tree),
                queue: VecDeque::new(),
                budget,
            },
            batch,
        ))
    }
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub const fn tree(&self) -> Option<&Tree> {
        self.tree.as_ref()
    }
    /// Update a whole snapshot; every accepted snapshot advances the tree version.
    /// # Errors
    /// Fails validation or disables the VM on an evaluation failure.
    pub fn update(&mut self, spec: CardSpec) -> Result<MutationBatch, CardError> {
        spec.validate()?;
        let next = self.next_version()?;
        let result = self.vm.as_mut().ok_or(CardError::Inactive)?.render(&spec);
        let tree = match result {
            Ok(tree) => tree,
            Err(error) => {
                if self.vm.as_ref().is_some_and(CardRuntime::has_failed) {
                    self.vm.take();
                    self.queue.clear();
                    self.version = next;
                }
                return Err(error);
            }
        };
        let mut batch = tree.diff(self.tree.as_ref(), self.mounted_version, next);
        batch.host_slots = spec.slots();
        self.version = next;
        self.mounted_version = next;
        self.spec = spec;
        self.tree = Some(tree);
        Ok(batch)
    }
    /// Queue at most 32 bounded events; stale tokens are checked again on delivery.
    /// # Errors
    /// Rejects queue overflow and oversized strings before allocating queue storage.
    pub fn enqueue(&mut self, event: Event) -> Result<(), CardError> {
        if self.queue.len() >= MAX_QUEUED_EVENTS {
            return Err(CardError::Limit("event queue"));
        }
        if event.token.key.len() > 160
            || matches!(&event.event, EventKind::Text { value } | EventKind::Select { value } if value.len() > 4096)
        {
            return Err(CardError::Limit("event"));
        }
        self.queue.push_back(event);
        Ok(())
    }
    /// Deliver one queued event against the currently displayed tree.
    /// # Errors
    /// Rejects inactive sessions, invalid control kinds and invalid model changes.
    pub fn next_event(&mut self) -> Result<Option<EventResult>, CardError> {
        let Some(event) = self.queue.pop_front() else {
            return Ok(None);
        };
        if event.token.session != self.id || event.token.version != self.version {
            return Ok(Some(EventResult::StaleDropped));
        }
        if self.vm.is_none() {
            return Err(CardError::Inactive);
        }
        let (form, field) = self
            .spec
            .components
            .iter()
            .filter_map(|c| if let Component::Form(form) = c { Some(form) } else { None })
            .find_map(|form| {
                if matches!(event.event, EventKind::Submit)
                    && event.token.key == format!("{}:submit", form.id)
                {
                    return Some((form.clone(), None));
                }
                form.normalized_fields()
                    .into_iter()
                    .find(|f| event.token.key == format!("{}:{}", form.id, f.id))
                    .map(|f| (form.clone(), Some(f)))
            })
            .ok_or(CardError::Invalid("event control"))?;
        if form.disabled || field.as_ref().is_some_and(|f| f.disabled) {
            return Err(CardError::Invalid("disabled control"));
        }
        if matches!(event.event, EventKind::Submit) {
            if field.is_some() {
                return Err(CardError::Invalid("submit control"));
            }
            let mut errors = BTreeMap::new();
            let mut fields = BTreeMap::new();
            for f in form.normalized_fields().into_iter().filter(|f| !f.disabled) {
                let binding = f.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?;
                let value = self.spec.model.get(binding).ok_or(CardError::Invalid("field"))?;
                let missing = f.required
                    && match value {
                        Scalar::Text(v) => v.trim().is_empty(),
                        Scalar::Toggle(v) => !*v,
                        Scalar::Number(_) => false,
                    };
                if missing {
                    errors.insert(f.id.clone(), "Required".to_owned());
                } else if let Some(error) = &f.error {
                    errors.insert(f.id.clone(), error.clone());
                }
                fields.insert(binding.to_owned(), value.clone());
            }
            if !errors.is_empty() {
                let mut spec = self.spec.clone();
                for c in &mut spec.components {
                    if let Component::Form(candidate) = c {
                        if candidate.id == form.id {
                            for f in &mut candidate.fields {
                                if let Some(error) = errors.get(&f.id) {
                                    f.error = Some(error.clone());
                                }
                            }
                        }
                    }
                }
                return Ok(Some(EventResult::Validation { batch: self.update(spec)? }));
            }
            let next = self.next_version()?;
            let batch = MutationBatch {
                previous_version: self.mounted_version,
                version: next,
                mutations: Vec::new(),
                host_slots: self.spec.slots(),
            };
            self.version = next;
            self.mounted_version = next;
            return Ok(Some(EventResult::Submit { action: form.submit, fields, batch }));
        }
        let field = field.ok_or(CardError::Invalid("field control"))?;
        let value = match (event.event, field.kind) {
            (EventKind::Text { value }, FieldKind::Input)
            | (EventKind::Select { value }, FieldKind::Select) => Scalar::Text(value),
            (EventKind::Number { value }, FieldKind::Number) => Scalar::Number(value),
            (EventKind::Toggle { value }, FieldKind::Toggle) => Scalar::Toggle(value),
            _ => return Err(CardError::Invalid("event value type")),
        };
        let binding = field.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?;
        let mut spec = self.spec.clone();
        spec.model.insert(binding.into(), value);
        for c in &mut spec.components {
            if let Component::Form(candidate) = c {
                if candidate.id == form.id {
                    for f in &mut candidate.fields {
                        if f.id == field.id {
                            f.error = None;
                        }
                    }
                }
            }
        }
        Ok(Some(EventResult::Edited { batch: self.update(spec)? }))
    }
    /// Release the interpreter and remove the mounted tree. Repeated suspension is safe.
    /// # Errors
    /// Fails only if the monotonic version space is exhausted.
    pub fn suspend(&mut self) -> Result<MutationBatch, CardError> {
        let next = self.next_version()?;
        let mutations = self.tree.as_ref().map_or_else(Vec::new, |t| {
            // Removing a root removes its complete native subtree.
            vec![Mutation::Remove { key: t.root.key.clone() }]
        });
        self.vm.take();
        self.tree.take();
        self.queue.clear();
        let batch = MutationBatch {
            previous_version: self.mounted_version,
            version: next,
            mutations,
            host_slots: Vec::new(),
        };
        self.version = next;
        self.mounted_version = next;
        Ok(batch)
    }
    /// Recreate a budgeted VM and publish a full tree after suspension.
    /// # Errors
    /// Fails if already active or package evaluation/capacity fails.
    pub fn resume(&mut self) -> Result<MutationBatch, CardError> {
        if self.vm.is_some() {
            return Err(CardError::Invalid("already active"));
        }
        let next = self.next_version()?;
        let mut vm = CardRuntime::with_budget(
            &self.package,
            self.spec.clone(),
            std::rc::Rc::clone(&self.budget),
        )?;
        let tree = vm.render(&self.spec)?;
        let mut batch = tree.diff(self.tree.as_ref(), self.mounted_version, next);
        batch.host_slots = self.spec.slots();
        self.vm = Some(vm);
        self.tree = Some(tree);
        self.version = next;
        self.mounted_version = next;
        Ok(batch)
    }
    fn next_version(&self) -> Result<u64, CardError> {
        self.version.checked_add(1).ok_or(CardError::Limit("tree version"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::{fixture, guard, library};
    fn event(session: &CardSession, key: &str, kind: EventKind) -> Event {
        Event {
            token: EventToken {
                session: session.id(),
                version: session.version(),
                key: key.into(),
            },
            event: kind,
        }
    }
    fn without_style(mut batch: MutationBatch) -> MutationBatch {
        for mutation in &mut batch.mutations {
            if let Mutation::Upsert { node, .. } = mutation {
                node.attrs.style = None;
            }
        }
        batch
    }
    #[test]
    fn form_fixture_tree_mutations_and_stale_events() {
        let _guard = guard();
        let (mut session, batch) =
            CardSession::open(fixture(), library()).expect("test: open form");
        let tree =
            serde_json::to_value(session.tree().map(Tree::without_style)).expect("test: snapshot");
        assert_eq!(
            tree,
            serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/form.tree.json"))
                .expect("test: expected tree"),
            "real bytecode must render the semantic fixture"
        );
        assert_eq!(
            serde_json::to_value(without_style(batch)).expect("test: mutations"),
            serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/form.mount.json"))
                .expect("test: expected mutations"),
            "initial keyed mount must match snapshot"
        );
        let stale = event(&session, "profile:submit", EventKind::Submit);
        session
            .enqueue(event(&session, "profile:field", EventKind::Text { value: "Grace".into() }))
            .expect("test: queue edit");
        let Some(EventResult::Edited { batch }) = session.next_event().expect("test: edit") else {
            panic!("test: expected edit batch");
        };
        assert_eq!(
            serde_json::to_value(without_style(batch)).expect("test: edit mutations"),
            serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/form.edit.json"))
                .expect("test: expected edit"),
            "text edit must update only its keyed field"
        );
        session.enqueue(stale).expect("test: queue old token");
        assert!(
            matches!(
                session.next_event().expect("test: stale delivery"),
                Some(EventResult::StaleDropped)
            ),
            "old tree cannot submit after an edit"
        );
        session
            .enqueue(event(&session, "profile:submit", EventKind::Submit))
            .expect("test: queue submit");
        let Some(EventResult::Submit { fields, action, .. }) =
            session.next_event().expect("test: submit")
        else {
            panic!("test: expected intent");
        };
        assert_eq!(
            fields,
            BTreeMap::from([("name".into(), Scalar::Text("Grace".into()))]),
            "submit must include current owned fields only"
        );
        assert_eq!(action, "save", "action must come from validated card");
    }
    #[test]
    fn lifecycle_capacity_and_queue_are_bounded() {
        let _guard = guard();
        let p = library();
        let (mut a, _) = CardSession::open(fixture(), p.clone()).expect("test: first VM");
        let (_b, _) = CardSession::open(fixture(), p.clone()).expect("test: second VM");
        assert!(
            CardSession::open(fixture(), p.clone()).is_err(),
            "third resident VM must be rejected"
        );
        let stale = event(&a, "profile:submit", EventKind::Submit);
        for _ in 0..MAX_QUEUED_EVENTS {
            a.enqueue(stale.clone()).expect("test: bounded queue admission");
        }
        assert!(a.enqueue(stale.clone()).is_err(), "queue must reject the 33rd event");
        a.suspend().expect("test: suspend");
        {
            let (_c, _) =
                CardSession::open(fixture(), p).expect("test: suspended VM frees capacity");
        }
        a.resume().expect("test: resume");
        a.enqueue(stale).expect("test: old event");
        assert!(
            matches!(
                a.next_event().expect("test: stale after resume"),
                Some(EventResult::StaleDropped)
            ),
            "resume must never resurrect old tokens"
        );
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use crate::{
        Form, Node, NodeKind,
        runtime::tests::{fixture, guard, library, package},
    };
    fn token(session: &CardSession, key: &str, event: EventKind) -> Event {
        Event {
            token: EventToken {
                session: session.id(),
                version: session.version(),
                key: key.into(),
            },
            event,
        }
    }
    fn spec(ids: &[&str]) -> CardSpec {
        let mut spec = fixture();
        spec.components = ids
            .iter()
            .map(|id| Form {
                id: (*id).into(),
                component: "rf.form".into(),
                title: format!("Form {id}"),
                label: "Name".into(),
                binding: format!("/{id}"),
                submit: format!("save-{id}"),
            })
            .collect();
        spec.model = ids.iter().map(|id| ((*id).into(), format!("Value {id}"))).collect();
        spec
    }
    fn shallow(node: &Node) -> Node {
        let mut node = node.clone();
        node.children.clear();
        node
    }
    fn form_node(session: &CardSession, key: &str) -> Node {
        shallow(
            session
                .tree()
                .expect("test: mounted tree")
                .root
                .children
                .iter()
                .find(|n| n.key == key)
                .expect("test: expected form"),
        )
    }
    #[test]
    fn real_two_form_diff_covers_reorder_middle_insert_remove_and_value() {
        let _guard = guard();
        let (mut session, _) =
            CardSession::open(spec(&["a", "b"]), library()).expect("test: two forms");
        let batch = session.update(spec(&["b", "a"])).expect("test: reorder");
        assert_eq!(
            batch.mutations,
            vec![
                Mutation::Upsert {
                    parent: Some("root".into()),
                    index: 0,
                    node: form_node(&session, "b")
                },
                Mutation::Upsert {
                    parent: Some("root".into()),
                    index: 1,
                    node: form_node(&session, "a")
                }
            ],
            "reorder must only move both form keys"
        );
        let batch = session.update(spec(&["b", "c", "a"])).expect("test: middle insertion");
        let c = session
            .tree()
            .expect("test: tree")
            .root
            .children
            .iter()
            .find(|n| n.key == "c")
            .expect("test: inserted form");
        let field = c.children.first().expect("test: field");
        let submit = c.children.get(1).expect("test: submit");
        assert_eq!(
            batch.mutations,
            vec![
                Mutation::Upsert { parent: Some("root".into()), index: 1, node: shallow(c) },
                Mutation::Upsert { parent: Some("c".into()), index: 0, node: shallow(field) },
                Mutation::Upsert { parent: Some("c".into()), index: 1, node: shallow(submit) },
                Mutation::Upsert {
                    parent: Some("root".into()),
                    index: 2,
                    node: form_node(&session, "a")
                }
            ],
            "middle insert must mount only the new subtree and move the following sibling"
        );
        let batch = session.update(spec(&["b", "a"])).expect("test: middle removal");
        assert_eq!(
            batch.mutations,
            vec![
                Mutation::Remove { key: "c:submit".into() },
                Mutation::Remove { key: "c:field".into() },
                Mutation::Remove { key: "c".into() },
                Mutation::Upsert {
                    parent: Some("root".into()),
                    index: 1,
                    node: form_node(&session, "a")
                }
            ],
            "middle removal must remove children before parent and reposition the sibling"
        );
        let mut changed = spec(&["b", "a"]);
        changed.model.insert("a".into(), "Changed".into());
        let batch = session.update(changed).expect("test: value edit");
        assert_eq!(
            batch.mutations,
            vec![Mutation::Upsert {
                parent: Some("a".into()),
                index: 0,
                node: Node {
                    key: "a:field".into(),
                    kind: NodeKind::TextField,
                    text: "Name".into(),
                    value: "Changed".into(),
                    action: None,
                    children: Vec::new()
                }
            }],
            "value-only edits must not remount siblings or form containers"
        );
    }
    #[test]
    fn replay_foreign_wrong_kind_and_oversized_events_do_not_corrupt_session() {
        const MODEL_BOUND: usize = 4096;
        const KEY_BOUND: usize = 80;
        let _guard = guard();
        let (mut session, _) = CardSession::open(fixture(), library()).expect("test: session");
        let submit = token(&session, "profile:submit", EventKind::Submit);
        session.enqueue(submit.clone()).expect("test: first submit");
        assert!(
            matches!(session.next_event().expect("test: submit"), Some(EventResult::Submit { .. })),
            "current submit must emit an intent"
        );
        session.enqueue(submit).expect("test: replay queue");
        assert!(
            matches!(session.next_event().expect("test: replay"), Some(EventResult::StaleDropped)),
            "replayed submit must be dropped"
        );
        let mut foreign = token(&session, "profile:submit", EventKind::Submit);
        foreign.token.session = 0;
        session.enqueue(foreign).expect("test: foreign queue");
        assert!(
            matches!(session.next_event().expect("test: foreign"), Some(EventResult::StaleDropped)),
            "foreign session token must be dropped"
        );
        session
            .enqueue(token(&session, "profile:submit", EventKind::Text { value: "wrong".into() }))
            .expect("test: mismatched event queue");
        assert!(
            matches!(session.next_event(), Err(CardError::Invalid("event control"))),
            "text cannot target a submit control"
        );
        assert!(
            session
                .enqueue(token(&session, &"x".repeat(KEY_BOUND + 1), EventKind::Submit))
                .is_err(),
            "oversized key must fail before enqueue"
        );
        assert!(
            session
                .enqueue(token(
                    &session,
                    "profile:field",
                    EventKind::Text { value: "x".repeat(MODEL_BOUND + 1) }
                ))
                .is_err(),
            "oversized text must fail before enqueue"
        );
        let prior = session.version();
        session
            .enqueue(token(
                &session,
                "profile:field",
                EventKind::Text { value: "x".repeat(MODEL_BOUND) },
            ))
            .expect("test: boundary event enqueued");
        assert!(
            matches!(session.next_event(), Err(CardError::Limit("model"))),
            "JSON model overhead must reject the boundary text value"
        );
        assert_eq!(
            session.version(),
            prior,
            "pre-evaluation rejection cannot consume a tree version"
        );
        session.update(fixture()).expect("test: VM remains usable after rejected model");
    }
    #[test]
    fn failed_evaluation_invalidates_tokens_and_resume_diffs_the_displayed_tree() {
        let _guard = guard();
        let source = include_str!("../library/form.js")
            .replace("function render(", "function renderForm(")
            + "\nlet calls=0;function render(input){if(++calls===2)throw 1;renderForm(input)}";
        let (mut session, _) =
            CardSession::open(fixture(), package(&source)).expect("test: first successful mount");
        let old = token(&session, "profile:submit", EventKind::Submit);
        let displayed = session.tree().cloned().expect("test: displayed tree");
        assert!(
            matches!(session.update(fixture()), Err(CardError::Script)),
            "second evaluation must fail with script error"
        );
        session.enqueue(old).expect("test: stale token queue");
        assert!(
            matches!(
                session.next_event().expect("test: stale token"),
                Some(EventResult::StaleDropped)
            ),
            "VM loss must invalidate old tokens"
        );
        let batch = session.resume().expect("test: resume without suspend");
        assert_eq!(batch.previous_version, 1, "resume must start from the native mounted version");
        assert!(
            batch.version > 2 && batch.mutations.is_empty(),
            "identical recovered tree must advance version without a double mount"
        );
        assert_eq!(
            session.tree(),
            Some(&displayed),
            "native tree identity must be preserved across recovery"
        );
    }
    #[test]
    fn admission_budget_rejection_preserves_live_vm() {
        let _guard = guard();
        let (mut session, _) = CardSession::open(fixture(), library()).expect("test: live VM");
        session.budget.borrow_mut().deny_for_test();
        let version = session.version();
        assert!(
            matches!(session.update(fixture()), Err(CardError::Budget)),
            "admission must enforce bounded recent evaluations"
        );
        assert!(
            session.vm.is_some() && session.version() == version,
            "no-work admission rejection must retain the live VM and version"
        );
        session.budget.borrow_mut().reset_for_test();
        session.update(fixture()).expect("test: original VM usable after budget window reset");
    }
}
