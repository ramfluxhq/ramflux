// SPDX-License-Identifier: BSD-3-Clause
use crate::{CardError, CardRuntime, CardSpec, Mutation, MutationBatch, SignedPackage, Tree};
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
    Edited {
        batch: MutationBatch,
    },
    /// Declarative intent only. The host SDK must authorize and send it.
    Submit {
        action: String,
        fields: BTreeMap<String, String>,
        batch: MutationBatch,
    },
}
/// A host-owned lifecycle; suspend releases VM capacity and invalidates all tokens.
pub struct CardSession {
    id: u64,
    version: u64,
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
        let batch = tree.diff(None, 0, 1);
        Ok((
            Self {
                id,
                version: 1,
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
                self.vm.take();
                self.queue.clear();
                return Err(error);
            }
        };
        let batch = tree.diff(self.tree.as_ref(), self.version, next);
        self.version = next;
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
        if event.token.key.len() > 80
            || matches!(&event.event, EventKind::Text { value } if value.len() > 4096)
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
        let form = self
            .spec
            .components
            .iter()
            .find(|form| match &event.event {
                EventKind::Text { .. } => event.token.key == format!("{}:field", form.id),
                EventKind::Submit => event.token.key == format!("{}:submit", form.id),
            })
            .ok_or(CardError::Invalid("event control"))?
            .clone();
        let binding = form.binding.strip_prefix('/').ok_or(CardError::Invalid("binding"))?;
        match event.event {
            EventKind::Text { value } => {
                let mut spec = self.spec.clone();
                spec.model.insert(binding.to_owned(), value);
                Ok(Some(EventResult::Edited { batch: self.update(spec)? }))
            }
            EventKind::Submit => {
                let value =
                    self.spec.model.get(binding).ok_or(CardError::Invalid("field"))?.clone();
                let next = self.next_version()?;
                let batch = MutationBatch {
                    previous_version: self.version,
                    version: next,
                    mutations: Vec::new(),
                };
                self.version = next; // one-use shown-tree submit, without SDK effects
                Ok(Some(EventResult::Submit {
                    action: form.submit,
                    fields: BTreeMap::from([(binding.to_owned(), value)]),
                    batch,
                }))
            }
        }
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
        let batch = MutationBatch { previous_version: self.version, version: next, mutations };
        self.version = next;
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
        let batch = tree.diff(None, self.version, next);
        self.vm = Some(vm);
        self.tree = Some(tree);
        self.version = next;
        Ok(batch)
    }
    fn next_version(&self) -> Result<u64, CardError> {
        self.version.checked_add(1).ok_or(CardError::Limit("tree version"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::{TEST_LOCK, fixture, library};
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
    #[test]
    fn form_fixture_tree_mutations_and_stale_events() {
        let _guard = TEST_LOCK.lock().expect("test: serial VM capacity");
        let (mut session, batch) =
            CardSession::open(fixture(), library()).expect("test: open form");
        let tree = serde_json::to_value(session.tree()).expect("test: snapshot");
        assert_eq!(
            tree,
            serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/form.tree.json"))
                .expect("test: expected tree"),
            "real bytecode must render the semantic fixture"
        );
        assert_eq!(
            serde_json::to_value(batch).expect("test: mutations"),
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
            serde_json::to_value(batch).expect("test: edit mutations"),
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
            BTreeMap::from([("name".into(), "Grace".into())]),
            "submit must include current owned fields only"
        );
        assert_eq!(action, "save", "action must come from validated card");
    }
    #[test]
    fn lifecycle_capacity_and_queue_are_bounded() {
        let _guard = TEST_LOCK.lock().expect("test: serial VM capacity");
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
