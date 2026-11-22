// SPDX-License-Identifier: BSD-3-Clause
//! Session-local drafts, lifecycle and version-fenced semantic events.
use crate::{
    CardError, CardRuntime, CardSpec, MutationBatch, SignedPackage, Tree,
    projection::{self, LocalState},
    spec::MAX_SAFE_INTEGER,
};
use ramflux_protocol::a2ui::{ResolvedAction, ResolvedActionKind, SurfaceDrafts};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
};
const MAX_QUEUED_EVENTS: usize = 32;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventToken {
    pub session: u64,
    pub signed_version: u64,
    pub edit_seq: u64,
    pub tree_version: u64,
    pub key: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostEventKind {
    Input { value: Value },
    Activate,
    SelectTab { index: usize },
    ModalOpen,
    ModalClose,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostEvent {
    pub token: EventToken,
    pub event: HostEventKind,
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
    /// The SDK builds/signs an `ActionFrame` using this resolver-selected action and
    /// the current resolved surface. The runtime performs no network dispatch.
    Submit {
        action: Box<ResolvedAction>,
        batch: MutationBatch,
    },
}
pub struct CardSession {
    id: u64,
    spec: CardSpec,
    package: SignedPackage,
    vm: Option<CardRuntime>,
    tree: Option<Tree>,
    version: u64,
    edit_seq: u64,
    local: LocalState,
    queue: VecDeque<HostEvent>,
    budget: std::rc::Rc<std::cell::RefCell<crate::budget::Budget>>,
    retired: bool,
    draft_conflict: bool,
}
impl CardSession {
    /// Open an authorized snapshot through the shared resolver and verified library.
    /// # Errors
    /// Refuses invalid state, package, budgets or exhausted session identifiers.
    pub fn open(
        spec: CardSpec,
        package: SignedPackage,
    ) -> Result<(Self, MutationBatch), CardError> {
        spec.validate()?;
        let id = fresh_id()?;
        let budget = crate::budget::Budget::new();
        let local = LocalState::default();
        let mut candidate = spec.clone();
        candidate.render_tree = Some(projection::project(&spec, id, 1, 0, &local)?);
        let mut vm =
            CardRuntime::with_budget(&package, candidate.clone(), std::rc::Rc::clone(&budget))?;
        let tree = vm.render(&candidate)?;
        let batch = tree.diff(None, 0, 1)?;
        Ok((
            Self {
                id,
                spec,
                package,
                vm: Some(vm),
                tree: Some(tree),
                version: 1,
                edit_seq: 0,
                local,
                queue: VecDeque::new(),
                budget,
                retired: false,
                draft_conflict: false,
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
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.vm.as_ref().is_some_and(|vm| !vm.has_failed()) && !self.retired
    }
    /// Current resolver data for SDK action construction, with raw local inputs.
    /// # Errors
    /// Refuses inactive sessions or invalid resolver state.
    pub fn resolved(&self) -> Result<ramflux_protocol::a2ui::ResolvedSurface, CardError> {
        if !self.is_active() {
            return Err(CardError::Inactive);
        }
        self.spec.resolved()
    }
    /// Replace a signed base; retain drafts only for identical input identity/base.
    /// # Errors
    /// Refuses rollback, identity changes, invalid candidates or engine failures.
    /// Authority loss retires the session and cancels all requests immediately.
    pub fn update(&mut self, mut spec: CardSpec) -> Result<MutationBatch, CardError> {
        if !spec.render_allowed || spec.snapshot.closed {
            self.retired = true;
            return self.suspend();
        }
        if spec.conversation_id != self.spec.conversation_id
            || spec.author_principal_id != self.spec.author_principal_id
            || spec.surface_ref != self.spec.surface_ref
        {
            return Err(CardError::Invalid("session identity"));
        }
        if spec.signed_version < self.spec.signed_version
            || (spec.signed_version == self.spec.signed_version
                && spec.signed_hash != self.spec.signed_hash)
        {
            return Err(CardError::Invalid("signed rollback"));
        }
        spec.host.clone_from(&self.spec.host);
        spec.validate()?;
        if spec.signed_version == self.spec.signed_version {
            if !self.is_active() {
                return Err(CardError::Inactive);
            }
            let tree = self.tree.as_ref().ok_or(CardError::Inactive)?;
            return tree.diff(Some(tree), self.version, self.version);
        }
        let drafts = retain_drafts(&self.spec, &spec)?;
        let conflict = drafts.len() != self.spec.drafts.len();
        spec.drafts = drafts;
        let mut local = self.local.clone();
        local.modals.clear();
        local.cancel_link();
        local.consumed.clear();
        let keys = projection::keys(&spec.resolved()?)?;
        let resolved = spec.resolved()?;
        local.tabs.retain(|key, index| {
            keys.iter()
                .position(|candidate| candidate == key)
                .and_then(|at| resolved.nodes.get(at))
                .and_then(|node| node.properties.get("tabs"))
                .and_then(Value::as_array)
                .is_some_and(|tabs| *index < tabs.len())
        });
        let batch = self.commit(spec, local, self.edit_seq)?;
        // Host conflict notice is a typed result through the session's read API.
        self.draft_conflict = conflict;
        Ok(batch)
    }
    /// Whether the last signed update discarded conflicting drafts.
    #[must_use]
    pub const fn draft_conflict(&self) -> bool {
        self.draft_conflict
    }
    /// Switch host presentation while retaining raw values and drafts.
    /// # Errors
    /// Refuses malformed presentation or failed execution.
    pub fn present(
        &mut self,
        presentation: crate::Presentation,
    ) -> Result<MutationBatch, CardError> {
        let spec = self.spec.clone().with_presentation(presentation)?;
        self.commit(spec, self.local.clone(), self.edit_seq)
    }
    fn commit(
        &mut self,
        mut spec: CardSpec,
        local: LocalState,
        edit_seq: u64,
    ) -> Result<MutationBatch, CardError> {
        if self.retired {
            return Err(CardError::Inactive);
        }
        let next = self.next_version()?;
        spec.validate()?;
        spec.render_tree = Some(projection::project(&spec, self.id, next, edit_seq, &local)?);
        let tree = self.vm.as_mut().ok_or(CardError::Inactive)?.render(&spec)?;
        let batch = tree.diff(self.tree.as_ref(), self.version, next)?;
        spec.render_tree = None;
        self.spec = spec;
        self.local = local;
        self.edit_seq = edit_seq;
        self.version = next;
        self.tree = Some(tree);
        Ok(batch)
    }
    /// Queue one bounded host event; semantic admission is repeated at delivery.
    /// # Errors
    /// Refuses oversized JSON or a full event queue.
    pub fn enqueue(&mut self, event: HostEvent) -> Result<(), CardError> {
        if self.queue.len() >= MAX_QUEUED_EVENTS || serde_json::to_vec(&event)?.len() > 16 * 1024 {
            return Err(CardError::Limit("event queue or bytes"));
        }
        self.queue.push_back(event);
        Ok(())
    }
    /// Deliver one event against current session, signed base, edit and tree versions.
    /// # Errors
    /// Refuses wrong control kinds, hidden/disabled targets or invalid drafts.
    pub fn next_event(&mut self) -> Result<Option<EventResult>, CardError> {
        let Some(event) = self.queue.pop_front() else {
            return Ok(None);
        };
        if !self.current(&event.token) {
            return Ok(Some(EventResult::StaleDropped));
        }
        let node = self
            .tree
            .as_ref()
            .and_then(|tree| tree.nodes.iter().find(|node| node.key == event.token.key))
            .cloned()
            .ok_or(CardError::Invalid("event key"))?;
        if node.attrs.get("disabled").and_then(Value::as_bool) == Some(true) {
            return Err(CardError::Invalid("disabled control"));
        }
        let result = self.deliver(&node, event.event)?;
        Ok(Some(result))
    }
    fn deliver(
        &mut self,
        node: &crate::Node,
        event: HostEventKind,
    ) -> Result<EventResult, CardError> {
        let mut local = self.local.clone();
        match event {
            HostEventKind::Input { value } => {
                let pointer = node
                    .attrs
                    .get("input_pointer")
                    .and_then(Value::as_str)
                    .ok_or(CardError::Invalid("input target"))?;
                let mut spec = self.spec.clone();
                spec.drafts.insert(pointer.into(), value);
                let seq = match advance(self.edit_seq, "edit sequence") {
                    Ok(seq) => seq,
                    Err(error) => {
                        self.vm = None;
                        self.tree = None;
                        self.queue.clear();
                        self.retired = true;
                        return Err(error);
                    }
                };
                Ok(EventResult::Edited { batch: self.commit(spec, local, seq)? })
            }
            HostEventKind::Activate => self.activate(node),
            HostEventKind::SelectTab { index } if node.kind == crate::NodeKind::Tabs => {
                let count = node.attrs.get("tabs").and_then(Value::as_array).map_or(0, Vec::len);
                if index >= count {
                    return Err(CardError::Invalid("tab index"));
                }
                local.tabs.insert(node.key.clone(), index);
                local.modals.clear();
                local.cancel_link();
                Ok(EventResult::Edited {
                    batch: self.commit(self.spec.clone(), local, self.edit_seq)?,
                })
            }
            HostEventKind::ModalOpen
                if node.kind == crate::NodeKind::Modal && local.link.is_none() =>
            {
                local.modals.clear();
                local.modals.insert(node.key.clone());
                Ok(EventResult::Edited {
                    batch: self.commit(self.spec.clone(), local, self.edit_seq)?,
                })
            }
            HostEventKind::ModalClose if node.kind == crate::NodeKind::Modal => {
                local.modals.remove(&node.key);
                Ok(EventResult::Edited {
                    batch: self.commit(self.spec.clone(), local, self.edit_seq)?,
                })
            }
            _ => Err(CardError::Invalid("event control kind")),
        }
    }
    fn activate(&mut self, node: &crate::Node) -> Result<EventResult, CardError> {
        let resolved = self.spec.resolved()?;
        let action = resolved
            .action(&node.component_id, &node.source_instance)
            .cloned()
            .ok_or(CardError::Invalid("action target"))?;
        if matches!(action.kind, ResolvedActionKind::Event { checks_pass: false, .. }) {
            return Ok(EventResult::Validation {
                batch: self.commit(self.spec.clone(), self.local.clone(), self.edit_seq)?,
            });
        }
        let mut local = self.local.clone();
        local.consumed.insert(node.key.clone());
        if let ResolvedActionKind::OpenUrl { url } = &action.kind {
            local.modals.clear();
            local.link = Some((node.key.clone(), ramflux_protocol::a2ui::validate_url(url)?));
        }
        let batch = self.commit(self.spec.clone(), local, self.edit_seq)?;
        if matches!(action.kind, ResolvedActionKind::OpenUrl { .. }) {
            Ok(EventResult::Edited { batch })
        } else {
            Ok(EventResult::Submit { action: Box::new(action), batch })
        }
    }
    /// Finish one SDK-handled link request and re-enable its Button locally.
    /// This performs no browser handoff, approval decision or authority operation.
    /// The SDK consumes/rechecks authority before reporting this completion.
    /// # Errors
    /// Refuses non-link slots, mismatched request identities and deny outcomes.
    pub fn complete_link(
        &mut self,
        reply: &crate::HostSlotReply,
    ) -> Result<EventResult, CardError> {
        if !self.current(&reply.token) {
            return Ok(EventResult::StaleDropped);
        }
        if matches!(reply.outcome, crate::SlotOutcome::Deny) {
            return Err(CardError::Invalid("link completion outcome"));
        }
        let slot = self
            .tree
            .as_ref()
            .and_then(|tree| {
                tree.host_slots
                    .iter()
                    .find(|slot| slot.id == reply.slot_id && slot.token == reply.token)
            })
            .ok_or(CardError::Invalid("link completion slot"))?;
        let crate::SlotRequest::LinkOpen { request_id, .. } = &slot.request else {
            return Err(CardError::Invalid("not a link slot"));
        };
        if request_id != &reply.request_id
            || self.local.link.as_ref().is_none_or(|(key, _)| key != &reply.token.key)
        {
            return Err(CardError::Invalid("link completion request"));
        }
        let mut local = self.local.clone();
        local.cancel_link();
        local.consumed.remove(&reply.token.key);
        Ok(EventResult::Edited { batch: self.commit(self.spec.clone(), local, self.edit_seq)? })
    }

    fn current(&self, token: &EventToken) -> bool {
        self.is_active()
            && token.session == self.id
            && token.signed_version == self.spec.signed_version
            && token.edit_seq == self.edit_seq
            && token.tree_version == self.version
    }
    /// Remove every mounted node/slot and invalidate queued events, releasing the VM.
    /// # Errors
    /// Refuses exhausted version space; authority retirement is permanent.
    pub fn suspend(&mut self) -> Result<MutationBatch, CardError> {
        let next = self.next_version()?;
        let mut empty =
            projection::project(&self.spec, self.id, next, self.edit_seq, &LocalState::default())?;
        empty.nodes.clear();
        empty.host_slots.clear();
        let batch = empty.diff(self.tree.as_ref(), self.version, next)?;
        self.vm = None;
        self.tree = None;
        self.queue.clear();
        self.local.modals.clear();
        self.local.cancel_link();
        self.version = next;
        Ok(batch)
    }
    /// Resume with a fresh session identity and a reset batch.
    /// # Errors
    /// Refuses retired/active sessions, limits and execution failures.
    pub fn resume(&mut self) -> Result<MutationBatch, CardError> {
        if self.retired || self.vm.is_some() {
            return Err(CardError::Inactive);
        }
        let id = fresh_id()?;
        let mut spec = self.spec.clone();
        spec.render_tree = Some(projection::project(&spec, id, 1, self.edit_seq, &self.local)?);
        let mut vm = CardRuntime::with_budget(
            &self.package,
            spec.clone(),
            std::rc::Rc::clone(&self.budget),
        )?;
        let tree = vm.render(&spec)?;
        let batch = tree.diff(None, 0, 1)?;
        self.id = id;
        self.vm = Some(vm);
        self.tree = Some(tree);
        self.version = 1;
        Ok(batch)
    }
    fn next_version(&mut self) -> Result<u64, CardError> {
        match advance(self.version, "tree version") {
            Ok(next) => Ok(next),
            Err(error) => {
                self.vm = None;
                self.tree = None;
                self.queue.clear();
                self.retired = true;
                Err(error)
            }
        }
    }
}
fn fresh_id() -> Result<u64, CardError> {
    NEXT_SESSION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
            id.checked_add(1).filter(|next| *next <= MAX_SAFE_INTEGER)
        })
        .map_err(|_| CardError::Limit("session identifiers"))
}
fn advance(value: u64, name: &'static str) -> Result<u64, CardError> {
    value.checked_add(1).filter(|next| *next <= MAX_SAFE_INTEGER).ok_or(CardError::Limit(name))
}
fn retain_drafts(old: &CardSpec, new: &CardSpec) -> Result<SurfaceDrafts, CardError> {
    let before = old
        .snapshot
        .resolve_for_locale(&SurfaceDrafts::new(), ramflux_protocol::a2ui::DisplayLocale::En)?;
    let after = new
        .snapshot
        .resolve_for_locale(&SurfaceDrafts::new(), ramflux_protocol::a2ui::DisplayLocale::En)?;
    let mut retained = SurfaceDrafts::new();
    for (pointer, value) in &old.drafts {
        let input = before
            .inputs
            .iter()
            .find(|input| &input.pointer == pointer)
            .ok_or(CardError::Invalid("draft owner"))?;
        let same = after.inputs.iter().any(|other| {
            other.component_id == input.component_id
                && other.source_instance == input.source_instance
                && other.pointer == input.pointer
                && other.value == input.value
                && other.component == input.component
                && other.scope == input.scope
        });
        if same {
            let mut candidate = retained.clone();
            candidate.insert(pointer.clone(), value.clone());
            if new
                .snapshot
                .resolve_for_locale(&candidate, ramflux_protocol::a2ui::DisplayLocale::En)
                .is_ok_and(|resolved| {
                    resolved
                        .inputs
                        .iter()
                        .filter(|input| candidate.contains_key(&input.pointer))
                        .all(|input| {
                            resolved
                                .nodes
                                .get(input.node)
                                .is_some_and(|node| node.errors.is_empty())
                        })
                })
            {
                retained = candidate;
            }
        }
    }
    Ok(retained)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runtime::tests::{fixture, guard, library};
    pub(crate) fn event(session: &CardSession, id: &str, event: HostEventKind) -> HostEvent {
        let tree = session.tree().expect("test: mounted tree");
        let node = tree.nodes.iter().find(|n| n.component_id == id).expect("test: target");
        HostEvent {
            token: EventToken {
                session: session.id(),
                signed_version: tree.signed_version,
                edit_seq: tree.edit_seq,
                tree_version: tree.tree_version,
                key: node.key.clone(),
            },
            event,
        }
    }
    pub(crate) fn send(
        session: &mut CardSession,
        id: &str,
        kind: HostEventKind,
    ) -> Result<EventResult, CardError> {
        session.enqueue(event(session, id, kind))?;
        session.next_event()?.ok_or(CardError::Invalid("test event"))
    }
    #[test]
    fn form_fixture_tree_mutations_and_stale_events() {
        let _guard = guard();
        let (mut session, mount) = CardSession::open(fixture(), library()).expect("test: open");
        assert_eq!(mount.mutations.len(), 5, "all reachable instances mount");
        let stale = event(&session, "button", HostEventKind::Activate);
        send(&mut session, "input", HostEventKind::Input { value: serde_json::json!("Grace") })
            .expect("test: edit");
        assert_eq!(
            session.spec.snapshot.data_model["name"], "Ada",
            "draft never mutates signed base"
        );
        session.enqueue(stale).expect("test: queue stale");
        assert!(
            matches!(session.next_event().expect("test: deliver"), Some(EventResult::StaleDropped)),
            "editing fences prior tokens"
        );
        let result = send(&mut session, "button", HostEventKind::Activate).expect("test: activate");
        assert!(matches!(result, EventResult::Submit { .. }), "activation emits a resolver action");
        session.update(fixture()).expect("test: identical signed read is idempotent");
        assert!(
            send(&mut session, "button", HostEventKind::Activate).is_err(),
            "consumed buttons remain disabled until signed update"
        );
        session.suspend().expect("test: offscreen suspension");
        session.resume().expect("test: fresh identity on resume");
        assert!(
            send(&mut session, "button", HostEventKind::Activate).is_err(),
            "offscreen lifecycle cannot replay a consumed submit"
        );
        let mut link = fixture();
        link.signed_version = 2;
        let button = link
            .snapshot
            .components
            .iter_mut()
            .find(|node| node["id"] == "button")
            .expect("test: button");
        button["action"] = serde_json::json!({"functionCall":{"@call":"openUrl","args":{"url":"https://example.com/path"}}});
        link.signed_hash = link.snapshot.hash().expect("test: new signed link");
        session.update(link).expect("test: signed update re-arms the action");
        assert!(
            matches!(
                send(&mut session, "button", HostEventKind::Activate)
                    .expect("test: link activation"),
                EventResult::Edited { .. }
            ),
            "link never submits an author event"
        );
        let slot = session
            .tree()
            .expect("test: link tree")
            .host_slots
            .first()
            .expect("test: host link request")
            .clone();
        let crate::SlotRequest::LinkOpen { request_id, .. } = slot.request else {
            panic!("test: expected a link request")
        };
        let reply = crate::HostSlotReply {
            token: slot.token,
            slot_id: slot.id,
            request_id,
            outcome: crate::SlotOutcome::Cancel,
        };
        session
            .complete_link(&reply)
            .expect("test: SDK-reported cancellation clears local link pending");
        assert!(
            matches!(
                session.complete_link(&reply).expect("test: replayed completion"),
                EventResult::StaleDropped
            ),
            "completion is consumed by advancing the token version"
        );
        send(&mut session, "button", HostEventKind::Activate)
            .expect("test: a cancelled link can be requested again");
        session.suspend().expect("test: suspension cancels link presentation");
        session.resume().expect("test: resume after cancelled link");
        send(&mut session, "button", HostEventKind::Activate)
            .expect("test: cancelled link latch is released across suspension");
    }
    #[test]
    fn lifecycle_capacity_and_queue_are_bounded() {
        let _guard = guard();
        let (mut a, _) = CardSession::open(fixture(), library()).expect("test: first VM");
        let (b, _) = CardSession::open(fixture(), library()).expect("test: second VM");
        assert!(CardSession::open(fixture(), library()).is_err(), "at most two resident VMs");
        drop(b);
        for _ in 0..32 {
            a.enqueue(event(&a, "input", HostEventKind::Input { value: serde_json::json!("Ada") }))
                .expect("test: queue capacity");
        }
        assert!(
            a.enqueue(event(&a, "button", HostEventKind::Activate)).is_err(),
            "queue is bounded"
        );
        let id = a.id();
        let batch = a.suspend().expect("test: suspend");
        assert!(batch.host_slots.is_empty(), "suspension cancels host work");
        a.resume().expect("test: resume");
        assert_ne!(a.id(), id, "resume has fresh token identity");
    }
    #[test]
    fn real_two_form_diff_covers_reorder_middle_insert_remove_and_value() {
        let _guard = guard();
        let (mut s, _) = CardSession::open(fixture(), library()).expect("test: open");
        let mut spec = s.spec.clone();
        let form =
            spec.snapshot.components.iter_mut().find(|n| n["id"] == "form").expect("test: form");
        form["children"] = serde_json::json!(["button", "input"]);
        spec.signed_version += 1;
        spec.signed_hash = spec.snapshot.hash().expect("test: hash");
        let batch = s.update(spec).expect("test: reorder");
        assert!(batch.mutations.iter().any(|m| matches!(m,crate::Mutation::Upsert{index:0,node,..} if node.component_id=="button")),"reordered keyed controls are reinserted at their current positions");
    }
    #[test]
    fn replay_foreign_wrong_kind_and_oversized_events_do_not_corrupt_session() {
        let _guard = guard();
        let (mut s, _) = CardSession::open(fixture(), library()).expect("test: open");
        let mut foreign = event(&s, "input", HostEventKind::Activate);
        foreign.token.session += 1;
        s.enqueue(foreign).expect("test: foreign queue");
        assert!(
            matches!(s.next_event().expect("test: foreign"), Some(EventResult::StaleDropped)),
            "foreign sessions drop"
        );
        assert!(send(&mut s, "input", HostEventKind::Activate).is_err(), "input is not an action");
        assert!(
            send(&mut s, "input", HostEventKind::Input { value: serde_json::json!(123) }).is_err(),
            "input type must match resolver ownership"
        );
        assert!(
            s.enqueue(event(
                &s,
                "input",
                HostEventKind::Input { value: serde_json::json!("x".repeat(17000)) }
            ))
            .is_err(),
            "bound event before queuing"
        );
        assert_eq!(s.version(), 1, "refusals preserve the last good tree and tokens");
    }
    #[test]
    fn failed_evaluation_invalidates_tokens_and_resume_diffs_the_displayed_tree() {
        let _guard = guard();
        let (mut s, _) = CardSession::open(fixture(), library()).expect("test: open");
        let token = event(&s, "input", HostEventKind::Input { value: serde_json::json!("new") });
        s.suspend().expect("test: suspend");
        s.resume().expect("test: resume");
        s.enqueue(token).expect("test: old token");
        assert!(
            matches!(s.next_event().expect("test: old delivery"), Some(EventResult::StaleDropped)),
            "resume invalidates old identity even at same tree version"
        );
        let mut revoked = fixture();
        revoked.render_allowed = false;
        s.update(revoked).expect("test: authority loss cancels tree");
        assert!(s.tree().is_none() && !s.is_active(), "authority loss removes tree");
        assert!(s.resume().is_err(), "retired sessions cannot resurrect");
    }
    #[test]
    fn admission_budget_rejection_preserves_live_vm() {
        let _guard = guard();
        let (mut s, _) = CardSession::open(fixture(), library()).expect("test: open");
        s.budget.borrow_mut().deny_for_test();
        assert!(
            matches!(
                s.update({
                    let mut next = fixture();
                    next.signed_version = 2;
                    next
                }),
                Err(CardError::Budget)
            ),
            "pre-execution admission budget rejects without disabling the VM"
        );
        assert!(s.is_active(), "admission refusal preserves VM");
        s.budget.borrow_mut().reset_for_test();
        let mut invalid = fixture();
        invalid.signed_hash = "tampered".into();
        assert!(s.update(invalid).is_err(), "reject before VM evaluation");
        assert!(s.is_active(), "invalid admission preserves live VM");
        send(&mut s, "input", HostEventKind::Input { value: serde_json::json!("Grace") })
            .expect("test: valid edit after refusal");
    }
}
