# SECURITY-BACKREVIEW-FIX-02 (Opus takeover after review round 2)

Branch `fix/security-backreview-02` from `origin/fix/security-backreview-01` 89b8479e2. QA label `cl-secrev2`.
Inputs: `SECURITY-BACKREVIEW-2026-11-26.md`, `SECURITY-BACKREVIEW-FIX-01.md`, `SECURITY-BACKREVIEW-FIX-01-review-r2.md`.
Code commit: `f37c76e1f`. No new test code. The real run is done by a Haiku from the rows below.

## Finding -> change -> commit

| Finding | Change | Commit |
|---|---|---|
| r2 M1 (#605 M1) | The nine router mesh routes with no production caller are compiled only with `itest-http`: POST `/mvp6/friend/request`, `/mvp7/lifecycle/{event,cancel,finalize}`, `/mvp7/abuse/report`, `/mvp7/federation/tombstone/apply`, and GET `/mvp7/lifecycle/*`, `/mvp7/metadata/*`, `/mvp7/abuse/report/*` (`handle_mesh_itest_value` in `apps/ramflux-router/src/handlers.rs`; the handlers in `lifecycle.rs` and `handle_mvp6_friend_request` are gated too). A production router answers 404 for them. In itest builds the caller policy (`ITEST_ROUTE_CALLER_POLICY`) still admits only `ramflux-gateway` (and `ramflux-federation` for the tombstone). It now has prefix rules, so the GET routes are covered too (closes r2 L2). | f37c76e1f |
| r2 M2 (#609 M2) | `authorize_reply` scans the owner's rows, deserializes each one and counts only `expires_at > now` (the row being written is excluded). It deletes expired rows in the same write transaction after the range borrow ends, and commits the sweep even when the cap refuses. The cap check uses the live count. | f37c76e1f |
| r2 L1 (#609 L3) | A fence row is imported from an archive only when its anchor equals `main.runtime_account_identity.principal_commitment` (the restoring account's own anchor), and only together with its floor row. | f37c76e1f |
| REACH-STALE-HEAD-01 (#609 M1) | See the design below (SDK `resubmit`, settle by operation id, node `commit_reach` checks the operation first and checks the owner). | f37c76e1f |
| docs | `docs/account_reach.md`: resubmit rule and the reply-permission lifetime and cap. | f37c76e1f |

### Production account deletion path (r2 M1 trace)

Verified by grep over `apps` and `crates`. Production account deletion is `rf username delete` (`apps/rf/src/handlers/username.rs:45`). It becomes `UsernameChange::Delete`, then a signed username-directory operation with `w::Action::Delete` (`crates/ramflux-sdk/src/username_directory/draft.rs:112-116`). That operation is submitted through `bus/username_directory/submission.rs` to the home directory on the federation service (`crates/ramflux-node-core/src/username_directory/home.rs:270,367`, `home/recovery.rs:54`), which marks the account `deleted` and refuses later operations with `account_deleted`. That path never calls the router `/mvp7/lifecycle/*` routes. The only senders of those routes are `apps/ramflux-gateway/src/itest_http.rs:299-520` and `apps/ramflux-federation/src/itest_http.rs:635`. So gating them removes no production path.

### REACH-STALE-HEAD-01 design

The problem: `prepare_set` runs on the writer and is synchronous. It returned the journaled policy unchanged. Once the authority head or home head moved, every resend failed with `reach_signature` or `reach_home`. `settle` never ran, so the journal was resent forever and every new change returned `OperationPending`.

The pipeline stays prepare (writer) -> exchange (async, owned input only) -> apply (writer):
1. `prepare_set` now returns `ReachSend::Fresh(action)` for a newly signed and journaled policy (unchanged behaviour), or `ReachSend::Stored(policy)` when a matching intent is already journaled. `Purpose::Reach` carries the stored intent (`stored: Option<Box<ReachPolicy>>`). Both the user call and the background `delivery_status` retry reach this path.
2. For a stored intent, `Prepared::exchange` calls `crate::account_reach::resubmit` (async, no database access):
   - `ReachGet` first;
   - if the home policy has the intent's `operation_id`, the operation already committed, and the read is returned as the result;
   - else, if the intent's `home_head_hash` equals the verified current home head and its `authority_head_hash` equals `object_hash(own_record)` (the local current authority), resend the exact journaled bytes;
   - else re-sign the same `mode`/`expected_revision`/`operation_id` on the current heads with the existing `submit`, and send that. The journal keeps the original intent. A later retry repeats the decision, and Ed25519 over the same body gives the same bytes, so the home's operation dedupe still holds.
3. `settle` (apply) also drops the intent when the committed policy has the intent's `operation_id` (it may be the re-signed bytes). A stale `expected_revision` comes back as a home conflict, which already drops the intent. So every path ends: committed, conflict, or still pending only while the home is unreachable or the node's custody lags the local one.
4. Node `commit_reach(root, policy, ...)`: it first requires `policy.account_anchor == root` (the session root, passed by `apps/ramflux-federation/src/username_directory/home_reach.rs`). It then looks up `reach-operation:{root}:{operation_id}` before the signature and head checks. If the stored digest equals the digest of the incoming policy, it returns the stored state; a different digest is refused with `reach_operation_reuse`. Only then does it verify the signature and the home chain and run the CAS. The owner check keeps the earlier lookup from answering for another account's operation.
There is no fallback or legacy path, and no `unwrap`, `expect` or indexing was added.

### Real-run knob (for M2)

The node-core feature `itest-reply-permission-limits` (federation passthrough `ramflux-federation/itest-reply-permission-limits`) sets the cap to 1 live permission and the lifetime to 20 s. `lib.rs` refuses it with `compile_error!` in release and production builds, the same as `itest-http`. The defaults are unchanged (4096, 86 400 s).

## Skipped Lows: owner lines

- #620 L1 `sign_enrollment_layer` under `cfg(test)`: follow-up, owner controller (MASTER-PLAN backlog, card SECONDARY-LAYER-TESTFN-01). Fix shape: a `test-support` feature on `ramflux-crypto` that the SDK dev-dependency enables, with a release `compile_error!`. Not done here because nine SDK test files call it, which makes it a cross-crate test-harness change with no production behaviour.
- #608 L4 `base32_lower` `unwrap_or(0)`: won't fix in this unit. The index comes from a 5-bit mask and is always < 32, so the fallback is unreachable, and the back-review gave no Fix wording. Revisit only if the alphabet code changes.
- Same-class sweep, `serde_json` to `parse_i_json` on mesh handlers: follow-up, owner controller (card MESH-IJSON-SWEEP-01). It is a different defect class and is not in this unit.

## Guards (on f37c76e1f)

- `cargo fmt --all -- --check` (QA): pass.
- `cargo clippy -p ramflux-router -p ramflux-node-core -p ramflux-storage -p ramflux-sdk -p ramflux-federation --all-targets -- -D warnings` (QA): rc 0.
- Same clippy with `ramflux-router/itest-http` and `ramflux-federation/itest-reply-permission-limits` (QA): rc 0 (the gated code compiles warning-free both ways).
- `scripts/ci/test-timing.py --check`: PASS. `scripts/check-account-transactions.py`: 0 violations.
- `scripts/generate-c-abi-methods.py --check`: METHOD_POLICY_OK (run on the Mac; on QA it stops with "contact.verify product pin is not an immutable commit" because qa-cargo removes `.git`, the same on the base).
- I-JSON guard `cargo nextest run -p ramflux-protocol --test ijson_decode_site_guard` (QA): 8 passed. The new storage-row decoder `reply_permission_rows` is registered class E in `crates/ramflux-node-core/ijson_decode_sites.registry`.

## Real-run rows (for the Haiku; do not weaken any expectation)

Builds on QA, own target, in this order. Feature unification would overwrite the router binary, so copy each binary aside right after its build:
- B1 production router: `cargo build -p ramflux-router`, then copy `target/debug/ramflux-router` to `bin-prod/ramflux-router`.
- B2 itest set: `RAMFLUX_ITEST_BUILD=1 cargo build -p ramflux-rf --features ramflux-rf/itest-memory-vault -p ramflux-federation --features ramflux-federation/itest-http,ramflux-federation/itest-reply-permission-limits -p ramflux-router --features ramflux-router/itest-http -p ramflux-retention -p ramflux-gateway --features ramflux-gateway/itest-http`, then copy the binaries to `bin-itest/`. FIX-01 left out `ramflux-router/itest-http`; without it rows R2 and R3 cannot pass.
Stack: `~/secrev-local-stack.sh up --bin-dir <bin> --run-dir <run>` (mesh certs `RUN/certs/<service>.pem|.key`, CA `RUN/certs/ca.pem`; the router mesh address is the `router = "..."` endpoint in the generated config). Mesh probe: `curl --http1.1 -sk --cert RUN/certs/<svc>.pem --key RUN/certs/<svc>.key -X <M> https://<router-mesh>/<path> -d '{}' -w ' %{http_code}'`. Record the status line and body for each probe.

| Row | Finding | Binaries | Steps | Pass condition |
|---|---|---|---|---|
| R1 | #605 removal | B1 router + B2 rest | From the `ramflux-gateway` identity, probe all nine routes (6 POST with `{}`, GET `/mvp7/lifecycle/x`, `/mvp7/metadata/x`, `/mvp7/abuse/report/x`). Control: GET `/mvp2/device-set/x` from the gateway. | Nine times `404 not found`; the control is not 404. |
| R2 | #605 caller policy (403 probe) | B2 | Repeat the nine probes from the `ramflux-retention` identity (an admitted mesh peer that is not on the list). | Nine times `403 Forbidden`, body `route requires an admitted caller` (GET prefix routes included). |
| R3 | #605 completed itest lifecycle | B2 | Create an account with rf while its daemon is connected to the stack gateway, so the device is registered. Gate: GET `/mvp1/device-manifest/<commitment>` through the gateway itest listener shows the device. Then run `SECURITY-BACKREVIEW-FIX-01-row1-driver.py <gw-itest> <principal> <device>` (start, get, cancel, get, start again, finalize, get). | Every step HTTP 200. Lifecycle state (as serialized for `AccountLifecycleState`) after each step: `delete_pending`, then `active`, then `delete_pending` again, then `deleted`. No 403 or 500. |
| R4 | production deletion path still works | B2 with username directory (the OPEN-ACCOUNT-BETA-01 run13 stack, `im-bus/log/OPEN-ACCOUNT-BETA-01/tools-run13/`) | Claim a name, run `rf username delete`, then `rf username status`, then try a new claim. | Delete commits. Status shows the delete operation. The new claim is refused with `account_deleted`. |
| R5 | #609 M2 cap and expiry | B2 (knob on) + username directory, owner `alice` open, peers `bob` and `carol` | bob and carol each send a request to alice. alice `contact.requests.reply` to bob (ok). Within 20 s, reply to carol. Wait 21 s, reply to carol again. | First reply ok. Second refused `reply_permission_cap`. Third ok (bob's expired row was swept). |
| R6 | REACH-STALE-HEAD-01 | B2 + username directory, alice primary | Stop federation. `account.reach.set {mode: open, expected_revision: 1, operation_id: X}` journals (pending). Pair a second device to alice (the authority head changes, as in FIX-01 row 3). Start federation. Wait for background delivery, up to 2 min. Then `account.reach.get`. Then send `account.reach.set` with a different operation id and `expected_revision` = the current revision. | The get shows `open` at revision 2 with `operation_id` X and `authority_head_hash` = the new head. The `reach/change/<root>` journal row is gone. The follow-up set is not `operation_pending`. The federation log shows no repeating `reach_signature` refusals. |
| R7 | completed-then-retried | same stack | Repeat the exact `account.reach.set` from R6 (same operation id X, mode and expected revision). | Returns the stored state (revision 2, no new revision). It does not return `operation_pending` or `reach_operation_reuse`. |
| R8 | r2 L1 fence import | rf | Optional row: restore an archive of alice that carries a `reach/fence/<other-root>` row. | After the import, no fence row for the other root (read with `rf`'s diag or sqlite on the scratch copy). |

## Feedback to controller

- FIX-01's feedback still applies: R3 depends on a device registration that rf does only while its daemon holds a gateway session. The OPEN-ACCOUNT-BETA-01 stack already does this; reuse it.
- R6 needs a paired second device (same need as FIX-01 row 3). Plan one stack for R3-R7.

STATUS: READY f37c76e1f
