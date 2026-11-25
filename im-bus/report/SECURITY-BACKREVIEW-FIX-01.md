# SECURITY-BACKREVIEW-FIX-01 (round 1)

Branch `fix/security-backreview-01` from `origin/next` 30d0f9a7c. Code head: `e7675c8ff`.
Source: `im-bus/report/SECURITY-BACKREVIEW-2026-11-26.md`. QA lane `cl-secrev`.

## Status

STATUS: BLOCKED real run (row 1 not completed; row 3 not run). Guards are green (see below). Not READY.

## Finding -> commit -> real-run row

| Finding | Result | Commit | Real-run row |
|---|---|---|---|
| #605 M1 caller policy for sibling routes | fixed (6 entries) | e7675c8ff | row 1 (partial, see below) |
| #605 L1 custody conflict account anchor at DEBUG | fixed | e7675c8ff | n/a (log level) |
| #605 L2 log_path split_last + doc line | fixed | e7675c8ff | n/a |
| #605 L3 federation/relay raw path via log_path, 128-byte cap | fixed | e7675c8ff | n/a |
| #608 L1 retry_after_ms lower clamp 1000 ms | fixed | e7675c8ff | n/a (not in rows) |
| #608 L2 refusal jitter capped under MAX | fixed | e7675c8ff | n/a |
| #608 L3 centre reason bounded to 64 chars, debug-escaped | fixed | e7675c8ff | n/a |
| #608 L4 seed copy in centre enrol | fixed (signing via SigningKey) | e7675c8ff | n/a |
| #608 L4 base32 unwrap_or(0) | NOT done: no Fix wording in the report | - | - |
| #609 M1 stale reach heads | NOT done: Opus unit (see below) | - | row 2 (Opus) |
| #609 M2 reply permission cap, dm_scope binding, expires_at | fixed | e7675c8ff | not run |
| #609 L1 secondary reach init waits for primary | fixed | e7675c8ff | not run |
| #609 L2 authority-chain doc rule | doc recorded as "target, not enforced"; the verifier requirement is NOT implemented | e7675c8ff | n/a |
| #609 L3 doc sentence fixed; fence rows need a matching floor | fixed | e7675c8ff | n/a |
| #620 M1 renewal due / 3600 s spacing | fixed | e7675c8ff | row 3 (not run) |
| #620 L1 sign_enrollment_layer cfg(test) | NOT done: skipped by controller (cross-crate: SDK test files call it) | - | - |
| #620 L2 dropped enqueue result logged at DEBUG | fixed | e7675c8ff | n/a |
| Sweep: serde_json on mesh handlers -> parse_i_json | NOT done (different defect class, not in this unit) | - | - |

## Guards (on e7675c8ff)

- `cargo check` on QA for protocol, storage, node-core, sdk, router, federation, relay, ramflux-rf: pass.
- `cargo fmt --check` on QA: pass.
- `cargo clippy -p <8 crates> --all-targets -- -D warnings` on QA: pass (rc=0, after the Duration fix).
- `scripts/ci/test-timing.py --check`: PASS.
- `scripts/check-account-transactions.py`: 0 violations.
- `scripts/generate-c-abi-methods.py --check`: METHOD_POLICY_OK.
- I-JSON guard: not needed (no new JSON decoding).

## Real runs

Build: `RAMFLUX_ITEST_BUILD=1 cargo build -p ramflux-rf --features ramflux-rf/itest-memory-vault -p ramflux-federation -p ramflux-router -p ramflux-retention -p ramflux-gateway --features ramflux-gateway/itest-http` on QA, OK. Binaries: `/opt/ops/prx-lanes/cl-secrev/target/debug/`.

### Row 1: account deletion lifecycle (start, cancel, finalize)

- Driver: `im-bus/report/SECURITY-BACKREVIEW-FIX-01-row1-driver.py` (copy on QA: `~/secrev-row1-driver.py`).
- Stack: `~/secrev-local-stack.sh up` with `RAMFLUX_ITEST_HTTP=1`, gateway itest listener 127.0.0.1:18931, run dir `~/secrev-row1-run` (stopped afterwards).
- Output: `~/secrev-row1-output.jsonl` on QA (contains the last failing run).
- Identity: verified in code. The itest proxy calls `router_post_json`, which uses the gateway's production `RouterMeshClient` (same mesh cert, `ramflux-gateway`). Only the listener is itest-gated. So the same service identity as the production caller in `ROUTE_CALLER_POLICY`.
- Result: NOT PASSED. The request reaches the router through the gateway and is not refused by the caller policy (403 would have come first). The router then answers HTTP 500 `lifecycle actor device is not registered`: the device manifest on the router is empty (`device_count=0`), because the account created through rf was never published to the node. Account creation itself worked (pty driver `~/secrev-acct.py`, account `account-sf6hdhVqchs2pES-NFoidw0wP8cyU1YI5NVD_oARdBo`, principal `principal-yjYqNLazQvxdWhnLmtRUOHIkp7GchuddXHlv2IShob4`, device `device-R85zQ2oeAHw4iLokA4yLBt3qrOAPApBaR51Ei6YCDao`).
- rf CLI: no account-level deletion or lifecycle command exists in `apps/rf/src/cli` (only agent delete and conversation delete). So row 1 cannot also run through rf.
- Next step needed: publish the device to the node (device registration on the router), then rerun the driver. This is an open item.

### Row 2: reach-mode change, device list change, resubmit

Moved to the Opus unit (controller decision). Not run.

### Row 3: paired secondary layer renewal (first accepted, immediate second refused)

Not run. Knob: build feature `ramflux-rf/itest-short-layer-lease` (`apps/rf/Cargo.toml:20`, `ramflux-sdk/itest-short-layer-lease`). It shortens the renewal due time at build time. It needs a rebuild of rf on QA plus a paired secondary device, which depends on the row 1 device registration above.

## #609 M1: what the Opus unit needs to know

- `crates/ramflux-sdk/src/bus/username_directory/reach.rs` `prepare_set` is synchronous. It returns the stored signed policy unchanged when an intent exists (line ~25), so a stale intent is resubmitted forever.
- The fix wording needs an async `ReachGet` before the decision. `prepare_set` cannot issue it. The bus flow in `crates/ramflux-sdk/src/bus/username_directory.rs` (`prepare` -> `exchange` -> `apply`) would need a two-phase action.
- `crates/ramflux-node-core/src/username_directory/home/reach.rs` `commit_reach` checks the signature before the `reach-operation:{root}:{operation_id}` lookup. The fix needs the lookup first, and a digest comparison.
- `settle` in `reach.rs` only runs on success or conflict, so an error leaves the intent in place.

## Opus-or-controller notes

- #620 L1 is cross-crate: `sign_enrollment_layer` is used from nine SDK test files, so `#[cfg(test)]` in `ramflux-crypto` breaks them.
- #609 L2 requires a verifier chain walk that does not exist yet; only the doc part is in.
- #609 M2 picks a 1-day TTL (`REPLY_PERMISSION_TTL_SECONDS`) and a 4096 cap. Both are defaults the controller should confirm.
- #605 M1 policy values: `ramflux-gateway` (friend request, lifecycle, abuse report) and `ramflux-federation` (tombstone apply) are the gateway itest proxy and federation itest handler callers. Gateway and federation are the only admitted callers in the production policy.

feedback to controller: row 1 needs a device-registration step before lifecycle start works; the brief did not say how a real account is published to the node.
