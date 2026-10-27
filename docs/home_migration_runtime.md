<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Cooperative home migration runtime

Migration control uses native custody possession grants. A grant is bound to one
signed control hash, requester, custody record, source address and purpose. It is
consumed before any peer exchange. It is not an ordinary account session.

The runtime is opt-in with `RAMFLUX_HOME_MIGRATION_ENABLED=1`. It requires the
configured node service signer, `RAMFLUX_CUSTODY_NODE_RECORD_FILE`, the independently
pinned custody node public key, the mesh CA, `RAMFLUX_CLIENT_GATEWAY_TCP_ADDR`,
`RAMFLUX_FEDERATION_PUBLIC_ENDPOINT`,
`RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN`, and
`RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_TOKEN`. The admin origin is an internal
HTTP origin without a path. Its token belongs to the node services, not clients.
The destination offer binds a freshly verified signed client discovery record,
including its gateway address, CA and migration capability.

## Routes and readers

| Surface | Route/frame | Reader and trust boundary |
| --- | --- | --- |
| Custody client TLS, directly or through the gateway's existing custody proxy | `home_migration` challenge and session action | `CustodyService`: branch possession and action scope; the migration service checks the owner control and current authority |
| Federation internal admin HTTP | `POST /internal/home-migration/peer` | Federation admin handler: operator token, remaining request budget and current independent peer admission |
| Federation peer TCP TLS | `POST /v3/home-migration/peer` | Federation mesh handler: federation service certificate, admitted peer route and CA; relays to its own router |
| Router TCP/QUIC mesh | `POST /v3/home-migration/peer` | Router handler: federation service role; custody bridge independently reloads the admitted signing pin and verifies the signed peer wrapper and owner evidence |
| Federation public client HTTP | Both private migration paths | No handler; returns 404 |

Server-hop messages carry only a decreasing remainder of one ten-second caller
budget. Peer wrappers bind the source, audience, action, root, migration id,
evidence hash, nonce and short validity interval. Plain HTTP is used only for the
explicit internal admin hop. Remote peers use their independently admitted CA
with the federation TLS server name; the local router hop uses its mesh CA and
router TLS server name. Client discovery is not a replacement for peer admission.

## Durable admission floors

`home_root_gates_v1` stores root-wide dormant/former-home refusals. Its in-memory
projection is loaded at startup. Ordinary native registration and session
operations read this projection under a root lease. A target submission retains
its root lease through the durable WAL acknowledgement, even if its caller is
cancelled. A root cutover fences devices outside the sealed delivery map too.
ACK/close and migration-scoped read operations remain available.

Preparing a destination saves the verified source home and its verified ancestry.
An expired or cancelled reservation does not erase this home floor or enable a
second local genesis. A foreign prepare cannot demote a root already serving a
local registration. Source commit and destination activation update the durable
root gate with their head transaction, then update the cache while retaining the
exclusive root lease. Only a verified source proof releases the destination's
ordinary-client gate. A former home signs its migration refusal with the retained
node signer; the proof hash and new-home hint are covered by that signature.
Ordinary-client refusals bind their challenge/request nonce rather than a remote
recipient's envelope id.

`migration_local_signer_v1` retains the local node identity once a genesis or
reservation is committed. Startup checks this row before serving. Signer removal,
node-id changes, signer rotation or disabling migration while this row exists
refuse startup. Node-key rotation and retirement of the retained proof history
require a later protocol. An unused node is not pinned merely by starting it.

## Courier lifecycle

The router supervises one courier worker, started only with the migration runtime.
An idle tick reads due indexes without opening a writer. Claims use individual
short transactions and small metadata; operation bundles are loaded individually
by at most sixteen workers, with no more than four exchanges per peer and one
shared ten-second tick deadline. A local durable-state failure stops that tick.
Peer failure keeps the durable retry row. Unprocessed claims become eligible
after their claim lease expires. Shutdown cancels the next tick and joins the
current bounded tick. No authority, control or database lock crosses peer I/O.

The courier sends Commit only within the sealed deadline. After expiry it waits
out the permitted source-clock skew, then requests a signed terminal outcome.
Neither time, a transport error nor a quota refusal activates an inbox or changes
an unknown outcome back into an executable commit. Public resolve can return an
already stored committed proof without contacting an offline successor. Private
progress reads require current home authority; a pending destination reports its
own reservation state without inventing source backlog counters.
