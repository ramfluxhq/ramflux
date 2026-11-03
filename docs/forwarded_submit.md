<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Forwarded submission bounds

A migrated destination uses the local federation forward client. TCP mesh-TLS
and async ingress share the router's configured forward semaphore (default 32).
Both acquire without queueing and return `forward_in_progress` on saturation.
Local destinations do not acquire a permit or allocate a forward worker.

DNS has a three-second deadline. Socket connect, request writes, response header,
and response body share a single twelve-second deadline. Partial progress never
renews it. The configured total forward timeout also applies to both ingress
paths. A process-wide IO runtime drives these operations from blocking workers;
its DNS blocking pool is bounded, including system lookups that cannot be cancelled.
Expired futures close their socket and return `ForwardTimeout` with the phase.
RAII keeps a live blocking worker counted even if its async waiter is cancelled.

The old-home reservation lease defaults to 20 seconds, leaving margin beyond the
3 + 12 second network bound and whole-second lease timestamp rounding. New-home
Pending lasts 142 seconds (twice the worst-case 71-second router post), preventing
an old-home retry from creating a second delivery while the first is uncertain.

`home_node_migration_forward_count` is appended after sender signing and excluded
from sender canonical bytes. The federation signature authenticates the marker
in transit; sender fields and sender extensions remain signed. SDK builds before
FU-BATCH-03 reject forwarded messages. The desktop SDK pin update DESK-PIN-01 has
shipped; downstream clients must use that SDK version or later.
