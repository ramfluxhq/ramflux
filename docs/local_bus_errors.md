# Local bus error codes and retries

Error frames keep the original diagnostic in `error.message`. Clients should use
`error.code` for policy rather than matching that text. A retry must retain the
operation id where applicable and use bounded backoff; a transport outage does
not prove that a remote mutation was never committed.

| Code | Meaning | Automatic retry |
| --- | --- | --- |
| `Unavailable` | Transient QUIC or I/O failure, HTTP client timeout/connect/body failure, unopened transport, backpressure, draining/shutdown timeout, exhausted transport retries, or HTTP 408/429/5xx | Bounded retry after connectivity recovers |
| `Unauthenticated` | Transport refused an unauthenticated session | Authenticate before retrying |
| `TransportSecurity` | TLS verification or certificate pin failure | Stop; repair the trusted binding before retrying |
| `ValidationFailed` | Other HTTP 4xx, codec/protocol/oversized-frame failure, invalid DNS name, incompatible or nonproduction backend, unsupported operation, or another permanent transport failure | Correct the request/configuration first |

Only recognized HTTP status diagnostics emitted by the transport (`HTTP <code>`
or `HTTP/2 <code>`) classify as HTTP 408/429/5xx. An arbitrary HTTP error string is not a
retryable outage. Other task, contact, capability and grant refusals retain their
specific codes. A quota refusal needs capacity to become available; do not spin
on it.

The task approval decision applier uses an explicit transient allowlist:
`InboundPending`, storage/I/O failures, transient transport variants above, and
gateway-session unavailable/rejected errors. It retains those decisions for a
later bounded courier pass. Every other application error rejects the decision;
a permanent validation, authentication or trust failure never becomes an
indefinitely retried approval. Task scans log and skip task-local errors while
preserving storage/I/O and account-wide capacity backpressure. A skipped task
never authorizes a grant.

QUIC crypto alerts retain their typed TLS classification through mesh, gateway,
and relay-pool calls. HTTPS source chains are checked for rustls verification
failures before applying timeout/connect/body retry rules. Authentication and
trust failures keep their codes through contact availability wrappers. A failed trust check
does not poison the mesh outage circuit breaker for a caller with valid roots.
Postcard encoding/decoding, missing binary magic and runtime payload mismatches
are protocol errors, so they never become retryable QUIC outages.

The C ABI uses the same transport policy: authentication and TLS failures map to
`AuthFailed`, temporary failures to `TransportUnavailable`, and permanent frame
or configuration failures to `InvalidArgument`.

Repeated task-row warnings are limited to once per stable row key per hour in
this daemon process. The warning cache has a fixed 4096-key bound; a full window
suppresses new keys until space expires. Logging happens outside its mutex.
