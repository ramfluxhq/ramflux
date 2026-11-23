<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Node media limits and upload checkpoints

These calls use the existing `AttachmentFrame` on the authenticated gateway session.
The gateway supplies the requester from that session and forwards to the local relay
at `/attachments/v1/call`. Clients cannot select another account for accounting.
The SDK integration cards own the bus and C ABI methods; these are node wire calls.

`{"call":"account_status"}` returns `AttachmentAccountStatus` as JSON in the
ordinary reply body. `limits` contains `max_plaintext_bytes`, `quota_bytes`,
`network_chunk_bytes`, `segment_bytes`, `retention_seconds`,
`pending_lease_seconds`, and `pending_max_seconds`. Defaults are 4 GiB per object,
20 GiB per account, 512 KiB slices, 4 MiB cipher segments, seven days of retention,
and a one-hour pending lease with a 24-hour ceiling. The SDK must use the lesser
of its own object limit and the advertised node limit.

`usage` contains disjoint `used_bytes`, `reserved_bytes`, and `cleanup_debt_bytes`.
Their sum is `charged_bytes`; `available_bytes` saturates at zero when an operator
lowers the quota below existing charge. All accounting is ciphertext, including
AEAD tags, shared across the account's devices. Expiry or retirement fences access
before erasure. Failed erasure retains its charge; the bounded cleanup worker
retries durable debt after restart. A repeated Reserve, PUT, or Commit does not
add charge. A conflicting PUT refuses without removing accepted slices.

`upload_status` takes base64url `upload_id`, `object_id`, `manifest_hash`, integer
`payload_generation`, and zero-based segment `index`. The result is
`AttachmentUploadStatus`: `state`, `payload_generation`, `index`,
`received_bitmap`, `received_bytes`, `segment_length`, `network_chunk_bytes`,
`lease_until`, `lease_hard_until`, and nullable `expires_at`. Bit n acknowledges
the slice at n * network_chunk_bytes within this segment; the final slice may
be shorter. The node re-hashes acknowledged bytes before returning the bitmap.
A missing checkpoint reports zero; corrupt checkpoint metadata fails closed.
Query every segment needed for resume; a bitmap never authorizes a read or
extends a deadline. Retry unacknowledged slices using the identical ciphertext
and immutable identity, with a fresh requester proof. Expired, foreign, or
substituted uploads refuse through the existing typed reply `code`.

Operator overrides (unsigned decimal values) are
`RAMFLUX_RELAY_ATTACHMENT_QUOTA_BYTES`,
`RAMFLUX_RELAY_ATTACHMENT_MAX_PLAINTEXT_BYTES`,
`RAMFLUX_RELAY_ATTACHMENT_RETENTION_SECONDS`,
`RAMFLUX_RELAY_ATTACHMENT_PENDING_LEASE_SECONDS`, and
`RAMFLUX_RELAY_ATTACHMENT_PENDING_MAX_SECONDS`. Invalid policy fails startup;
the object limit cannot exceed 4 GiB and quota must be positive. Reducing limits
does not evict existing reservations or waive cleanup debt. Retention and lease
terms already persisted on an upload remain unchanged.
