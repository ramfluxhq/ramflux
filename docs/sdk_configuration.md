# SDK account configuration

Offline retention for newly sent content defaults to seven days (604800 seconds).
Use `RamfluxClient::set_offline_retention_secs` and `offline_retention_secs`, or
local bus `account.config.set` / `account.config.get` with
`{"offline_retention_secs": 604800}` on an unlocked account. Values outside
3600..=604800 are rejected with `InvalidOfflineRetention`; the setting persists
per account and is read when sending. DM/group content, membership/key controls,
message object manifests and own-device copies use this setting, including bus
sends with a legacy per-message TTL field. Signed contact/group request deadlines
still bound their carriers. Existing queued envelopes are unchanged. Call signals,
best-effort receipts and reset handshakes keep their named short deadlines; the
server's seven-day maximum is unchanged. This is mailbox retention, independent
of disappearing-message timers or attachment relay retention.
