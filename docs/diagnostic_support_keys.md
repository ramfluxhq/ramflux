# Pinned diagnostic support public keys

The core SDK exposes the release-pinned, public-only catalog in
`crates/ramflux-sdk/diag/support-public-keys.v1.json` through the standalone
`int32_t ramflux_v2_diag_support_key(struct RamfluxBuffer **out)` export. It does
not open an account, read files or use the network. Free a successful output
with `ramflux_v2_buffer_free`; a null output slot returns InvalidArgument (1).

The committed empty catalog deliberately disables support encryption and returns
`{"available":false,"reason":"support_key_unavailable"}` with status 0. No test
or placeholder key enables uploads. Provisioning requires a normal public-key
commit and application re-pin. The controller generates the real private epochs
offline; neither this repository nor the SDK receives private support keys.

A provisioned output is the catalog itself (not a wrapped response):

- `schema`: `ramflux.diag.support-keys.v1`
- `active_epoch`: the positive integer epoch selected for new encryption
- `keys`: at most eight entries, each containing `epoch`, `kem_id=32`,
  `kdf_id=1`, `aead_id=3`, `public_key` (32-byte unpadded base64url),
  `encrypt_not_before`, `encrypt_until`, and `accept_until`

The complete catalog is at most 4096 bytes. Unknown/duplicate fields, duplicate
epochs, unsupported suites, zero keys and malformed windows are refused.
Timestamps are canonical UTC RFC3339 at whole-second precision;
`accept_until` equals `encrypt_until` plus 30 days. A malformed embedded catalog
also returns `support_key_unavailable` rather than exposing partial key material.

Applications select only `active_epoch` within its encryption window. They must
not downgrade, download a replacement key or accept a node-supplied endpoint or
key. Public-key rotation ships in a new core/application release. Old private
epochs remain offline through the last accepted bundle's retention deadline;
compromise requires admission revocation and a new pinned application build.
The catalog is public material, not permission to upload without preview and
explicit consent. File export remains available when support is unavailable.

Bundle construction, HPKE sealing and the upload service belong to the client
and publisher service. There is no sealing ABI or compiled service origin in the
SDK. The accepted envelope uses RFC 9180 Base mode DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256 and ChaCha20-Poly1305, with `info` equal to ASCII
`ramflux.diag.upload.v1` plus NUL. The sender first obtains `enc`, serializes the
reservation once and seals the ZIP once with those exact bytes as AAD, sequence
zero. Ciphertext length is bundle length plus 16; no separate nonce is sent.
The application must retain the exact reservation bytes for offline support.
The service wire contract and its origin are owned separately from the core.
