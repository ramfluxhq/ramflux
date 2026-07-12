<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (c) 2026 Span Brain -->

# Federation trust materials (operator-provided, offline-signed)

The production relay verifies the federation issuer trust chain against materials placed in this
directory (mounted read-only at `/etc/ramflux/federation`). **No private key is ever stored here or in
any service container** — all signing is performed OFFLINE, out of band, by the operator.

Two files are served/verified (both are public data + signatures):

## `provider-keyring.json` — the provider keyring (T23-A2b2b)

An offline-root-signed document that authorizes which provider signing keys may sign the trust-snapshot
envelope, and for which exact `provider_epoch`. The relay pins the **offline root PUBLIC key** via
`RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY` (an independent trust anchor — never a provider or
snapshot key) and rejects any keyring not signed by it.

Shape (fill in real base64url Ed25519 public keys + signature; sign `keyring_signature` offline over the
canonical document with `keyring_signature` cleared):

```jsonc
{
  "schema": "ramflux.federation_provider_keyring.v1",
  "version": 1,
  "issuer_node_id": "<your federation issuer node id>",
  "keyring_epoch": 1,                    // monotonic; only a strictly higher epoch may change content
  "keys": [
    {
      "key_id": "provider-2026Q3",
      "public_key": "<base64url ed25519 provider public key>",
      "not_before": 0,
      "not_after": 4102444800,
      "retired_at": null,                // set to a unix second to retire (then this key stops authorizing)
      "authorized_provider_epoch": 1     // the EXACT provider_epoch this key may sign
    }
    // during a rotation, stage the next key here (higher keyring_epoch) before cutting the envelope over
  ],
  "keyring_signature": "<base64url ed25519 signature by the OFFLINE ROOT over the canonical keyring>"
}
```

## `trust-snapshot.json` — the provider-signed trust snapshot envelope

The versioned (`..._envelope.v4`) `ProviderSignedTrustSnapshot`, signed OFFLINE by the provider key whose
`key_id`/`authorized_provider_epoch` appear in the keyring above. The federation node serves this file
verbatim (it holds no signing key); the relay verifies it against the keyring.

## Fail-closed

If the keyring file is missing/empty/corrupt, the offline-root public key is wrong, or the relay cache
path is unset, the relay's federation trust provider fails closed at start (it does not authorize any v3
object request). Rotate by publishing a higher-`keyring_epoch` keyring, then a higher-`provider_epoch`
envelope signed by the newly-authorized key.

This directory is git-tracked only by its `.gitkeep`; place real (public) materials here at deploy time.
