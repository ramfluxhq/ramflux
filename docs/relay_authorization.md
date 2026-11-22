# Object relay authorization

The gateway issues object relay v3 tokens through `relay_token_v3_issue` and
returns `relay_token_v3_issued`. The relay validates the gateway issuer
certificate and trust snapshot, token scope, and requester proof of possession.
Shared-HMAC object relay tokens and their issuance frames are not supported.
The gateway has no object relay shared-key loader or local-mint feature.
Voice and TURN authorization are separate mechanisms.

Retained v3 object tombstones store the object and optional manifest scope,
tombstone hash, source event, signing time, expiry, and immutable owner signing
key identifier and public key. They contain no synthetic relay token or object
permission envelope. Replay equality includes every retained field; a replay
cannot extend expiry or change ownership.

This changes the relay database tombstone row format. A relay database with
tombstones written by an older build must be replaced with fresh relay state
before starting this build. There is no migration or alternate reader. The
v3 client request and response formats are unchanged.
