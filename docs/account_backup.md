# Encrypted account backup

`account.backup.export` encrypts the account recovery manifest and a bounded relationship
snapshot with the existing passphrase-derived AEAD key. Contacts and peer root commitments
are inside the ciphertext, never in clear-text backup metadata. The snapshot uses the same
root-bound contact payloads as own-device synchronization: restrictions precede acceptances,
with at most 512 payloads and 3 MiB of base64-encoded contact data. Contacts without cached
peer manifests and entries beyond that budget continue through sibling backfill.

`account.backup.import` authenticates the backup before installing contacts, verifies each
peer manifest and relationship's owned-root binding, and applies the snapshot atomically.
Existing blocks, removals, and revoked capabilities override restored acceptances. Import
remains offline; fresh device activation and network registration are separate operations.
A new device can authenticate a first peer message using contacts restored from the backup,
without waiting for a background sibling queue tick. The snapshot describes state at export;
later changes still require synchronization. Legacy backups without the optional contact
snapshot remain readable and require contact backfill or explicit contact acceptance.
