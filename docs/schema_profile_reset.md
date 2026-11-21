# Storage profile generation and development reset

The active application profile is generation **1** (message schema v1). Development
account, index, backup and gateway stores require the coordinated reset. Generation-0
stores are refused with `schema_reset_required`; there is no compatibility reader or
down-migration. The protocol design is `docs/design/message_schema_v1.md`.

SQLite `PRAGMA user_version` is the durable application-profile marker, separate
from SQL migration checksums and versions. Existing unmarked databases read as
zero. All account/index opens, query-only readers and private archive/restore
opens check it after applying the encryption key and before application-table
access or migrations. This check performs no writes and installs no migration.
SQLite snapshots and re-encrypted copies retain the marker. New profile creation
publishes a private, fully written generation-1 database header atomically before
application schema access. It never initializes or replaces an existing database,
including an empty generation-0 file. Account headers use the account encryption
key. Concurrent creation cannot overwrite the winning database.

Backup streams additionally carry `schema_generation` in their authenticated
context totals. Absence means generation zero for existing archives. The SDK
checks it immediately after authenticating the header, before counts, payload
metadata decoding or staging. The enclosed database is checked independently,
so a matching outer header cannot authorize a different-generation database.
New exports always emit the active generation.

A mismatch returns typed `SchemaResetRequired`. Preserve the selected database
or archive and create a fresh store using a matching complete client/node
profile. Never delete, convert or downgrade the selected data automatically.
The bus code is `SchemaResetRequired`, backup failure is
`schema_reset_required`, and the exported C error is 23.

Before activation, stop the environment and drain/reset old node queues. To
revert activation, stop new-profile discovery and sends, preserve new databases,
archives and inboxes separately offline, and restore the complete matching old
client/node environment with retained old stores or fresh old-profile stores.
Keep the PR1 fence and its live wiring when reverting activation. It must refuse
new-generation inputs without changing them; never import new data into the old
profile. Preserve the new bytes until reactivation. Reverting the foundation
itself is outside this rollback procedure.
