# Device pairing preview / CLI only

Native SAS device pairing is a preview for the SDK and reference CLI. It remains
default-off. Desktop and mobile pairing companions are unavailable; this preview
does not establish their readiness or enable pairing for ordinary clients.
The node release gate also suppresses discovery advertisement while the feature
is dormant. Setting an environment opt-in does not override that release gate.

Pairing enrolls a separately generated device branch. Each device keeps its own
signing and agreement keys, local encrypted store and data passphrase. Pairing
never copies an existing device's ratchet state or account authority seeds.
Both people using the devices must compare the displayed SAS and confirm locally
before the primary can approve enrollment. An invitation token is a temporary
bearer credential: transfer it through the attended pairing flow and keep it out
of logs, command arguments, saved status and shell history.

The invitation's signed node key and account context arrive through the trusted
QR or manual invitation exchange. A self-consistent signature on an invitation
does not independently authenticate an unfamiliar node. The HTTPS relay origin
must be an HTTPS origin without credentials, a path, a query or a fragment; TLS
certificate validation still applies. Relay access cannot authorize an ordinary
account session. Every primary pairing attempt owns a fresh authenticated native
proof connection and closes it when the ceremony ends.

A recipient becomes eligible for ordinary networking only after it independently
reads the acknowledged native head and verifies inclusion of its actual local
keys. Interrupted installation remains fenced until native authority, the local
vault, the encrypted account DB and the installed marker agree. A relay success
or an approval message alone is insufficient.

Cooperative primary transfer preserves the other devices and their denial state.
The destination supplies its recovery phrase through a dedicated private local
prompt to certify a fresh management key. Neither the phrase nor a data-store
passphrase belongs in pairing JSON or generic events. The original primary
retains its branch identity as a secondary after transfer; management-key cleanup
does not authorize deleting that branch. Existing targets retain their own data
credential and key references.

Peers without the required pairing profile return `UpdateRequired`. Pairing does
not fall back to phrase recovery, legacy root signing or a weaker relay route.

Full-account primary transfer uses the `full_account_data_v1` profile, committed
inside the v3 SAS context on both devices. It transfers supported logical account
data through an encrypted, resumable stream; device secrets remain local. The
preview refuses an unsupported persisted record with `UnsupportedRecord` before
issuing an invitation. It never silently skips a record or falls back to the
older bounded handover payload. This full transfer workflow is still under
development and is not enabled for ordinary clients.

A durable chunk receipt confirms encrypted staging on the receiving device. It
does not confirm that data was applied, that a primary change was published, or
that the recipient can open a session. Those steps require separate verification
of the merged data, the exact native publication and local installation. After
a successful primary change, a final catch-up tail remains pending until the
receiver merges it or the user explicitly abandons it; lease expiry or another
primary change does not silently mark the tail complete.

For an existing full-transfer stage, `rf pairing --account <id> transfer-status
--operation-id <id> --generation <n>` reads `device.transfer.status` through the
same SDK coordinator. The response contains only the role, stage, cut, lease,
byte totals, missing-attachment count, tail status and an exact typed error. Its
64-bit counters use decimal JSON strings. During the current disk-only phase,
completed byte totals still show `streaming`; they do not claim semantic
verification or installation. `pairing status` keeps the legacy ceremony view.
