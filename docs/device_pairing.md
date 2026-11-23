# Device pairing

Native SAS device pairing is released. Clients pair by default
(`RAMFLUX_DEVICE_PAIRING_ENABLED` unset or `1`; `0` turns it off). A node serves
the pairing routes and advertises `device_pairing_v2` and `primary_transfer_full_v1`
only when its operator sets `RAMFLUX_DEVICE_PAIRING_ENABLED=1`; a node without the
opt-in advertises neither. A client refuses to start a ceremony with a node whose
discovery record does not advertise `device_pairing_v2`. A phone joins an
existing account through in-process C ABI v2. Desktop GUI pairing companions
remain outside this release.

The product follows a phone-first account model: the phone is the primary device,
desktop clients mainly host agents, and the web client is a linked secondary.
Primary authority follows the verified native device role and keys; a desktop
session is not a prerequisite for pairing. The SDK, the reference CLI, and a
phone that calls `ramflux_v2_set_credential_provider` exercise this shared flow.

The phone installs that callback before `device.pair.join`. The supervisor asks
on the same in-process connection. Pairing join uses action `setup`. A call that
already uses the private channel may ask for `unlock` or `phrase`. The callback
writes the code into SDK-owned buffers. It is not a JSON field, an event, or a
log line, and the SDK zeroizes it when the callback returns. Joining does not
open a second daemon socket. An `account.unlock` request whose body omits
`passphrase` uses the same callback. `account.passphrase.rotate` still places
its codes in the request body; the bridge wipes that body after encoding and
does not ask the callback.

Pairing enrolls a separately generated device branch. Each device keeps its own
signing and agreement keys, local encrypted store and data passphrase. Pairing
never copies an existing device's ratchet state or account authority seeds.
For an owner's added device, `rf pairing begin` defaults to all five capabilities:
`call,group,message,register,sync`. Use `--capabilities` to select a narrower set.
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
client refuses an unsupported persisted record with `UnsupportedRecord` before
issuing an invitation. It never silently skips a record or falls back to the
older bounded handover payload. This full transfer workflow is still under
development.

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
64-bit counters use decimal JSON strings. Disk totals alone still show `streaming`.
After the receiver commits and signs an applied-input receipt, both peers show
`awaiting_reverse`; reverse proof, catch-up and installation are separate steps.
`pairing status` keeps the legacy ceremony view.

Local display clients can use `subscription.open` with their account ID and the
single topic `device.pairing.event`. Each event body is a closed
`ramflux.pairing.LocalEvent.v2`; invitation tokens and private input never appear
in it. The bounded display stream includes a sequence cursor and reports lag
when a reader must subscribe again. It is available for a staged recipient
without admitting ordinary account networking.

The narrow ABI's `ramflux_pairing_event_poll` also receives these background
snapshots after a successful pairing call. Its reader is separate from attended
credential calls and accepts only the handle's current operation and generation.
Closing the handle drains that reader; locking the account ends its daemon
subscription. Polling display events never requests a recovery phrase or a data
passphrase.

After enrollment, the approving device schedules one bounded history sync when
its ordinary native session is available. A failed attempt does not undo pairing;
use `rf device sync export` for a manual retry. A full-account transfer does not
schedule this separate history export.

Automatic enrollment history receipts are device-local excluded state in `pairing_own_sync`. They are never exported as history or imported as another device's pending work.
