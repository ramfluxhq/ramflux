# Android host integration for the in-process core

On Android the application process is the supervisor. There is no daemon, no
socket and no second process. This note lists what the host application must
do, and which SDK check enforces each rule. The Rust surface is
`ramflux_sdk::android`; the Keystore helper is
`crates/ramflux-sdk/android/src/main/kotlin/org/ramflux/sdk/vault/KeystoreBridge.kt`.

## Storage

Pass `Context.getNoBackupFilesDir()` to
`AndroidStorage::from_no_backup_files_dir`. Nothing else is accepted.

| Path | Result |
| --- | --- |
| `/data/user/<n>/<package>/no_backup`, `/data/data/<package>/no_backup` | accepted |
| `getFilesDir()`, `getDatabasePath()`, any other private directory | refused: Auto Backup copies it |
| `/sdcard`, `/storage/...`, `/data/media/...`, `/mnt/expand/...` | refused: shared, external or adopted storage |
| `/data/user_de/...` | refused: device-protected storage is readable before first unlock |

The SDK creates two owner-only directories there: `ramflux` (account index,
SQLCipher databases with their WAL files, the object spool, `daemon.lock`) and
`ramflux-vault` (Keystore-wrapped vault entries). The embedded supervisor
checks the data root again before it opens anything, and `prepare` proves that
advisory file locks are effective on the filesystem, because the data-root lock
and the account writer lock depend on them.

Set `android:installLocation="internalOnly"`. An application moved to adopted
storage gets a `/mnt/expand/...` data directory, which is refused.

## Backup and device transfer

All three are required. `allowBackup="false"` alone does not stop a
device-to-device transfer on every Android 12+ device.

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/ramflux_data_extraction_rules"
    android:fullBackupContent="@xml/ramflux_full_backup_content"
    android:installLocation="internalOnly">
```

The two rule files are `android::backup::DATA_EXTRACTION_RULES_XML` (Android 12
and later; excludes every domain for `cloud-backup` and `device-transfer`) and
`android::backup::FULL_BACKUP_CONTENT_XML` (Android 11 and earlier). A build or
instrumentation test must run `check_manifest`, `check_data_extraction_rules`
and `check_full_backup_content` against the merged manifest and the shipped
resource files, and should also inspect a real backup with
`adb shell bmgr backupnow <package>`.

Moving an account to a new phone uses the recovery export. A wrapped vault
entry copied without its Keystore key cannot be opened; the SDK reports
`vault_missing` and never creates fresh state under the old device identity.
The application then offers two actions only: restore from a recovery export,
or delete the orphan and link as a new device.

## Vault

Seeds are wrapped by an AES-256-GCM key in the Android Keystore. The Keystore
key never leaves secure hardware; the seed is never a Keystore key.

1. Load the native library.
2. Touch `KeystoreBridge`; its initializer registers the class with the SDK.
3. Call `install_android_vault(storage.vault_dir(), prefer_strongbox)`.

Until step 3 every vault operation fails closed.

| Rule | Behaviour |
| --- | --- |
| Hardware | The key must report `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` or `SECURITY_LEVEL_STRONGBOX` (API 31+), or `isInsideSecureHardware()` before that. Any other key is deleted and refused. There is no software or file fallback. |
| StrongBox | Opt-in. `prefer_strongbox = true` requests StrongBox and falls back to the TEE on `StrongBoxUnavailableException`. |
| Background key | No user authentication and no unlocked-device requirement, so it works after first unlock while the device is locked. |
| Presence key | Authentication for every use. The application registers a `PresencePrompter` that shows `BiometricPrompt` with a `CryptoObject`. Without one, ceremonies that need presence are refused. |
| Recorded class | `hardware_wrapped_android_keystore_tee` or `hardware_wrapped_android_keystore_strongbox`. Before API 31 a StrongBox key is recorded as TEE. |
| Emulator | Emulator and CI builds use the `itest-memory-vault` test feature. Production builds cannot enable it. |

Keep `org.ramflux.sdk.vault.KeystoreBridge` and `PresencePrompter` in the R8
keep rules; they are called only through JNI.

## Lifecycle

Forward `ProcessLifecycleOwner` events to `AndroidHost`:

| Event | Call | Effect |
| --- | --- | --- |
| `ON_START` | `on_foreground()` | Starts a stopped core, resumes a suspended one |
| `ON_STOP` | `on_background()` | Sends `Close`, closes every database, releases `daemon.lock`; returns only after the release was observed |
| Task removed | `on_shutdown()` | Stops the core |

Call them off the main thread. Android does not announce the death of a cached
process, so a background process must hold no database and no lock; that is
the state `on_background()` leaves. A recreated process starts from `Stopped`
and resumes its gateway session from the database.

Message sync never holds a foreground service. Only an active call may, with
`android:foregroundServiceType="phoneCall"`. Doze and App Standby suspend the
network for a background process; the connection is expected to end there. Do
not request a battery-optimization exemption for message sync.

## Network

Register one `ConnectivityManager.registerDefaultNetworkCallback` and forward
every callback to `AndroidHost::network()`. Do not call synchronous
`ConnectivityManager` getters inside a callback. Forward
`ACTION_DEVICE_IDLE_MODE_CHANGED` to `on_device_idle_changed`.

Create one `NetworkMonitor`, pass it to `AndroidHost::new`, and call
`AndroidHost::install_session_defaults()` once before the first
`on_foreground()`. From then on every gateway session the core opens shares
that monitor and uses the raced order, and the transport that worked is
remembered per network for ten minutes.

The session uses the `Auto` transport (QUIC raced against TCP+TLS on 443) on
the default network. It never binds a specific `Network`, including under a
VPN. A metered network only defers bulk transfers the user did not ask for.

The network security configuration sets `cleartextTrafficPermitted="false"`.
A debug override that trusts user certificate authorities belongs in the debug
source set only. The gateway session is pinned by the node's certificate
authority, not by the platform trust store, and no screen offers to trust a
certificate.

## Push

Push is optional at build time and at run time. A build without the
`android-push-fcm` feature contains no vendor-push code, and a device without
Google Play services reports `NotificationMode::ForegroundOnly`: messages
arrive while the application is open and there is no notification otherwise.
Sending and receiving do not depend on push.

With a provider, the messaging service calls `WakePayload::parse` on the data
fields and acts on `wake_action`: post the fixed generic notification, or
report an incoming call that is at most 30 seconds old. The provider message
is data-only and carries an opaque wake id and a class; any other field is
refused. The service must not open the database or a connection.

## Node operator note

A node that enables a push provider learns, per device, a provider token, the
timing and the class (`message` or `call`) of each wake. The provider learns
the same. Neither learns the sender, the conversation or the content. An
operator who does not configure a provider loses background notifications for
Android users and nothing else.
