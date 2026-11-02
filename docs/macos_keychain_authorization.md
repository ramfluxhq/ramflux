# macOS keychain authorization for the primary vault

The native primary vault keeps born-v3 primary, branch and headless-provisioning
seeds in the macOS keychain. This note records which processes may use which
keychain, how the SDK selects one, and what was measured. It complements the
custody boundary in [root key custody](root_key_custody.md) and the migration
rules in [home node migration](home_node_migration_sdk.md).

## Two keychain implementations

| | Data-protection keychain | File-based login keychain |
| --- | --- | --- |
| Selected by | `kSecUseDataProtectionKeychain = true` (or `kSecAttrSynchronizable = true`) | Default `SecItem` target on macOS |
| Entitlement | `keychain-access-groups` or `com.apple.application-identifier` (restricted) | None |
| Provisioning profile | Required; must authorize the entitlements and the signing certificate | None |
| Signing | Apple Development (devices in the profile) or Developer ID; Mac App Store re-signs | Any, including ad hoc |
| `SecAccessControl` / user presence | Supported (Touch ID or password sheet) | Not supported |
| `kSecAttrAccessible` | Enforced | Ignored; the item follows the keychain's lock state |
| Access control | Access group membership | Per-item ACL keyed by the creator's designated requirement |
| Process context | User login session (GUI, LaunchAgent, SSH with an unlocked keychain); never a LaunchDaemon | User login session with the login keychain unlocked |

Missing entitlement: `SecItemAdd` returns `errSecMissingEntitlement` (-34018).
Lookups do not: `SecItemCopyMatching` returns `errSecItemNotFound` (-25300), so a
read-only probe cannot detect the condition. A restricted entitlement claimed
without a matching embedded profile is worse: the system kills the process at
launch (`SIGKILL (Code Signature Invalid)`, "Unsatisfied entitlements").

A bare command-line tool has nowhere to embed a profile. To claim restricted
entitlements it must be wrapped in an app-like bundle with
`Contents/embedded.provisionprofile`. `rf` runs from inside the desktop bundle
and inherits nothing from it: entitlements belong to the main executable of each
process.

Ad hoc signatures have a designated requirement tied to one exact build (its
cdhash). Login-keychain ACLs created by one build therefore do not trust the next
one, and the first read after an update shows the "wants to use your confidential
information" confirmation. Choosing Always Allow trusts the new build.

## By macOS version

| macOS | Data-protection keychain for a non-App-Store tool | Notes |
| --- | --- | --- |
| 10.15 | Bundle + profile + `keychain-access-groups` or App ID | `kSecUseDataProtectionKeychain` introduced |
| 11 | As 10.15, and the executable must claim `com.apple.application-identifier` | Without the App ID claim the profile may be ignored and launch blocked |
| 12 | As 10.15; the profile is honoured without the App ID claim | Claiming App ID and `com.apple.developer.team-identifier` remains recommended |
| 13, 14, 15 | As 12 | No documented change; on 14.5 key items default to the data-protection keychain, so unentitled tools see -34018 |
| 26 | As 12 (measured below) | No documented change for this API |

Ad hoc signing cannot satisfy any profile on any version. Daemons are limited to
the file-based keychain on every version.

## Error codes

| Status | Name | Meaning here |
| --- | --- | --- |
| -34018 | `errSecMissingEntitlement` | No data-protection entitlement; triggers the login-keychain fallback |
| -25308 | `errSecInteractionNotAllowed` | Keychain locked or interaction disallowed (SSH, background session); fails closed |
| -25300 | `errSecItemNotFound` | Missing item; also returned by lookups that lack the entitlement |
| -128 | `errSecUserCanceled` | User dismissed a presence or ACL prompt; fails closed |
| -25293 | `errSecAuthFailed` | Authentication failed; fails closed |
| -50 | `errSecParam` | Unsupported attribute combination |

## Measurements on macOS 26

Measured on macOS 26 (Darwin 25.6.0) with a Swift probe that adds, reads and
deletes one generic password, run from an SSH session and from a LaunchAgent in
the user's GUI session. "Login" rows use `kSecUseDataProtectionKeychain = false`.

| Signing | Entitlements | Profile | Context | Data-protection add | Login add |
| --- | --- | --- | --- | --- | --- |
| Unsigned (linker ad hoc) | none | no | SSH | -34018 | -25308 (locked) |
| Unsigned (linker ad hoc) | none | no | GUI | -34018 | 0, read 0, delete 0 |
| Apple Development | none | no | GUI | -34018 | 0, read 0, delete 0 |
| Apple Development | `keychain-access-groups` | no | GUI | killed at launch (137) | n/a |
| Apple Development | App ID + team ID | no | GUI | killed at launch (137) | n/a |
| Apple Development | both | no | GUI | killed at launch (137) | n/a |
| Ad hoc | each of the three sets | no | SSH | killed at launch (137) | n/a |

Lookups of a missing item returned -25300 for both keychains, with and without
`kSecUseAuthenticationUIFail`, in every unentitled case. Signing with the Apple
Development identity failed over SSH (`errSecInternalComponent`) because the
login keychain holding the key was locked.

No signing route without a macOS provisioning profile can reach the
data-protection keychain.

## Selection in the SDK

1. `preflight()` runs before any phrase is generated (creation and recovery). It
   inserts and deletes a non-secret probe item in the data-protection keychain.
2. Status 0 selects the data-protection keychain (`vault_class:
   software_os_credential_non_synchronizing`).
3. Status -34018 repeats the probe in the login keychain. Success selects it
   (`vault_class: software_os_credential_login_keychain`). Login items use a
   separate service, `org.ramflux.identity.primary.login-keychain.v1`, are
   non-synchronizing and request when-unlocked-this-device-only.
4. Any other status, including a locked login keychain, fails with
   `CustodyVaultUnavailable` before the phrase is shown. There is no plaintext
   file fallback.

The choice is cached per process after a successful probe; failures are retried.
New authority records the class, and the account summary reports it. Reads try
the data-protection store first and then the login keychain, so an account
created by an unentitled build remains usable after an entitled upgrade. Every
loaded key is still checked against the signed public record.

The login-keychain class never stores user-presence items, so home-node
migration signing refuses with `custody_user_presence_unavailable` for it.

## Getting the protected class

Ship the desktop app signed with Developer ID (or Apple Development for listed
devices), wrap `rf` in its own app-like bundle with an embedded macOS profile for
the same team, and claim `com.apple.application-identifier`,
`com.apple.developer.team-identifier` and `keychain-access-groups` for that App
ID. Until then ad hoc builds use the login-keychain class.

## Sources

- TN3137, On Mac keychain APIs and implementations: <https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains>
- TN3125, Inside Code Signing: Provisioning Profiles: <https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles>
- TN3127, Inside Code Signing: Requirements: <https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements>
- Signing a daemon with a restricted entitlement: <https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement>
- Sharing access to keychain items among a collection of apps: <https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps>
- `kSecUseDataProtectionKeychain`: <https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain>
- `kSecAttrAccessible`: <https://developer.apple.com/documentation/security/ksecattraccessible>
- `errSecMissingEntitlement`: <https://developer.apple.com/documentation/security/errsecmissingentitlement>
- SecItem: Pitfalls and Best Practices: <https://developer.apple.com/forums/thread/724013>
- Resolving Code Signing Crashes on Launch: <https://developer.apple.com/forums/thread/706427>
- Forum threads on -34018 for command-line tools: <https://developer.apple.com/forums/thread/714752>, <https://developer.apple.com/forums/thread/759481>
