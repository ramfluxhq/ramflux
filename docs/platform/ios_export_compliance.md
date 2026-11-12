# iOS export-compliance strings (draft, not submitted)

Status: **draft**. Nothing here has been submitted to App Store Connect, to the US Bureau
of Industry and Security, or to the French authority. It is not legal advice. A person
responsible for the release must review it against the rules in force on the submission
date before any value below is used.

## What the app contains

The iOS app links the ramflux core as a static library. The encryption in that library is
not limited to what the Apple operating system provides:

| Purpose | Algorithms (all published standards) | Implementation |
|---|---|---|
| End-to-end message and attachment protection | X25519, HPKE (RFC 9180) with AES-GCM, ChaCha20-Poly1305, AES-256-GCM, HKDF, HMAC, SHA-2, BLAKE3 | Rust crates compiled into the app |
| Signatures and device identity | Ed25519 | Rust crates compiled into the app |
| Passphrase key derivation, recovery phrase | Argon2, BIP-39 word encoding | Rust crates compiled into the app |
| Local database at rest | SQLCipher (AES-256) | bundled C library compiled into the app |
| Transport to the user's node | TLS 1.3 over QUIC and over TCP | `rustls` with `ring`, compiled into the app |
| Key storage | Keychain items | Apple operating system |

The app implements **no proprietary or unpublished algorithm**. Every primitive is a
published standard or a published, openly specified construction. The source is public.

## Draft answers

### `Info.plist`

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<true/>
```

Reason for `true`: the app's encryption is user-data confidentiality implemented in the
app itself, not only authentication and not only encryption supplied by the operating
system. Do not set `false` to skip the questions.

`ITSEncryptionExportComplianceCode` is left out until App Store Connect has issued a code
for uploaded documentation. A placeholder value must never ship.

### App Store Connect encryption questions

| Question (paraphrased) | Draft answer |
|---|---|
| Does the app use encryption? | Yes. |
| Does it qualify for an exemption because it only uses encryption within the Apple operating system? | No. |
| Does it implement proprietary encryption algorithms not accepted by international standard bodies (IEEE, IETF, ITU)? | No. |
| Does it implement standard encryption algorithms instead of, or in addition to, those provided by the Apple operating system? | Yes. |
| Will the app be available on the App Store in France? | Decide per release; see below. |

### Documentation this answer set leads to

Per Apple's "Export compliance documentation for encryption" reference, an app that uses
an industry-standard algorithm not provided within the Apple operating system uploads a
**French encryption declaration** when it is distributed on the App Store in France. A
US CCATS is listed there only for proprietary algorithms, which this app does not have.

Open items for the release owner (none is decided by this document):

1. **France.** Either file the French encryption declaration and upload it, or leave
   France out of the storefront list for the first release.
2. **US classification.** Confirm the classification of the app under the US Export
   Administration Regulations with whoever is responsible for the project's export
   filings, including whether a self-classification report or a notification for publicly
   available encryption source code applies. This document does not assert an ECCN.
3. **Other storefronts.** Check local rules for each country added to the storefront
   list.

### Review notes (draft text for the App Review information field)

> This app is an end-to-end encrypted messenger. Message content is encrypted on the
> device with published standard algorithms (X25519, HPKE, AES-GCM, ChaCha20-Poly1305,
> Ed25519) and can be read only by the conversation's participants. The app connects only
> to the server the user chooses; it has no central service operated by the developer.
> Local data is stored in an encrypted database inside the app's own container. The app
> uses no proprietary cryptography.

### Consequence for a node operator

The operator of a node distributes nothing through the App Store and makes no
App Store export statement. An operator who redistributes a build of the app, or hosts
the web client, is a distributor of encryption software in their own jurisdiction and
must check the rules that apply to them. The project does not encode any one country's
law in the client and adds no country-specific behaviour.

## Where the values live

- `bindings/apple/Harness/Info.plist` carries the draft `ITSAppUsesNonExemptEncryption`
  value for the acceptance harness, which is never submitted.
- A product app target copies the key from this document after review.

## Sources checked

- Apple, "Export compliance documentation for encryption":
  https://developer.apple.com/help/app-store-connect/reference/export-compliance-documentation-for-encryption
- Apple, "Complying with Encryption Export Regulations":
  https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations
  (the page body could not be read by the tool used for this draft; the key names above
  must be re-verified against it)
