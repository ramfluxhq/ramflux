# Large attachment version-one codec vectors

`large_attachment_v1.json` contains seven fixed known-answer records, independently
calculated with Python cryptography 46.0.3 / blake3 1.0.8 and cross-checked with
Swift CryptoKit. It freezes canonical protobuf media bytes, native manifest and
signature inputs, domain-separated hashes, and segment AEAD outputs.

Plaintext byte `j` is `j % 251`. Cases cover empty, 31 bytes, P-1, P, P+1,
and 2P+17 bytes, where P=4194304-16. The final case independently encrypts the
31-byte case with fresh key/object identity and identical segmentation.
Large ciphertext is fixed by SHA-256 and boundary bytes; short ciphertext is
included in full. Every seed and key is public test material.

These are codec fixtures: placeholder wrapped key slots and absent registration
receipts confer no production authority. Plaintext digests and full inner
manifests are encrypted message metadata, never relay-visible fields.
