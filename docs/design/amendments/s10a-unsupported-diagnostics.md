# S10a Unsupported diagnostics

OV2-RX-UNSUP uses the first matching reason in this order:
`layer_above_supported`, `unknown_kind`, `unknown_field`, `unknown_enum`,
`unknown_entity`, `body_undecodable`, `identity_undecodable`.
These labels describe the decoder result and grant no authority. Malformed
wire, lifetime, consent, identity and native-operation checks remain admission
requirements. This amendment does not admit an otherwise refused input.

An Unsupported view backed by retained raw bytes exports a random 16-byte
`raw_handle`. Its source-qualified copy id remains in the local private mapping.
The mapping and view join the receive transaction and message erasure footprint.
Redelivery keeps the same handle. A successful reparse retires the handle with
its Unsupported view in the installing transaction. If channel policy instead
retires the raw bytes and keeps a non-actionable historical diagnostic, that
view's handle is empty and its private mapping is removed. Neither form contains
native execution authority or claims that an erased body remains available.

An Edit targeting an existing Unsupported placeholder waits for its Message
content just as an Edit targeting absent content does. Early-Edit registers are
qualified by the original author root as well as target id; an accepted peer in
another conversation cannot replace that author's register by naming its id.
When the verified original identity becomes available, foreign pending claims
are retired. Upgrade installation resolves the legitimate parked Edit in the
same writer transaction and publishes the resulting content in force, with the
original immutable identity and the actual journal cursor. It never publishes
an original preview that the winning Edit has just retired.
