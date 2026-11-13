# ramflux-client-model

Pure presentation calculations for native client adapters. This crate has no
dependencies, I/O, runtime, storage, account writer or UI framework.

- `conversation::Row` borrows one account snapshot's ID, title and displayable
  preview, with source unread/attention, pin and latest-activity facts.
- `conversation::page` filters and sorts pin/recent/ID, returns at most 100
  rows, and rejects queries above 1024 bytes. Offsets reset on snapshot changes.
  Pass `visible = false` for locked or inaccessible accounts.
- `conversation::totals` keeps unread messages separate from pending decisions
  and suppresses both for inaccessible snapshots.
- `receipt::present` returns an outgoing receipt, the remaining pre-acceptance
  retry delay and whether a manual retry is explicitly safe. Time does not
  turn acceptance into delivery/read or authorize a duplicate send.

Adapters must supply authenticated source facts, suppress deleted/erased text,
and discard borrowed presentations before applying a new snapshot. This is not
a full-text index, a receipt authority or a command admission policy. Hosts
own localization; business mutation remains in the SDK supervisor.
