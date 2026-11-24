# Account reach

Reach and discovery are independent. Accounts start in `contacts_only` mode at
revision 1. Opening an account does not accept contacts or make a hidden name
searchable. The primary device authorizes each policy revision; linked devices
read the home-committed policy.

`account.reach.get {}` returns `{mode, revision, policy}` from the authenticated
home. `account.reach.set {mode, expected_revision, operation_id}` commits the next
revision. Modes are `contacts_only` and `open`. A stale revision returns
`reach_revision_conflict` with the current policy and revision. Operation IDs are
nonempty opaque strings of at most 256 bytes. Reusing an operation with different
policy bytes refuses; a completed retry never reopens an account subsequently
closed by a newer revision. Offline changes retain their exact signed intent.

The home reports signed reach records with username-directory evidence. Directory
and SDK observations reject rollback and same-revision substitution. Resolved
names and native contact cards/links carry the policy together with its signing
authority. Historical cards are hints; they grant neither message admission nor
contact consent. Restoring an archive preserves the higher signed observation
floor and never activates archived pending sends.

`conversation.start {name, text, operation_id}` resolves and pins the recipient,
then durably queues an intent. Its result contains `conversation_id`, `message_id`,
`placement` (`direct` for an open recipient, otherwise `requests`) and `state`.
`contact.requests.reply {request_id, text, operation_id}` first commits a home
permission scoped to the requesting root and conversation, then queues the reply
on `requests`. It leaves the contact request pending. Blocks refuse new replies.
Retries preserve the original intent identifiers and placement; changed text or
recipient under the same operation ID refuses.

These intents remain `pending` until destination-enforced sender work is enabled.
No unaccepted message uses a cost-free transport fallback. Opening an account
introduces no recipient quarantine count, byte or rate cap. Destination work,
close/block enforcement, node protection and delivery are the next activation
boundary; a queued intent is not a delivered message.
