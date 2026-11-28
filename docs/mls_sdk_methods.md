# MLS SDK methods

Direct messages. The first send to a peer establishes one MLS group and fans the Welcome only after the orderer's merge. A lost race deletes only the losing group. While an identity change is pending, `conversation.send` with that same operation id returns `identity_change_pending` and does not send. `contact.trust.accept_change` records the acceptance and does not send; the client sends again with a new operation id. `conversation.security` reports the group's phase, epoch, and members.

from G6
