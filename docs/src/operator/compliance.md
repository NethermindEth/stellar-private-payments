# Compliance controls

A pool gives its operator a fixed set of controls. None of them lets the admin move a user's
funds: only `transact` moves tokens, and only with a proof from the notes' owner.

| Control | Enforces | Doesn't | Set |
| --- | --- | --- | --- |
| Allowlist | Only enrolled note public keys can spend or deposit | Screen recipients, or tell you who holds a key | Policy at deployment; members any time |
| Blocklist | Listed note public keys can't spend or deposit | Stop a user from deriving new keys from a new Stellar account | Policy at deployment; entries any time |
| Maximum deposit | No single deposit exceeds the limit | Limit a user's total, or limit withdrawals | At deployment |
| Deposit pause | No new deposits enter the pool | Stop transfers or withdrawals | Any time, by the admin or a pause file |
| GVK | The GVK holder can read every note, and in traceable mode every spend | Let the holder spend, freeze, or change anything | At deployment |
| Selective disclosure | A user can prove to an authority that they own chosen notes | Let anyone but the user produce the proof | Always available to users |
| Asset rules | The token's issuer can't freeze or claw back the pool's balance | Apply to the asset outside the pool | At deployment |

## Screening

The allowlist and the blocklist screen the note public key of each note a transaction spends,
including the zero-value notes a client spends in a deposit, which carry the depositor's key. A
user therefore passes the ASP check on every deposit, transfer, and withdrawal, but never as a
recipient: a blocked key can receive a note and can't spend it.

Listing a key on the blocklist freezes every note it owns in every pool that reads the blocklist,
until the key is released. Removing a member from an allowlist freezes their notes the same way.
Ask users to withdraw before removing them where you can.

The screened value is a note public key, not a person. Linking a key to a person happens off chain,
in your own onboarding. For allowlist enrollment, see [Run an ASP](run-an-asp.md).

## Audit

A GVK pool encrypts each note to the GVK public key fixed at construction. The GVK holder decrypts
them on the admin page's Global View tab, with any connected wallet, and can export the result as
CSV. In view-only mode the holder sees each note's owner's note public key, amount, and blinding
when it is created. In traceable mode the holder also sees which note each spend consumed, which
links a user's whole history.

Without a GVK, audits depend on users. Selective disclosure lets a user prove ownership of up
to four notes at a time to an authority they name, in a receipt anyone can check without a wallet.
For the receipt format and its checks, see [Selective Disclosure](../disclosure.md).

## What is public

Every deposit and withdrawal shows its address and amount, every transaction shows the account
that sent it, and the blocklist shows every key on it. Transfer amounts and recipients, and which
deposit funded which withdrawal, stay private. For every value by event, see
[Contract event privacy](../privacy-tradeoffs.md).
