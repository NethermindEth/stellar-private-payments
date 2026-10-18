# Advanced transactions

`spp transact` lets you choose exactly which notes to spend and what each
private output is. Use `deposit`, `transfer`, and `withdraw` unless you need
that control.

A transaction takes at most two `--input` notes and at most two `--output`
values, and must balance:

```text
input notes + deposit = private outputs + withdrawal + pool fee
```

Every transaction pays the pool fee, a fixed amount set when the pool is
deployed. `--deposit` is what leaves your account, fee included, and
`--withdraw` is what the recipient receives. `spp transact` refuses an
unbalanced transaction before proving, and its error names the fee in the
token's smallest unit. The examples below assume a fee of 0.1 tokens.

A note worth no more than the fee leaves nothing once the fee is paid, and a
transaction pays one fee for one note or two. Spend such a note as one of two
`--input` notes summing to more than the fee, or beside a `--deposit` of at
least the fee plus the pool's smallest deposit. `spp transfer` and
`spp withdraw` never deposit, so they spend it only beside a second note.

Amounts are in whole tokens, with up to as many decimal places as the pool's token defines, so `4.5` is 4.5 tokens.

List your unspent notes to get their commitments:

```sh
spp notes --account alice CPOOL --unspent
```

## Private transfer with change

This spends one 10-token note, sends 4 tokens to a registered Stellar address,
returns 5.9 tokens to you, and pays the 0.1 fee:

```sh
spp transact --account alice CPOOL \
  --input 0xINPUT_COMMITMENT \
  --output 4@GRECIPIENT \
  --output 5.9
```

An output has one of these forms:

```text
AMOUNT                              to yourself
AMOUNT@G...                         to a registered Stellar address
AMOUNT@NOTE_KEY:ENCRYPTION_KEY      to explicit recipient keys
```

An output of `0` cannot name a recipient.

## Deposit

A deposit can create one or two private outputs. This one sends 10 tokens
from your account, puts 9.9 in notes, and pays the 0.1 fee:

```sh
spp transact --account alice CPOOL \
  --deposit 10 \
  --output 4@GRECIPIENT \
  --output 5.9
```

## Withdrawal

This spends one 10-token note, withdraws 4 tokens publicly, keeps 5.9 as a
private note, and pays the 0.1 fee:

```sh
spp transact --account alice CPOOL \
  --input 0xINPUT_COMMITMENT \
  --output 5.9 \
  --withdraw 4 \
  --withdraw-to GDESTINATION
```

`--withdraw-to` defaults to the address of `--account`, not the `--sign-as`
payer.

`--deposit` and `--withdraw` cannot be used together.

## Requirements

- Each `--input` must be an unspent note owned by `--account` in this pool.
- A deposit must put at least the pool's smallest deposit in notes after the
  pool fee.
- A deposit must send at most the pool's maximum deposit, pool fee included.
- A Stellar-address recipient must have registered their keys. If the registry
  is unavailable or the recipient hasn't registered, use the explicit-key form.
