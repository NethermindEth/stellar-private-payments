# Advanced transactions

`spp transact` lets you choose exactly which notes to spend and what each
private output is. Use `deposit`, `transfer`, and `withdraw` unless you need
that control.

A transaction takes at most two `--input` notes and at most two `--output`
values, and must balance:

```text
input notes + deposit = private outputs + withdrawal
```

Amounts are in whole tokens with up to 7 decimal places, so `4.5` is 4.5 tokens.

List your unspent notes to get their commitments:

```sh
spp notes --account alice CPOOL --unspent
```

## Private transfer with change

This spends one 10-token note, sends 4 tokens to a registered Stellar address,
and returns 6 tokens to you:

```sh
spp transact --account alice CPOOL \
  --input 0xINPUT_COMMITMENT \
  --output 4@GRECIPIENT \
  --output 6
```

An output has one of these forms:

```text
AMOUNT                              to yourself
AMOUNT@G...                         to a registered Stellar address
AMOUNT@NOTE_KEY:ENCRYPTION_KEY      to explicit recipient keys
```

An output of `0` cannot name a recipient.

## Deposit

A deposit can create one or two private outputs:

```sh
spp transact --account alice CPOOL \
  --deposit 10 \
  --output 4@GRECIPIENT \
  --output 6
```

## Withdrawal

This spends one 10-token note, withdraws 4 tokens publicly, and keeps 6 as a
private note:

```sh
spp transact --account alice CPOOL \
  --input 0xINPUT_COMMITMENT \
  --output 6 \
  --withdraw 4 \
  --withdraw-to GDESTINATION
```

`--withdraw-to` defaults to the address of `--account`, not the `--sign-as`
payer.

`--deposit` and `--withdraw` cannot be used together.

## Requirements

- Each `--input` must be an unspent note owned by `--account` in this pool.
- A Stellar-address recipient must have registered their keys. If the registry
  is unavailable or the recipient hasn't registered, use the explicit-key form.
