# Transaction planner

Builds a **transaction plan** for private pool spends: which wallet notes to use, how many on-chain `transact` calls to make, and what each step does.

This lives in `stellar_private_payments::planner` (formerly the `tx-planner` crate).

Each on-chain transaction is a **2-in / 2-out** `transact` (at most two real inputs, two outputs). The planner only emits steps that fit that shape.

## What it optimizes for

The goal is to pay a target `NoteAmount` while keeping wallet and chain cost low:

1. **Fewer on-chain transactions** — each `PlannedStep` is one `transact`. Spending `k` notes usually needs `k - 1` steps (merge pairs, then a final spend). One note that already covers the amount needs a single step.

2. **Fewer notes touched** — spending fewer inputs means fewer commitments consumed and usually less consolidation. Exact matches avoid unnecessary change notes in the pool.

3. **Exact before overshoot** — when the target cannot be matched exactly, prefer the smallest excess (change returned on the final step).

## Pool fee

Every `transact` pays the pool fee out of the notes it spends. A spend of `k` notes takes `max(k - 1, 1)` steps, so its notes must sum to at least `amount + steps × fee`. That sum is the goal the tiers below compare against: `amount + fee` for one or two notes, and `amount + (k - 1) × fee` for an exact `k`. Each `Consolidate` output is its two inputs minus the fee, and the final change is whatever the notes hold above the goal.

A note at or below the fee costs at least what it brings when it adds a step, so it leaves only beside a larger note. [`max_spend`](plan/mod.rs) returns the most one spend can send from a wallet.

## Coin selection priority

[`find_combination`](plan/combination.rs) picks note indices from the wallet. It tries tiers in this order and stops at the first hit:

| Order | Result | Meaning |
|------:|--------|---------|
| 1 | Two exact | Two notes sum to the goal |
| 2 | One exact | A single note equals the goal |
| 3 | Two overshoot | Two notes cover the goal; excess becomes change |
| 4 | One overshoot | One note covers the goal; excess becomes change |
| 5 | Exact k (k ≥ 3) | Smallest k notes that sum exactly to the goal |
| 6 | Overshoot (greedy) | Fallback when no exact k-subset exists |

Two-note pairs are tried before a single-note exact match so common “pay from two inputs” cases use one `transact` instead of leaving an extra note idle.

At most [`TRANSACTION_LIMIT`](plan/combination.rs) notes (10) may be selected; [`plan`](plan/mod.rs) rejects larger sets.

## Plan shape

[`plan(amount, fee, notes)`](plan/mod.rs) runs coin selection, then builds a [`TransactionPlan`](plan/mod.rs):

- **One note** — one step, `Final` (send + optional change).
- **Several notes** — `Consolidate` steps merge two inputs into one synthetic note, then the last step is `Final` (send + optional change).

[`SpendSession`](execute/mod.rs) freezes the plan and wallet snapshot at `setup`. The caller loops: `step()` → prove/submit → `complete_step(output_commitments)`.

## Public API

- `plan` — wallet notes + spend amount + pool fee → `TransactionPlan` (also used for spend previews)
- `max_spend` — wallet notes + pool fee → the largest amount one spend can send
- `SpendSession::setup` — plan + wallet snapshot + `SpendTarget`
- `SpendSession::step` / `complete_step` — step loop
- `find_combination` — coin selection only
- `TransactionPlan`, `SpendableNote`, `PlannedStep`, `Transact`, `PlanError`, `SpendSessionError`
