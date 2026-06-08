# tx-planner

Builds a **transaction plan** for private pool spends: which wallet notes to use, how many on-chain `transact` calls to make, and what each step does.

Each on-chain transaction is a **2-in / 2-out** `transact` (at most two real inputs, two outputs). The planner only emits steps that fit that shape.

## What it optimizes for

The goal is to pay a target `NoteAmount` while keeping wallet and chain cost low:

1. **Fewer on-chain transactions** — each `PlannedStep` is one `transact`. Spending `k` notes usually needs `k - 1` steps (merge pairs, then a final spend). One note that already covers the amount needs a single step.

2. **Fewer notes touched** — spending fewer inputs means fewer commitments consumed and usually less consolidation. Exact matches avoid unnecessary change notes in the pool.

3. **Exact before overshoot** — when the target cannot be matched exactly, prefer the smallest excess (change returned on the final step).

## Coin selection priority

[`find_combination`](src/plan/combination.rs) picks note indices from the wallet. It tries tiers in this order and stops at the first hit:

| Order | Result | Meaning |
|------:|--------|---------|
| 1 | Two exact | Two notes sum to the goal |
| 2 | One exact | A single note equals the goal |
| 3 | Two overshoot | Two notes cover the goal; excess becomes change |
| 4 | One overshoot | One note covers the goal; excess becomes change |
| 5 | Exact k (k ≥ 3) | Smallest k notes that sum exactly to the goal |
| 6 | Overshoot (greedy) | Fallback when no exact k-subset exists |

Two-note pairs are tried before a single-note exact match so common “pay from two inputs” cases use one `transact` instead of leaving an extra note idle.

At most [`TRANSACTION_LIMIT`](src/plan/combination.rs) notes (10) may be selected; [`plan`](src/plan/mod.rs) rejects larger sets.

## Plan shape

[`plan(amount, notes)`](src/plan/mod.rs) runs coin selection, then builds a [`TransactionPlan`](src/plan/mod.rs):

- **One note** — one step, `Final` (send + optional change).
- **Several notes** — `Consolidate` steps merge two inputs into one synthetic note, then the last step is `Final` (send + optional change).

[`SpendSession`](src/execute/mod.rs) freezes the plan and wallet snapshot at `setup`. The caller loops: `step()` → prove/submit → `complete_step(output_commitments)`.

## Public API

- `plan` — wallet notes + spend amount → `TransactionPlan` (also used for spend previews)
- `SpendSession::setup` — plan + wallet snapshot + `SpendTarget`
- `SpendSession::step` / `complete_step` — step loop
- `find_combination` — coin selection only
- `TransactionPlan`, `SpendableNote`, `PlannedStep`, `Transact`, `PlanError`, `SpendSessionError`
