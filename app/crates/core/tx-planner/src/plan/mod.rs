//! Transaction planning types and [`plan`] entry point.

mod combination;
mod error;

pub use combination::{CombinationResult, TRANSACTION_LIMIT, find_combination};
pub use error::PlanError;

use types::{Field, NoteAmount};

/// Full plan: one or more on-chain `transact` calls (2-in / 2-out each).
#[derive(Clone, Debug)]
pub struct TransactionPlan {
    steps: Vec<PlannedStep>,
}

/// One on-chain `transact` (at most 2 real inputs after padding).
#[derive(Clone, Debug)]
pub struct PlannedStep {
    pub inputs: (StepNote, Option<StepNote>),
    pub action: StepAction,
}

#[derive(Clone, Debug)]
pub enum StepAction {
    /// Merge two notes into one.
    Consolidate { output: NoteAmount },
    /// Final plan spend step.
    Final {
        outputs: (NoteAmount, Option<NoteAmount>),
    },
}

/// One row in the wallet index (planner input only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendableNote {
    /// Stable id (matches DB / UI note id).
    pub commitment: Field,
    pub amount: NoteAmount,
}

/// One row in the wallet index (planner step input only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepNote {
    /// Stable id (matches DB / UI note id).
    ///
    /// If `None` then the note does not exist at the time of planning.
    pub commitment: Option<Field>,
    pub amount: NoteAmount,
}

impl TransactionPlan {
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    fn assemble(steps: Vec<PlannedStep>) -> Option<Self> {
        match steps.last() {
            Some(PlannedStep {
                action: StepAction::Final { .. },
                ..
            }) => Some(Self { steps }),
            _ => None,
        }
    }

    /// Last step in the plan.
    pub fn final_step(&self) -> &PlannedStep {
        self.steps
            .last()
            .expect("transaction plan always has at least one step")
    }
}

impl IntoIterator for TransactionPlan {
    type IntoIter = std::vec::IntoIter<PlannedStep>;
    type Item = PlannedStep;

    fn into_iter(self) -> Self::IntoIter {
        self.steps.into_iter()
    }
}

impl<'a> IntoIterator for &'a TransactionPlan {
    type IntoIter = std::slice::Iter<'a, PlannedStep>;
    type Item = &'a PlannedStep;

    fn into_iter(self) -> Self::IntoIter {
        self.steps.iter()
    }
}

/// Build a plan from unspent notes and a target spend amount.
pub fn plan(
    amount: NoteAmount,
    notes: &[SpendableNote],
) -> std::result::Result<TransactionPlan, PlanError> {
    if notes.is_empty() {
        return Err(PlanError::NoSpendableNotes);
    }

    let values: Vec<NoteAmount> = notes.iter().map(|n| n.amount).collect();
    let combo = find_combination(&values, amount)?;

    let (indices, change) = match combo {
        CombinationResult::Impossible => return Err(PlanError::NoCombination),
        CombinationResult::OneExact(i) => (vec![i], None),
        CombinationResult::TwoExact(i, j) => (vec![i, j], None),
        CombinationResult::OneOvershoot(i, excess) => (vec![i], Some(excess)),
        CombinationResult::TwoOvershoot(i, j, excess) => (vec![i, j], Some(excess)),
        CombinationResult::ExactK(indices) => (indices, None),
        CombinationResult::Overshoot(indices, excess) => (indices, Some(excess)),
    };

    if indices.len() > TRANSACTION_LIMIT {
        return Err(PlanError::TooManyNotes {
            selected: indices.len(),
            max_notes: TRANSACTION_LIMIT,
        });
    }

    for &index in &indices {
        if index >= notes.len() {
            return Err(PlanError::NoteIndexOutOfRange { index });
        }
    }

    let n_steps = indices.len().saturating_sub(1).max(1);
    let mut steps = Vec::with_capacity(n_steps);
    let note0 = StepNote::from_spendable(notes[indices[0]].clone());
    if indices.len() == 1 {
        // single note
        let action = StepAction::Final {
            outputs: (amount, change),
        };
        let step = PlannedStep {
            inputs: (note0, None),
            action,
        };
        steps.push(step);
    } else {
        // multiple notes
        let mut sum = note0.amount;
        let mut prev_note = note0;
        for index in indices.iter().skip(1) {
            let current_note = StepNote::from_spendable(notes[*index].clone());
            let Some(next_sum) = sum.checked_add(current_note.amount) else {
                return Err(PlanError::InputAmountOverflow);
            };
            sum = next_sum;
            let action = StepAction::Consolidate { output: sum };
            let step = PlannedStep {
                inputs: (prev_note, Some(current_note)),
                action,
            };
            steps.push(step);
            prev_note = StepNote::from_amount(sum);
        }

        // last step is final
        if let Some(last_step) = steps.last_mut() {
            last_step.action = StepAction::Final {
                outputs: (amount, change),
            };
        }
    }

    TransactionPlan::assemble(steps).ok_or(PlanError::InvalidPlan)
}

impl StepNote {
    fn from_spendable(note: SpendableNote) -> Self {
        StepNote {
            commitment: Some(note.commitment),
            amount: note.amount,
        }
    }

    fn from_amount(amount: NoteAmount) -> Self {
        StepNote {
            commitment: None,
            amount,
        }
    }
}

impl PlannedStep {
    /// Resolve this step's inputs against the current wallet notes.
    ///
    /// Inputs with a known commitment are matched by commitment and amount.
    /// Inputs without a commitment (merge intermediates) are matched by amount,
    /// excluding the sibling input's commitment when present. Exactly one match
    /// is required.
    pub fn resolve(&self, notes: &[SpendableNote]) -> Result<Vec<SpendableNote>, PlanError> {
        let mut out = Vec::with_capacity(2);
        out.push(resolve_input_note(
            &self.inputs.0,
            notes,
            self.inputs.1.as_ref(),
        )?);
        if let Some(second) = &self.inputs.1 {
            out.push(resolve_input_note(second, notes, Some(&self.inputs.0))?);
        }
        Ok(out)
    }
}

fn resolve_input_note(
    input: &StepNote,
    notes: &[SpendableNote],
    sibling: Option<&StepNote>,
) -> Result<SpendableNote, PlanError> {
    match input.commitment {
        Some(commitment) => notes
            .iter()
            .find(|note| note.commitment == commitment)
            .cloned()
            .ok_or(PlanError::CommitmentNotFound { commitment })
            .and_then(|note| {
                if note.amount != input.amount {
                    Err(PlanError::NoteAmountMismatch {
                        commitment,
                        actual: note.amount,
                        expected: input.amount,
                    })
                } else {
                    Ok(note)
                }
            }),
        None => {
            let excluded = sibling.and_then(|note| note.commitment);
            let matches: Vec<&SpendableNote> = notes
                .iter()
                .filter(|note| note.amount == input.amount)
                .filter(|note| excluded != Some(note.commitment))
                .collect();
            match matches.len() {
                0 => Err(PlanError::NoNoteForAmount {
                    amount: input.amount,
                }),
                1 => Ok(matches[0].clone()),
                _ => Err(PlanError::AmbiguousNoteForAmount {
                    amount: input.amount,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::Field;

    static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

    fn note(amount: u128) -> SpendableNote {
        let salt = NOTE_SALT.fetch_add(1, Ordering::Relaxed);
        let commitment_value = amount
            .checked_add(1_000)
            .and_then(|base| base.checked_add(salt as u128))
            .expect("test note commitment value overflow");
        SpendableNote {
            commitment: Field::from(NoteAmount::from(commitment_value)),
            amount: NoteAmount::from(amount),
        }
    }

    fn goal_amount(amount: u128) -> NoteAmount {
        NoteAmount::from(amount)
    }

    fn step_at(plan: &TransactionPlan, index: usize) -> &PlannedStep {
        plan.into_iter()
            .nth(index)
            .unwrap_or_else(|| panic!("step index {index} out of range"))
    }

    fn assert_step_count(plan: &TransactionPlan, expected: usize) {
        assert_eq!(plan.len(), expected, "unexpected step count: {plan:?}");
    }

    fn assert_final_outputs(step: &PlannedStep, send: u128, change: Option<u128>) {
        match &step.action {
            StepAction::Final { outputs } => {
                assert_eq!(outputs.0, NoteAmount::from(send));
                assert_eq!(outputs.1, change.map(NoteAmount::from));
            }
            other => panic!("expected final, got {other:?}"),
        }
    }

    fn assert_consolidate_output(step: &PlannedStep, output: u128) {
        match &step.action {
            StepAction::Consolidate { output: out } => {
                assert_eq!(*out, NoteAmount::from(output));
            }
            other => panic!("expected consolidate, got {other:?}"),
        }
    }

    /// Sum of all spendable note amounts passed into [`plan`].
    fn balance(notes: &[SpendableNote]) -> NoteAmount {
        notes
            .iter()
            .map(|n| n.amount)
            .fold(NoteAmount::ZERO, |sum, amount| {
                sum.checked_add(amount)
                    .expect("note amounts must not overflow in tests")
            })
    }

    fn final_action(plan: &TransactionPlan) -> &StepAction {
        match &plan.final_step().action {
            action @ StepAction::Final { .. } => action,
            other => panic!("expected last plan step to be final, got {other:?}"),
        }
    }

    fn send_amount(action: &StepAction) -> NoteAmount {
        let StepAction::Final { outputs } = action else {
            panic!("expected final step action");
        };
        outputs.0
    }

    fn change_amount(action: &StepAction) -> NoteAmount {
        let StepAction::Final { outputs } = action else {
            panic!("expected final step action");
        };
        outputs.1.unwrap_or(NoteAmount::ZERO)
    }

    /// Sum of wallet notes the plan spends (each real commitment counted once).
    fn consumed_balance(plan: &TransactionPlan) -> NoteAmount {
        let mut seen: Vec<&Field> = Vec::new();
        let mut total = NoteAmount::ZERO;
        for step in plan {
            for input in [Some(&step.inputs.0), step.inputs.1.as_ref()] {
                let Some(input) = input else { continue };
                let Some(commitment) = &input.commitment else {
                    continue;
                };
                if seen.contains(&commitment) {
                    continue;
                }
                seen.push(commitment);
                total = total
                    .checked_add(input.amount)
                    .expect("note amounts must not overflow in tests");
            }
        }
        total
    }

    /// Unspent wallet notes plus change from the final step.
    fn remaining_balance(
        wallet: NoteAmount,
        plan: &TransactionPlan,
        action: &StepAction,
    ) -> NoteAmount {
        let consumed = consumed_balance(plan);
        let unspent = wallet
            .checked_sub(consumed)
            .expect("consumed must not exceed wallet in tests");
        unspent
            .checked_add(change_amount(action))
            .expect("note amounts must not overflow in tests")
    }

    /// `initial - send` must equal unspent notes plus final change.
    fn assert_balance(wallet: NoteAmount, plan: &TransactionPlan) {
        let action = final_action(plan);
        let send = send_amount(action);
        let remaining = remaining_balance(wallet, plan, action);
        assert_eq!(
            wallet
                .checked_sub(send)
                .expect("wallet must cover send in tests"),
            remaining,
            "initial balance minus send must equal unspent notes plus change"
        );
        let consumed = consumed_balance(plan);
        assert_eq!(
            consumed,
            send.checked_add(change_amount(action))
                .expect("note amounts must not overflow in tests"),
            "consumed notes must equal send plus change"
        );
    }

    #[test]
    fn plan_no_spendable_notes() {
        let err = plan(goal_amount(10), &[]).expect_err("empty notes should not plan");
        assert!(matches!(err, PlanError::NoSpendableNotes));
    }

    #[test]
    fn plan_no_combination() {
        let notes = vec![note(1), note(2), note(3)];
        let err =
            plan(goal_amount(100), &notes).expect_err("goal above wallet sum should not plan");
        assert!(matches!(err, PlanError::NoCombination));
    }

    #[test]
    fn plan_step_count_scales_with_note_count() {
        let notes_1 = vec![note(10)];
        assert_step_count(
            &plan(goal_amount(10), &notes_1).expect("plan should succeed"),
            1,
        );

        let notes_2 = vec![note(4), note(6), note(20)];
        assert_step_count(
            &plan(goal_amount(10), &notes_2).expect("plan should succeed"),
            1,
        );

        let notes_3 = vec![note(2), note(3), note(5)];
        assert_step_count(
            &plan(goal_amount(10), &notes_3).expect("plan should succeed"),
            2,
        );
    }

    #[test]
    fn plan_consolidate_final() {
        let plan =
            plan(goal_amount(10), &[note(2), note(3), note(5)]).expect("plan should succeed");
        assert_step_count(&plan, 2);
        assert!(matches!(
            step_at(&plan, 0).action,
            StepAction::Consolidate { .. }
        ));
        assert!(matches!(step_at(&plan, 1).action, StepAction::Final { .. }));
    }

    #[test]
    fn plan_consolidate_consolidate_final() {
        let plan = plan(goal_amount(10), &[note(1), note(3), note(1), note(5)])
            .expect("plan should succeed");
        assert_step_count(&plan, 3);
        assert!(matches!(
            step_at(&plan, 0).action,
            StepAction::Consolidate { .. }
        ));
        assert!(matches!(
            step_at(&plan, 1).action,
            StepAction::Consolidate { .. }
        ));
        assert!(matches!(step_at(&plan, 2).action, StepAction::Final { .. }));
    }

    #[test]
    fn plan_two_exact_0() {
        let send = 10;
        let notes = vec![note(4), note(6), note(10)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 1);
        assert_final_outputs(plan.final_step(), send, None);
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_two_exact_1() {
        let send = 10;
        let notes = vec![note(4), note(6), note(20)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 1);
        assert_final_outputs(plan.final_step(), send, None);
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_two_overshoot() {
        let send = 10;
        let notes = vec![note(1), note(2), note(5), note(6)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 1);
        assert_final_outputs(plan.final_step(), send, Some(1));
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_one_overshoot() {
        let send = 10;
        let notes = vec![note(15)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 1);
        assert!(step_at(&plan, 0).inputs.1.is_none());
        assert_final_outputs(plan.final_step(), send, Some(5));
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_one_exact() {
        let send = 10;
        let notes = vec![note(3), note(6), note(10)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_eq!(step_at(&plan, 0).inputs.0.amount, NoteAmount::from(10));
        assert!(step_at(&plan, 0).inputs.1.is_none());
        assert_final_outputs(plan.final_step(), send, None);
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_k_3_exact_0() {
        let send = 10;
        let notes = vec![note(2), note(3), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 2);
        assert_balance(balance(&notes), &plan);
        assert_consolidate_output(step_at(&plan, 0), 8);
        assert_final_outputs(plan.final_step(), send, None);
    }

    #[test]
    fn plan_k_3_overshoot_0() {
        let send = 10;
        let notes = vec![note(2), note(3), note(6)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 2);
        assert_consolidate_output(step_at(&plan, 0), 9);
        assert_final_outputs(plan.final_step(), send, Some(1));
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_k_3_exact_1() {
        let send = 10;
        let notes = vec![note(1), note(2), note(3), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 2);
        assert_balance(balance(&notes), &plan);
        assert_final_outputs(plan.final_step(), send, None);
    }

    #[test]
    fn plan_k_3_overshoot_1() {
        let send = 10;
        let notes = vec![note(2), note(2), note(4), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 2);
        assert_final_outputs(plan.final_step(), send, Some(1));
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_k_4_exact_0() {
        let send = 10;
        let notes = vec![note(1), note(1), note(3), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 3);
        assert_balance(balance(&notes), &plan);
        assert_final_outputs(plan.final_step(), send, None);
    }

    #[test]
    fn plan_k_4_overshoot_0() {
        let send = 10;
        let notes = vec![note(2), note(2), note(2), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 3);
        assert_final_outputs(plan.final_step(), send, Some(1));
        assert_balance(balance(&notes), &plan);
    }

    #[test]
    fn plan_k_4_exact_1() {
        let send = 10;
        let notes = vec![note(1), note(1), note(1), note(3), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 3);
        assert_balance(balance(&notes), &plan);
        assert_final_outputs(plan.final_step(), send, None);
    }

    #[test]
    fn plan_k_4_overshoot_1() {
        let send = 10;
        let notes = vec![note(2), note(2), note(2), note(2), note(5)];
        let plan = plan(goal_amount(send), &notes).expect("plan should succeed");
        assert_step_count(&plan, 3);
        assert_final_outputs(plan.final_step(), send, Some(1));
        assert_balance(balance(&notes), &plan);
    }

    fn committed_note(amount: u128, commitment: u128) -> SpendableNote {
        SpendableNote {
            commitment: Field::from(NoteAmount::from(commitment)),
            amount: NoteAmount::from(amount),
        }
    }

    #[test]
    fn resolve_final() {
        let wallet = vec![committed_note(7, 101)];
        let tx_plan = plan(NoteAmount::from(7), &wallet).expect("plan should succeed");
        let step = tx_plan.into_iter().next().expect("one step");
        let inputs = step.resolve(&wallet).expect("resolve should succeed");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].commitment, Field::from(NoteAmount::from(101)));
    }

    #[test]
    fn resolve_consolidate_final() {
        let spend = 10;
        let wallet = vec![
            committed_note(2, 101),
            committed_note(3, 102),
            committed_note(5, 103),
        ];
        let tx_plan = plan(goal_amount(spend), &wallet).expect("plan should succeed");
        assert_step_count(&tx_plan, 2);

        let mut steps = tx_plan.into_iter();

        // consolidate step
        let step0 = steps.next().expect("step 0");
        let inputs0 = step0.resolve(&wallet).expect("resolve step 0");

        let StepAction::Consolidate {
            output: merge_amount,
        } = step0.action
        else {
            panic!("expected first step to consolidate");
        };
        let merged = SpendableNote {
            commitment: Field::from(NoteAmount::from(900)),
            amount: merge_amount,
        };
        let merged_commitment = merged.commitment;

        // update wallet
        let mut wallet = wallet
            .iter()
            .filter(|note| {
                note.commitment != inputs0[0].commitment && note.commitment != inputs0[1].commitment
            })
            .cloned()
            .collect::<Vec<_>>();
        wallet.push(merged);
        assert_eq!(
            wallet.len(),
            2,
            "wallet expected to have two after consolidation step"
        );

        // final step
        let step1 = steps.next().expect("step 1");
        let inputs1 = step1.resolve(&wallet).expect("resolve step 1");
        assert!(
            inputs1
                .iter()
                .any(|input| input.commitment == merged_commitment),
            "expected new committed note to be input for final step"
        );
        let StepAction::Final { outputs } = step1.action else {
            panic!("expected last step to be final");
        };
        assert_eq!(outputs.0, spend.into(), "final output is spend amount");
        assert!(outputs.1.is_none(), "no change");
    }
}
