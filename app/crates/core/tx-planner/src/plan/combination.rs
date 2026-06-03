//! Coin selection: pick note indices that reach a target amount.

use super::PlanError;
use types::NoteAmount;

/// Upper bound on combination size explored by [`find_combination`].
pub const TRANSACTION_LIMIT: usize = 10;

#[derive(Debug, PartialEq)]
pub enum CombinationResult {
    /// Tier 1: Exactly two elements that sum exactly to the goal
    TwoExact(usize, usize),
    /// Tier 1.5: A single element that matches the goal exactly
    OneExact(usize),
    /// Tier 2: Exactly two elements that overshoot the goal
    TwoOvershoot(usize, usize, NoteAmount),
    /// Tier 2.5: A single element that overshoots the goal
    OneOvershoot(usize, NoteAmount),
    /// Tier 3: Three or more elements (k >= 3) that sum exactly to the goal
    ExactK(Vec<usize>),
    /// Tier 4: Multiple elements that overshoot the goal (greedy fallback)
    Overshoot(Vec<usize>, NoteAmount),
    /// No combination possible (total sum of all elements < goal)
    Impossible,
}

/// Find a combination of elements with sum equal to or larger than the goal,
/// prioritizing the lowest combination count (with two-note pairs preferred
/// over single-note exact matches).
pub fn find_combination(
    values: &[NoteAmount],
    goal: NoteAmount,
) -> Result<CombinationResult, PlanError> {
    if values.is_empty() {
        return Ok(CombinationResult::Impossible);
    }

    let mut sorted_vals: Vec<(usize, NoteAmount)> = values.iter().copied().enumerate().collect();
    sorted_vals.sort_unstable_by_key(|&(_, x)| x);

    let two = TwoScan::scan(&sorted_vals, goal)?;
    if let TwoScan::Exact(a, b) = two {
        return Ok(CombinationResult::TwoExact(a, b));
    }

    let one = OneScan::scan(&sorted_vals, goal)?;
    if let OneScan::Exact(i) = one {
        return Ok(CombinationResult::OneExact(i));
    }

    if let TwoScan::Overshoot(a, b, excess) = two {
        return Ok(CombinationResult::TwoOvershoot(a, b, excess));
    }

    if let OneScan::Overshoot(i, excess) = one {
        return Ok(CombinationResult::OneOvershoot(i, excess));
    }

    match KScan::scan(&sorted_vals, goal)? {
        KScan::Exact(indices) => Ok(CombinationResult::ExactK(indices)),
        KScan::Overshoot(indices, excess) => Ok(CombinationResult::Overshoot(indices, excess)),
        KScan::Miss => Ok(CombinationResult::Impossible),
    }
}

enum TwoScan {
    Exact(usize, usize),
    Overshoot(usize, usize, NoteAmount),
    Miss,
}

impl TwoScan {
    /// Two-pointer scan over ascending `(index, amount)` pairs.
    fn scan(sorted: &[(usize, NoteAmount)], goal: NoteAmount) -> Result<Self, PlanError> {
        Ok(Self::scan_impl(sorted, goal)?.unwrap_or(Self::Miss))
    }

    fn scan_impl(
        sorted: &[(usize, NoteAmount)],
        goal: NoteAmount,
    ) -> Result<Option<Self>, PlanError> {
        if sorted.len() < 2 {
            return Ok(None);
        }

        let mut best_overshoot: Option<(usize, usize, NoteAmount)> = None;
        let mut left = 0;
        let mut right = sorted
            .len()
            .checked_sub(1)
            .ok_or(PlanError::InputAmountOverflow)?;
        while left < right {
            let sum = sorted[left]
                .1
                .checked_add(sorted[right].1)
                .ok_or(PlanError::InputAmountOverflow)?;
            let Some(diff) = sum.checked_sub(goal) else {
                left = left.checked_add(1).ok_or(PlanError::InputAmountOverflow)?;
                continue;
            };
            if diff.is_zero() {
                return Ok(Some(Self::Exact(sorted[left].0, sorted[right].0)));
            }
            if diff > NoteAmount::ZERO {
                if best_overshoot.is_none_or(|(_, _, excess)| diff < excess) {
                    best_overshoot = Some((sorted[left].0, sorted[right].0, diff));
                }
                right = right.checked_sub(1).ok_or(PlanError::InputAmountOverflow)?;
            }
        }

        Ok(best_overshoot.map(|(a, b, excess)| Self::Overshoot(a, b, excess)))
    }
}

enum OneScan {
    Exact(usize),
    Overshoot(usize, NoteAmount),
    Miss,
}

impl OneScan {
    /// Linear scan over ascending `(index, amount)` values.
    fn scan(sorted: &[(usize, NoteAmount)], goal: NoteAmount) -> Result<Self, PlanError> {
        let mut exact = None;
        let mut overshoot = None;

        for &(idx, x) in sorted {
            let Some(diff) = x.checked_sub(goal) else {
                continue;
            };
            if diff.is_zero() {
                exact = Some(idx);
            } else if diff > NoteAmount::ZERO {
                overshoot = Some((idx, diff));
                break;
            }
        }

        Ok(match (exact, overshoot) {
            (Some(i), _) => Self::Exact(i),
            (None, Some((i, excess))) => Self::Overshoot(i, excess),
            (None, None) => Self::Miss,
        })
    }
}

enum KScan {
    Exact(Vec<usize>),
    Overshoot(Vec<usize>, NoteAmount),
    Miss,
}

impl KScan {
    /// k≥3 DFS on notes `< goal`, then greedy overshoot (largest notes first).
    fn scan(sorted: &[(usize, NoteAmount)], goal: NoteAmount) -> Result<Self, PlanError> {
        Ok(Self::scan_impl(sorted, goal)?.unwrap_or(Self::Miss))
    }

    fn scan_impl(
        sorted: &[(usize, NoteAmount)],
        goal: NoteAmount,
    ) -> Result<Option<Self>, PlanError> {
        let mut candidates_desc: Vec<(usize, NoteAmount)> =
            sorted.iter().copied().filter(|&(_, x)| x < goal).collect();
        candidates_desc.reverse();

        if candidates_desc.len() >= 3 {
            let max_k = std::cmp::min(candidates_desc.len(), TRANSACTION_LIMIT);
            for k in 3..=max_k {
                let mut iteration_limit = 5000;
                let mut path = Vec::new();
                let mut best_overshoot = None;

                let mut ctx = DfsContext {
                    candidates: &candidates_desc,
                    goal,
                    target_k: k,
                    iteration_limit: &mut iteration_limit,
                    path: &mut path,
                    best_overshoot: &mut best_overshoot,
                };
                if Self::dfs(NoteAmount::ZERO, 0, &mut ctx)? {
                    return Ok(Some(Self::Exact(path)));
                }

                if let Some((excess, overshoot_path)) = best_overshoot {
                    return Ok(Some(Self::Overshoot(overshoot_path, excess)));
                }
            }
        }

        Self::greedy_impl(sorted, goal)
    }

    /// Greedily add largest notes until the sum reaches the goal.
    fn greedy_impl(
        sorted: &[(usize, NoteAmount)],
        goal: NoteAmount,
    ) -> Result<Option<Self>, PlanError> {
        let mut total = NoteAmount::ZERO;
        let mut picks: Vec<usize> = Vec::new();
        for &(idx, x) in sorted.iter().rev() {
            total = total.checked_add(x).ok_or(PlanError::InputAmountOverflow)?;
            picks.push(idx);
            if total >= goal {
                let excess = total
                    .checked_sub(goal)
                    .ok_or(PlanError::InputAmountOverflow)?;
                return Ok(Some(Self::Overshoot(picks, excess)));
            }
        }
        Ok(None)
    }

    fn dfs(sum: NoteAmount, index: usize, ctx: &mut DfsContext<'_>) -> Result<bool, PlanError> {
        if ctx.path.len() == ctx.target_k {
            let Some(diff) = sum.checked_sub(ctx.goal) else {
                return Ok(false);
            };
            if diff.is_zero() {
                return Ok(true);
            }
            if diff > NoteAmount::ZERO
                && ctx
                    .best_overshoot
                    .as_ref()
                    .is_none_or(|(min_ov, _)| diff < *min_ov)
            {
                *ctx.best_overshoot = Some((diff, ctx.path.clone()));
            }
            return Ok(false);
        }

        if sum >= ctx.goal || index >= ctx.candidates.len() || *ctx.iteration_limit <= 0 {
            return Ok(false);
        }

        *ctx.iteration_limit = ctx
            .iteration_limit
            .checked_sub(1)
            .ok_or(PlanError::InputAmountOverflow)?;

        let next_index = index.checked_add(1).ok_or(PlanError::InputAmountOverflow)?;
        let note_index = ctx.candidates[index].0;
        let note_amount = ctx.candidates[index].1;

        ctx.path.push(note_index);
        if let Some(with_note) = sum.checked_add(note_amount)
            && Self::dfs(with_note, next_index, ctx)?
        {
            return Ok(true);
        }
        ctx.path.pop();

        Self::dfs(sum, next_index, ctx)
    }
}

struct DfsContext<'a> {
    candidates: &'a [(usize, NoteAmount)],
    goal: NoteAmount,
    target_k: usize,
    iteration_limit: &'a mut i32,
    path: &'a mut Vec<usize>,
    best_overshoot: &'a mut Option<(NoteAmount, Vec<usize>)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amounts(values: &[u128]) -> Vec<NoteAmount> {
        values.iter().copied().map(NoteAmount::from).collect()
    }

    fn goal(amount: u128) -> NoteAmount {
        NoteAmount::from(amount)
    }

    fn find(values: &[NoteAmount], goal: NoteAmount) -> CombinationResult {
        find_combination(values, goal).expect("combination should succeed")
    }

    #[test]
    fn comb_two_exact() {
        let dataset = amounts(&[4, 6, 10]);
        assert_eq!(find(&dataset, goal(10)), CombinationResult::TwoExact(0, 1));
    }

    #[test]
    fn comb_one_exact() {
        let dataset = amounts(&[3, 6, 10]);
        assert_eq!(find(&dataset, goal(10)), CombinationResult::OneExact(2));
    }

    #[test]
    fn comb_two_overshoot() {
        let dataset = amounts(&[1, 2, 5, 6, 12]);
        assert_eq!(
            find(&dataset, goal(10)),
            CombinationResult::TwoOvershoot(2, 3, goal(1))
        );
    }

    #[test]
    fn comb_one_overshoot() {
        let dataset = amounts(&[15]);
        assert_eq!(
            find(&dataset, goal(10)),
            CombinationResult::OneOvershoot(0, goal(5))
        );
    }

    #[test]
    fn comb_k_exact() {
        let dataset = amounts(&[2, 3, 5]);
        assert_eq!(
            find(&dataset, goal(10)),
            CombinationResult::ExactK(vec![2, 1, 0])
        );
    }

    #[test]
    fn comb_k_overshoot() {
        let dataset = amounts(&[2, 3, 6]);
        assert_eq!(
            find(&dataset, goal(10)),
            CombinationResult::Overshoot(vec![2, 1, 0], goal(1))
        );
    }

    #[test]
    fn comb_two_exact_before_one_exact() {
        let dataset = amounts(&[4, 6, 10]);
        assert_eq!(find(&dataset, goal(10)), CombinationResult::TwoExact(0, 1));
    }
}
