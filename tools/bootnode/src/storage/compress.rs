use crate::messages::GetEventsResponse;
use std::collections::{HashMap, HashSet};

/// One cached `getEvents` page row used for empty-span compression.
#[derive(Debug, Clone)]
pub struct PageRecord {
    pub id: i64,
    pub cursor_in: Option<String>,
    pub start_ledger: Option<u32>,
    pub cursor_out: String,
    pub last_event_ledger: Option<u32>,
    pub latest_ledger: u32,
    pub result: GetEventsResponse,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompressStats {
    pub spans_joined: u32,
    pub pages_removed: u32,
}

#[derive(Debug, Default)]
pub struct CompressPlan {
    /// Keep row id → new cursor_out, result, latest_ledger.
    pub updates: Vec<(i64, String, GetEventsResponse, u32)>,
    pub deletes: Vec<i64>,
}

impl CompressPlan {
    pub fn stats(&self) -> CompressStats {
        CompressStats {
            spans_joined: u32::try_from(self.updates.len()).unwrap_or(u32::MAX),
            pages_removed: u32::try_from(self.deletes.len()).unwrap_or(u32::MAX),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.updates.is_empty() && self.deletes.is_empty()
    }
}

fn is_empty_page(page: &PageRecord) -> bool {
    page.last_event_ledger.is_none() && page.result.events.is_empty()
}

/// Plan merges of contiguous empty pages that lie **entirely below**
/// `cutoff_ledger` (the retention handoff threshold).
///
/// Clients may still paginate empty cursor chains inside the handoff window, so
/// those pages are left alone. Historical empty runs (every page's
/// `latest_ledger < cutoff_ledger`) collapse into the first page.
pub fn plan_empty_compression(pages: &[PageRecord], cutoff_ledger: u32) -> CompressPlan {
    let by_cursor_in: HashMap<&str, &PageRecord> = pages
        .iter()
        .filter_map(|p| p.cursor_in.as_deref().map(|c| (c, p)))
        .collect();

    let mut plan = CompressPlan::default();
    let mut visited = HashSet::new();

    let roots: Vec<&PageRecord> = pages.iter().filter(|p| p.cursor_in.is_none()).collect();

    for root in roots {
        let mut current = Some(root);
        while let Some(page) = current {
            if !visited.insert(page.id) {
                break;
            }

            if !is_empty_page(page) {
                current = by_cursor_in.get(page.cursor_out.as_str()).copied();
                continue;
            }

            // Collect contiguous empty run starting here.
            let mut run = vec![page];
            let mut next = by_cursor_in.get(page.cursor_out.as_str()).copied();
            while let Some(n) = next {
                if !is_empty_page(n) || visited.contains(&n.id) {
                    break;
                }
                visited.insert(n.id);
                run.push(n);
                next = by_cursor_in.get(n.cursor_out.as_str()).copied();
            }

            let entirely_below_cutoff = run.iter().all(|p| p.latest_ledger < cutoff_ledger);
            if entirely_below_cutoff && run.len() >= 2 {
                let first = run[0];
                let last = run.last().expect("run len >= 2");
                let mut result = last.result.clone();
                result.cursor = last.cursor_out.clone();
                plan.updates.push((
                    first.id,
                    last.cursor_out.clone(),
                    result,
                    last.latest_ledger,
                ));
                for middle in &run[1..] {
                    plan.deletes.push(middle.id);
                }
            }

            current = next;
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_page(
        id: i64,
        cursor_in: Option<&str>,
        start_ledger: Option<u32>,
        cursor_out: &str,
        latest_ledger: u32,
    ) -> PageRecord {
        PageRecord {
            id,
            cursor_in: cursor_in.map(str::to_owned),
            start_ledger,
            cursor_out: cursor_out.to_owned(),
            last_event_ledger: None,
            latest_ledger,
            result: GetEventsResponse {
                cursor: cursor_out.to_owned(),
                events: vec![],
                latest_ledger,
                latest_ledger_close_time: "t".into(),
                oldest_ledger: 1,
                oldest_ledger_close_time: "t".into(),
            },
        }
    }

    fn event_page(
        id: i64,
        cursor_in: Option<&str>,
        start_ledger: Option<u32>,
        cursor_out: &str,
        event_ledger: u32,
        latest_ledger: u32,
    ) -> PageRecord {
        let mut page = empty_page(id, cursor_in, start_ledger, cursor_out, latest_ledger);
        page.last_event_ledger = Some(event_ledger);
        page.result.events = vec![crate::messages::Event {
            event_type: "contract".into(),
            ledger: event_ledger,
            ledger_closed_at: "t".into(),
            contract_id: "C".into(),
            id: "e".into(),
            operation_index: None,
            transaction_index: None,
            tx_hash: None,
            is_successful_contract_call: None,
            topic: vec![],
            value: "00".into(),
        }];
        page
    }

    #[test]
    fn merges_empty_run_entirely_below_cutoff() {
        // cutoff = 600; run ends at 590 → compress.
        let pages = vec![
            empty_page(1, None, Some(100), "c1", 400),
            empty_page(2, Some("c1"), None, "c2", 500),
            empty_page(3, Some("c2"), None, "c3", 590),
        ];
        let plan = plan_empty_compression(&pages, 600);
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].0, 1);
        assert_eq!(plan.updates[0].1, "c3");
        assert_eq!(plan.updates[0].3, 590);
        assert_eq!(plan.deletes, vec![2, 3]);
    }

    #[test]
    fn leaves_run_that_touches_handoff_window() {
        // cutoff = 600; last page at 700 → do not compress.
        let pages = vec![
            empty_page(1, None, Some(100), "c1", 400),
            empty_page(2, Some("c1"), None, "c2", 500),
            empty_page(3, Some("c2"), None, "c3", 600),
            empty_page(4, Some("c3"), None, "c4", 700),
        ];
        let plan = plan_empty_compression(&pages, 600);
        assert!(plan.is_empty());
    }

    #[test]
    fn leaves_run_entirely_in_handoff_window() {
        let pages = vec![
            event_page(1, None, Some(100), "e1", 550, 550),
            empty_page(2, Some("e1"), None, "c1", 650),
            empty_page(3, Some("c1"), None, "c2", 700),
        ];
        let plan = plan_empty_compression(&pages, 600);
        assert!(plan.is_empty());
    }

    #[test]
    fn does_not_merge_singleton_empty() {
        let pages = vec![empty_page(1, None, Some(100), "c1", 400)];
        let plan = plan_empty_compression(&pages, 600);
        assert!(plan.is_empty());
    }

    #[test]
    fn stops_empty_run_at_event_page() {
        let pages = vec![
            empty_page(1, None, Some(100), "c1", 400),
            empty_page(2, Some("c1"), None, "c2", 500),
            event_page(3, Some("c2"), None, "e1", 550, 550),
            empty_page(4, Some("e1"), None, "c3", 580),
            empty_page(5, Some("c3"), None, "c4", 590),
        ];
        let plan = plan_empty_compression(&pages, 600);
        assert_eq!(plan.updates.len(), 2);
        assert_eq!(plan.updates[0].1, "c2");
        assert_eq!(plan.updates[1].1, "c4");
    }
}
