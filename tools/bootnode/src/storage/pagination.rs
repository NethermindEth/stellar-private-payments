use crate::messages::{Event, GetEventsResponse};

pub const GENESIS_CURSOR_PREFIX: &str = "bootnode:genesis:";
pub const DEFAULT_PAGE_LIMIT: u32 = 1_000;
pub const MAX_PAGE_LIMIT: u32 = 10_000;

pub fn page_limit(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT)
}

pub fn genesis_cursor(start_ledger: u32) -> String {
    format!("{GENESIS_CURSOR_PREFIX}{start_ledger}")
}

pub fn parse_genesis_cursor(cursor: &str) -> Option<u32> {
    cursor
        .strip_prefix(GENESIS_CURSOR_PREFIX)
        .and_then(|value| value.parse().ok())
}

pub fn build_response(
    events: Vec<Event>,
    start_ledger: Option<u32>,
    request_cursor: Option<&str>,
    ledger_tip: u32,
    oldest_ledger: u32,
) -> GetEventsResponse {
    let cursor = if let Some(last) = events.last() {
        last.id.clone()
    } else if let Some(start_ledger) = start_ledger {
        genesis_cursor(start_ledger)
    } else if let Some(request_cursor) = request_cursor {
        request_cursor.to_owned()
    } else {
        String::new()
    };

    GetEventsResponse {
        events,
        latest_ledger: ledger_tip,
        latest_ledger_close_time: String::new(),
        oldest_ledger,
        oldest_ledger_close_time: String::new(),
        cursor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_cursor_roundtrip() {
        let cursor = genesis_cursor(2_800_000);
        assert_eq!(parse_genesis_cursor(&cursor), Some(2_800_000));
    }

    #[test]
    fn page_limit_defaults_and_caps() {
        assert_eq!(page_limit(None), DEFAULT_PAGE_LIMIT);
        assert_eq!(page_limit(Some(50)), 50);
        assert_eq!(page_limit(Some(999_999)), MAX_PAGE_LIMIT);
    }
}
