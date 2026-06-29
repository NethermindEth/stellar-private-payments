//! Human-readable token amounts (7 decimal places, Stellar stroops).

use wasm_bindgen::JsError;

const STROOPS_PER_UNIT: u128 = 10_000_000;

/// Parse a decimal token amount string into stroops (e.g. `"10.5"` →
/// `105_000_000`).
pub fn parse_token_amount(amount: &str) -> Result<u128, JsError> {
    let s = amount.trim();
    if s.is_empty() {
        return Err(JsError::new("amount must not be empty"));
    }
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(JsError::new(&format!("invalid amount: {amount}")));
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(JsError::new("invalid amount"));
    }
    let whole_val: u128 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| JsError::new(&format!("invalid amount: {amount}")))?
    };
    let mut frac_padded = frac.to_string();
    if frac_padded.len() > 7 {
        return Err(JsError::new("amount has more than 7 decimal places"));
    }
    frac_padded.push_str(&"0000000"[frac_padded.len()..]);
    let frac_val: u128 = frac_padded
        .parse()
        .map_err(|_| JsError::new(&format!("invalid amount: {amount}")))?;
    whole_val
        .checked_mul(STROOPS_PER_UNIT)
        .and_then(|w| w.checked_add(frac_val))
        .ok_or_else(|| JsError::new("amount overflow"))
}

/// Format stroops as a decimal string (trailing zeros trimmed).
pub fn format_token_amount(stroops: u128) -> String {
    let whole = stroops / STROOPS_PER_UNIT;
    let frac = stroops % STROOPS_PER_UNIT;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:07}");
    let trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_roundtrip() {
        assert_eq!(parse_token_amount("10").expect("valid amount"), 100_000_000);
        assert_eq!(
            parse_token_amount("10.5").expect("valid amount"),
            105_000_000
        );
        assert_eq!(format_token_amount(105_000_000), "10.5");
    }
}
