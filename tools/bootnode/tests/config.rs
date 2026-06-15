use bootnode::config;

#[test]
fn five_day_default_cutoff() {
    // 5 days at 5s/ledger
    assert_eq!(config::cutoff_ledgers(5, 5), 86_400);
}

#[test]
fn zero_ledger_seconds_falls_back_to_one() {
    assert_eq!(config::cutoff_ledgers(1, 0), 86_400);
}

#[test]
fn custom_window() {
    assert_eq!(config::cutoff_ledgers(2, 10), 17_280);
}
