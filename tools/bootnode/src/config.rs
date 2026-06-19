use std::{net::SocketAddr, path::PathBuf};
use url::Url;

#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Domain name used for ACME (TLS-ALPN-01).
    pub domain: String,
    /// ACME account contact email.
    pub acme_email: String,
    /// ACME cache directory (cert/account cache).
    pub acme_cache_dir: PathBuf,
    /// ACME directory URL (LetsEncrypt staging/prod).
    pub acme_directory_url: Option<Url>,
}

#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub otlp_endpoint: Option<String>,
    pub service_name: String,
    pub sample_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub upstream_rpc_url: Url,
    pub dev: bool,
    pub tls: Option<TlsConfig>,
    pub redirect_days: u32,
    pub ledger_seconds: u32,
    pub indexer_sleep_ms: u64,
    pub max_pages_per_round: u32,
    pub page_size: u32,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub otel: Option<OtelConfig>,
    pub initial_ledger_tip: u32,
}

impl Config {
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) fn cutoff_ledgers(&self) -> u32 {
        cutoff_ledgers(self.redirect_days, self.ledger_seconds)
    }
}

/// Redirect-window size in ledgers (tip minus this = redirect threshold).
#[allow(clippy::arithmetic_side_effects)]
pub fn cutoff_ledgers(redirect_days: u32, ledger_seconds: u32) -> u32 {
    let seconds = redirect_days
        .saturating_mul(24)
        .saturating_mul(60)
        .saturating_mul(60);
    let denom = ledger_seconds.max(1);
    seconds.saturating_div(denom)
}

#[cfg(test)]
mod tests {
    use super::cutoff_ledgers;

    #[test]
    fn five_day_default_cutoff() {
        // 5 days at 5s/ledger
        assert_eq!(cutoff_ledgers(5, 5), 86_400);
    }

    #[test]
    fn zero_ledger_seconds_falls_back_to_one() {
        assert_eq!(cutoff_ledgers(1, 0), 86_400);
    }

    #[test]
    fn custom_window() {
        assert_eq!(cutoff_ledgers(2, 10), 17_280);
    }
}
