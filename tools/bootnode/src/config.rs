use anyhow::{Context, Result};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use url::Url;

/// Bootnode configuration.
#[derive(Debug, Clone, Parser)]
#[command(name = "bootnode", version, about = "Bootnode RPC cache for PoolStellar indexer")]
pub(crate) struct Config {
    /// Bind address for the main HTTPS listener.
    #[arg(long, env = "BOOTNODE_BIND", default_value = "0.0.0.0:443")]
    pub(crate) bind: SocketAddr,

    /// Upstream Stellar RPC endpoint to index from and redirect to.
    #[arg(long, env = "BOOTNODE_UPSTREAM_RPC_URL")]
    pub(crate) upstream_rpc_url: Url,

    /// Postgres connection string.
    #[arg(long, env = "DATABASE_URL")]
    pub(crate) database_url: String,

    /// Max DB connections in the pool.
    #[arg(long, env = "BOOTNODE_DB_MAX_CONNECTIONS", default_value_t = 10)]
    pub(crate) db_max_connections: u32,

    /// Enable dev-mode behaviors.
    #[arg(long, env = "BOOTNODE_DEV", default_value_t = false)]
    pub(crate) dev: bool,

    /// Serve plain HTTP (debug only).
    ///
    /// This is only allowed when binding to loopback (127.0.0.1 / ::1).
    #[arg(long, env = "BOOTNODE_INSECURE_HTTP", default_value_t = false)]
    pub(crate) insecure_http: bool,

    /// Domain name used for ACME (TLS-ALPN-01).
    #[arg(long, env = "BOOTNODE_DOMAIN")]
    pub(crate) domain: Option<String>,

    /// ACME account contact email (mailto:... will be constructed).
    #[arg(long, env = "BOOTNODE_ACME_EMAIL")]
    pub(crate) acme_email: Option<String>,

    /// ACME cache directory (cert/account cache).
    #[arg(long, env = "BOOTNODE_ACME_CACHE_DIR", default_value = "./acme-cache")]
    pub(crate) acme_cache_dir: PathBuf,

    /// ACME directory URL (LetsEncrypt staging/prod).
    #[arg(long, env = "BOOTNODE_ACME_DIRECTORY_URL")]
    pub(crate) acme_directory_url: Option<Url>,

    /// Redirect buffer in days before network tip.
    #[arg(long, env = "BOOTNODE_REDIRECT_DAYS", default_value_t = 5)]
    pub(crate) redirect_days: u32,

    /// Assumed ledger close time in seconds.
    #[arg(long, env = "BOOTNODE_LEDGER_SECONDS", default_value_t = 5)]
    pub(crate) ledger_seconds: u32,

    /// Indexing loop sleep when caught up (ms).
    #[arg(long, env = "BOOTNODE_INDEXER_SLEEP_MS", default_value_t = 5_000)]
    pub(crate) indexer_sleep_ms: u64,

    /// Max pages per indexing round.
    #[arg(long, env = "BOOTNODE_MAX_PAGES_PER_ROUND", default_value_t = 10)]
    pub(crate) max_pages_per_round: u32,

    /// Events page size.
    #[arg(long, env = "BOOTNODE_PAGE_SIZE", default_value_t = 300)]
    pub(crate) page_size: u32,

    /// Rate limit per IP (requests per second).
    #[arg(long, env = "BOOTNODE_RATE_LIMIT_RPS", default_value_t = 10)]
    pub(crate) rate_limit_rps: u32,

    /// Rate limit burst per IP.
    #[arg(long, env = "BOOTNODE_RATE_LIMIT_BURST", default_value_t = 20)]
    pub(crate) rate_limit_burst: u32,

    /// Enable OpenTelemetry tracing export.
    #[arg(long, env = "BOOTNODE_OTEL_ENABLED", default_value_t = false)]
    pub(crate) otel_enabled: bool,

    /// OTLP endpoint (e.g. http://otel-collector:4317).
    #[arg(long, env = "BOOTNODE_OTEL_OTLP_ENDPOINT")]
    pub(crate) otel_otlp_endpoint: Option<String>,

    /// OpenTelemetry service name.
    #[arg(long, env = "BOOTNODE_OTEL_SERVICE_NAME", default_value = "poolstellar-bootnode")]
    pub(crate) otel_service_name: String,

    /// Trace sampling ratio (0.0..=1.0).
    #[arg(long, env = "BOOTNODE_OTEL_SAMPLE_RATIO", default_value_t = 0.05)]
    pub(crate) otel_sample_ratio: f64,
}

impl Config {
    pub(crate) fn parse_and_validate() -> Result<Self> {
        let cfg = Self::parse();

        if cfg.insecure_http {
            if !cfg.dev {
                anyhow::bail!("--insecure-http requires --dev");
            }
            let ip = cfg.bind.ip();
            if !(ip.is_loopback()) {
                anyhow::bail!(
                    "--insecure-http is only allowed on loopback binds (got {})",
                    cfg.bind
                );
            }
        } else {
            cfg.domain
                .as_ref()
                .context("--domain is required for HTTPS/ACME mode")?;
            cfg.acme_email
                .as_ref()
                .context("--acme-email is required for HTTPS/ACME mode")?;
        }

        if !(0.0..=1.0).contains(&cfg.otel_sample_ratio) {
            anyhow::bail!("--otel-sample-ratio must be within 0.0..=1.0");
        }

        Ok(cfg)
    }

    pub(crate) fn cutoff_ledgers(&self) -> u32 {
        let seconds = self
            .redirect_days
            .saturating_mul(24)
            .saturating_mul(60)
            .saturating_mul(60);
        let denom = self.ledger_seconds.max(1);
        seconds / denom
    }
}

