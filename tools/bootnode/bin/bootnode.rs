use anyhow::{Context, Result, bail};
use bootnode::{
    Bootnode, Postgres,
    config::{Config, OtelConfig, TlsConfig},
    metrics, otel,
    storage::Storage,
};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use url::Url;

/// Bootnode RPC cache for PoolStellar indexer.
#[derive(Debug, Parser)]
#[command(name = "bootnode", version, about)]
struct Cli {
    /// Bind address for the main HTTPS listener.
    #[arg(long, env = "BOOTNODE_BIND", default_value = "0.0.0.0:443")]
    bind: SocketAddr,

    /// Upstream Stellar RPC endpoint used by the background indexer.
    #[arg(long, env = "BOOTNODE_UPSTREAM_RPC_URL")]
    upstream_rpc_url: Url,

    /// Postgres connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Max DB connections in the pool.
    #[arg(long, env = "BOOTNODE_DB_MAX_CONNECTIONS", default_value_t = 10)]
    db_max_connections: u32,

    /// Enable dev-mode behaviors.
    #[arg(long, env = "BOOTNODE_DEV", default_value_t = false)]
    dev: bool,

    /// Serve plain HTTP (debug only).
    ///
    /// This is only allowed when binding to loopback (127.0.0.1 / ::1).
    #[arg(long, env = "BOOTNODE_INSECURE_HTTP", default_value_t = false)]
    insecure_http: bool,

    /// Domain name used for ACME (TLS-ALPN-01).
    #[arg(long, env = "BOOTNODE_DOMAIN")]
    domain: Option<String>,

    /// ACME account contact email (mailto:... will be constructed).
    #[arg(long, env = "BOOTNODE_ACME_EMAIL")]
    acme_email: Option<String>,

    /// ACME cache directory (cert/account cache).
    #[arg(long, env = "BOOTNODE_ACME_CACHE_DIR", default_value = "./acme-cache")]
    acme_cache_dir: PathBuf,

    /// ACME directory URL (LetsEncrypt staging/prod).
    #[arg(long, env = "BOOTNODE_ACME_DIRECTORY_URL")]
    acme_directory_url: Option<Url>,

    /// Redirect buffer in days before network tip.
    #[arg(long, env = "BOOTNODE_REDIRECT_DAYS", default_value_t = 5)]
    redirect_days: u32,

    /// Assumed ledger close time in seconds.
    #[arg(long, env = "BOOTNODE_LEDGER_SECONDS", default_value_t = 5)]
    ledger_seconds: u32,

    /// Indexing loop sleep when caught up (ms).
    #[arg(long, env = "BOOTNODE_INDEXER_SLEEP_MS", default_value_t = 5_000)]
    indexer_sleep_ms: u64,

    /// Max pages per indexing round.
    #[arg(long, env = "BOOTNODE_MAX_PAGES_PER_ROUND", default_value_t = 10)]
    max_pages_per_round: u32,

    /// Events page size.
    #[arg(long, env = "BOOTNODE_PAGE_SIZE", default_value_t = 300)]
    page_size: u32,

    /// Rate limit per IP (requests per second).
    #[arg(long, env = "BOOTNODE_RATE_LIMIT_RPS", default_value_t = 10)]
    rate_limit_rps: u32,

    /// Rate limit burst per IP.
    #[arg(long, env = "BOOTNODE_RATE_LIMIT_BURST", default_value_t = 20)]
    rate_limit_burst: u32,

    /// Enable OpenTelemetry tracing export.
    #[arg(long, env = "BOOTNODE_OTEL_ENABLED", default_value_t = false)]
    otel_enabled: bool,

    /// OTLP endpoint (e.g. http://otel-collector:4317).
    #[arg(long, env = "BOOTNODE_OTEL_OTLP_ENDPOINT")]
    otel_otlp_endpoint: Option<String>,

    /// OpenTelemetry service name.
    #[arg(
        long,
        env = "BOOTNODE_OTEL_SERVICE_NAME",
        default_value = "poolstellar-bootnode"
    )]
    otel_service_name: String,

    /// Trace sampling ratio (0.0..=1.0).
    #[arg(long, env = "BOOTNODE_OTEL_SAMPLE_RATIO", default_value_t = 0.05)]
    otel_sample_ratio: f64,
}

impl Cli {
    fn validate(&self) -> Result<()> {
        if self.insecure_http {
            if !self.dev {
                bail!("--insecure-http requires --dev");
            }
            let ip = self.bind.ip();
            if !ip.is_loopback() {
                bail!(
                    "--insecure-http is only allowed on loopback binds (got {})",
                    self.bind
                );
            }
        } else {
            self.domain
                .as_ref()
                .context("--domain is required for HTTPS/ACME mode")?;
            self.acme_email
                .as_ref()
                .context("--acme-email is required for HTTPS/ACME mode")?;
        }

        if self.otel_enabled && !(0.0..=1.0).contains(&self.otel_sample_ratio) {
            bail!("--otel-sample-ratio must be within 0.0..=1.0");
        }

        if self.database_url.trim().is_empty() {
            bail!("--database-url must not be empty");
        }

        Ok(())
    }

    fn into_config(self) -> Config {
        let tls = match (self.insecure_http, self.domain, self.acme_email) {
            (true, ..) => None,
            (false, Some(domain), Some(acme_email)) => Some(TlsConfig {
                domain,
                acme_email,
                acme_cache_dir: self.acme_cache_dir,
                acme_directory_url: self.acme_directory_url,
            }),
            (false, ..) => {
                unreachable!(
                    "--domain and --acme-email are required when --insecure-http is not set"
                )
            }
        };

        let otel = if self.otel_enabled {
            Some(OtelConfig {
                otlp_endpoint: self.otel_otlp_endpoint,
                service_name: self.otel_service_name,
                sample_ratio: self.otel_sample_ratio,
            })
        } else {
            None
        };

        Config {
            bind: self.bind,
            upstream_rpc_url: self.upstream_rpc_url,
            dev: self.dev,
            tls,
            redirect_days: self.redirect_days,
            ledger_seconds: self.ledger_seconds,
            indexer_sleep_ms: self.indexer_sleep_ms,
            max_pages_per_round: self.max_pages_per_round,
            page_size: self.page_size,
            rate_limit_rps: self.rate_limit_rps,
            rate_limit_burst: self.rate_limit_burst,
            otel,
            initial_ledger_tip: 0,
        }
    }

    async fn open_storage(&self) -> Result<Arc<dyn Storage>> {
        let backend =
            Postgres::connect(&self.database_url, self.db_max_connections as usize).await?;
        backend.init().await?;
        Ok(Arc::new(backend))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.validate()?;

    let storage = cli.open_storage().await?;
    let cfg = cli.into_config();

    let _otel = otel::init_telemetry(&cfg)?;
    metrics::init_metrics()?;
    let prom_handle = metrics::install_prometheus_recorder()?;

    Bootnode::setup(cfg, storage, prom_handle)
        .await?
        .serve()
        .await
}
