//! Browser SDK — wasm-bindgen bindings over [`stellar_private_payments_sdk`].
//!
//! Connect with [`Client`], then [`Client::account`], then [`Account::pool`].

mod bootnode;
mod circuits;
mod client;
mod correlation;
mod deployment;
mod protocol;
mod signer;
mod storage;
mod telemetry;
pub mod workers;

pub(crate) mod artifact_hashes {
    include!(concat!(env!("OUT_DIR"), "/artifact_hashes.rs"));
}

pub(crate) const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

pub use bootnode::bootnode_required_js as bootnode_required;
pub use client::{Account, Client, PrivatePool, verify_selective_disclosure_standalone};
pub use storage::Storage;

use wasm_bindgen::prelude::*;

pub(crate) fn wasm_start() {
    crate::telemetry::init_telemetry(None);
    crate::telemetry::install_panic_hook();
    tracing::info!("SDK telemetry initialized");
}

/// Configure the SDK telemetry settings (log level, sink targets, buffer sizes,
/// etc.).
///
/// If telemetry has not been initialized yet, this function will initialize it
/// with the specified config (or defaults). If telemetry has already been
/// initialized, this will dynamically update runtime settings (log level and
/// sensitive log reveal).
///
/// TS signature:
/// ```typescript
/// export function configureTelemetry(config?: {
///   level?: string;
///   sink?: "console" | "ringBuffer" | "both";
///   ringBufferBytes?: number;
///   revealSensitive?: boolean;
/// }): void;
/// ```
#[wasm_bindgen(js_name = configureTelemetry)]
pub fn configure_telemetry(config: JsValue) -> Result<(), JsValue> {
    use stellar_private_payments_sdk::types::TelemetryConfig;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsTelemetryConfig {
        level: Option<String>,
        sink: Option<stellar_private_payments_sdk::types::TelemetrySink>,
        ring_buffer_bytes: Option<usize>,
        reveal_sensitive: Option<bool>,
    }

    let defaults = crate::telemetry::resolve_default_config();

    let final_config = if config.is_undefined() || config.is_null() {
        defaults
    } else {
        let js_cfg: JsTelemetryConfig = serde_wasm_bindgen::from_value(config)?;
        TelemetryConfig {
            level: js_cfg.level.unwrap_or(defaults.level),
            sink: js_cfg.sink.unwrap_or(defaults.sink),
            ring_buffer_bytes: js_cfg
                .ring_buffer_bytes
                .unwrap_or(defaults.ring_buffer_bytes),
            reveal_sensitive: js_cfg.reveal_sensitive.unwrap_or(defaults.reveal_sensitive),
        }
    };

    if crate::telemetry::is_telemetry_initialized() {
        // If already initialized, dynamically update runtime settings
        let _ = crate::telemetry::set_log_level(&final_config.level);
        stellar_private_payments_sdk::types::set_reveal_sensitive(final_config.reveal_sensitive);
        return Ok(());
    }

    crate::telemetry::init_telemetry(Some(final_config));
    crate::telemetry::install_panic_hook();
    Ok(())
}

/// Replace the active tracing [`EnvFilter`] with `level`.
///
/// `level` must be a valid tracing directive such as `"info"` or
/// `"stellar_private_payments_sdk_web=debug"`.
#[wasm_bindgen]
pub fn set_log_level(level: &str) -> Result<(), JsValue> {
    crate::telemetry::set_log_level(level).map_err(JsValue::from)
}

/// Return the recent formatted log output stored in the in-memory ring buffer.
#[wasm_bindgen]
pub fn dump_recent_logs() -> String {
    crate::telemetry::dump_recent_logs()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_init_telemetry_native() {
        crate::telemetry::init_telemetry(None);
        assert!(crate::telemetry::is_telemetry_initialized());
    }
}
