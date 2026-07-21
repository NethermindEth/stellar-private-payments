use serde::{Deserialize, Serialize};
use std::{
    fmt,
    ops::Deref,
    sync::atomic::{AtomicBool, Ordering},
};

/// Target sinks for telemetry logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TelemetrySink {
    /// Write to standard system console (stdout/stderr or browser console).
    Console,
    /// Write to an in-memory ring buffer.
    RingBuffer,
    /// Write to both the console and the ring buffer.
    Both,
}

/// Unified telemetry configuration for the SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryConfig {
    /// Logging level filter (e.g. "info", "debug", "trace").
    pub level: String,
    /// Target logging sink.
    pub sink: TelemetrySink,
    /// Size of the in-memory ring buffer in bytes.
    pub ring_buffer_bytes: usize,
    /// Whether to reveal Tier-1 sensitive values in debug logs (always gated by
    /// compile assertions).
    pub reveal_sensitive: bool,
}

// Global reveal flag for Tier-1 fields
static REVEAL_SENSITIVE: AtomicBool = AtomicBool::new(false);

/// Enable or disable revealing Tier-1 sensitive fields in debug builds.
pub fn set_reveal_sensitive(reveal: bool) {
    REVEAL_SENSITIVE.store(reveal, Ordering::Relaxed);
}

/// Query whether Tier-1 sensitive fields should be revealed.
/// Always returns false in release builds (when debug_assertions is false).
pub fn reveal_sensitive() -> bool {
    cfg!(debug_assertions) && REVEAL_SENSITIVE.load(Ordering::Relaxed)
}

/// A wrapper for Tier-1 sensitive values (amounts, addresses, commitments,
/// nullifiers, etc.) that redacts their `Debug` and `Display` output in
/// production or when not explicitly enabled.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Sensitive<T>(pub T);

impl<T> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Sensitive<T> {
    /// Wrap a value as sensitive.
    pub fn new(val: T) -> Self {
        Self(val)
    }

    /// Expose a reference to the inner value.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Unwrap and consume into the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if reveal_sensitive() {
            self.0.fmt(f)
        } else {
            write!(f, "\"<redacted>\"")
        }
    }
}

impl<T: fmt::Display> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if reveal_sensitive() {
            self.0.fmt(f)
        } else {
            write!(f, "<redacted>")
        }
    }
}

impl<T: Serialize> Serialize for Sensitive<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Sensitive<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Sensitive)
    }
}

/// A wrapper for Tier-0 secrets (keys, seeds, etc.) that ALWAYS redacts its
/// `Debug` and `Display` output, and zeroizes its memory when dropped.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Secret<T: zeroize::Zeroize>(pub T);

impl<T: zeroize::Zeroize> Deref for Secret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: zeroize::Zeroize> Secret<T> {
    /// Wrap a value as a secret.
    pub fn new(val: T) -> Self {
        Self(val)
    }

    /// Expose a reference to the inner secret.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: zeroize::Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"<redacted>\"")
    }
}

impl<T: zeroize::Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

impl<T: zeroize::Zeroize + Serialize> Serialize for Secret<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: zeroize::Zeroize + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Secret)
    }
}

impl<T: zeroize::Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: zeroize::Zeroize> zeroize::Zeroize for Secret<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionPrivateKey, KeyDerivationSignature, NotePrivateKey};
    use zeroize::Zeroize;

    #[test]
    fn test_tier1_sensitive_redaction() {
        let val = Sensitive::new("sensitive_data".to_string());

        // By default, reveal_sensitive should be false
        set_reveal_sensitive(false);
        assert_eq!(format!("{:?}", val), "\"<redacted>\"");
        assert_eq!(format!("{}", val), "<redacted>");

        // Opt-in to reveal
        set_reveal_sensitive(true);
        if cfg!(debug_assertions) {
            assert_eq!(format!("{:?}", val), "\"sensitive_data\"");
            assert_eq!(format!("{}", val), "sensitive_data");
        } else {
            // Production builds must NEVER reveal Tier-1 values
            assert_eq!(format!("{:?}", val), "\"<redacted>\"");
            assert_eq!(format!("{}", val), "<redacted>");
        }

        // Reset state
        set_reveal_sensitive(false);
    }

    #[test]
    fn test_tier0_secret_redaction() {
        let secret_bytes = Secret::new([42u8; 32]);
        let secret_str = Secret::new("very_secret_key".to_string());

        set_reveal_sensitive(true);
        // Tier-0 must always be redacted under any setting/build
        assert_eq!(format!("{:?}", secret_bytes), "\"<redacted>\"");
        assert_eq!(format!("{}", secret_bytes), "<redacted>");
        assert_eq!(format!("{:?}", secret_str), "\"<redacted>\"");
        assert_eq!(format!("{}", secret_str), "<redacted>");

        set_reveal_sensitive(false);
    }

    #[test]
    fn test_key_types_redaction() {
        let enc_key = EncryptionPrivateKey([1u8; 32]);
        let note_key = NotePrivateKey([2u8; 32]);
        let signature = KeyDerivationSignature(vec![3u8; 10]);

        set_reveal_sensitive(true);
        // Key types must always be redacted under any setting/build
        assert_eq!(format!("{:?}", enc_key), "EncryptionPrivateKey(<redacted>)");
        assert_eq!(format!("{:?}", note_key), "NotePrivateKey(<redacted>)");
        assert_eq!(
            format!("{:?}", signature),
            "KeyDerivationSignature(<redacted>)"
        );

        set_reveal_sensitive(false);
    }

    #[test]
    fn test_zeroize_manual() {
        let mut secret = Secret::new([9u8; 32]);
        secret.zeroize();
        assert_eq!(secret.expose(), &[0u8; 32]);
    }

    #[test]
    fn test_telemetry_config_gating() {
        let config_reveal = TelemetryConfig {
            level: "debug".to_string(),
            sink: TelemetrySink::Console,
            ring_buffer_bytes: 1024,
            reveal_sensitive: true,
        };

        let config_redact = TelemetryConfig {
            level: "debug".to_string(),
            sink: TelemetrySink::Console,
            ring_buffer_bytes: 1024,
            reveal_sensitive: false,
        };

        // Gating under reveal config
        set_reveal_sensitive(config_reveal.reveal_sensitive);
        if cfg!(debug_assertions) {
            assert!(reveal_sensitive());
        } else {
            assert!(!reveal_sensitive());
        }

        // Gating under redact config
        set_reveal_sensitive(config_redact.reveal_sensitive);
        assert!(!reveal_sensitive());

        // Reset
        set_reveal_sensitive(false);
    }
}
