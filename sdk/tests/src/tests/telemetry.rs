//! Telemetry and logging privacy integration tests.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use stellar_private_payments_sdk::types::NoteAmount;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct MockWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl Write for MockWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().expect("lock buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for MockWriter {
    type Writer = MockWriter;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn test_ring_buffer_has_no_secrets_and_redacts_sensitive() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let writer = MockWriter { buf: buf.clone() };

    let filter = tracing_subscriber::EnvFilter::new("info");
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .without_time();

    let subscriber = tracing_subscriber::registry().with(filter).with(fmt_layer);

    // Run within thread-local subscriber context to capture output reliably
    tracing::subscriber::with_default(subscriber, || {
        let sensitive_amount =
            stellar_private_payments_sdk::types::Sensitive(NoteAmount::from(5u128));
        tracing::info!(amount = ?sensitive_amount, "deposit started");
    });

    let output =
        String::from_utf8(buf.lock().expect("lock buffer").clone()).expect("valid utf-8 logs");
    println!("Captured logs:\n{}", output);

    // Verify deposit log: it should contain "deposit started" and redacted amount
    assert!(output.contains("deposit started"));
    assert!(output.contains("amount"));
    assert!(output.contains("<redacted>"));

    // Ensure it does NOT contain the raw amount "5"
    assert!(!output.contains("amount = 5"));
    assert!(!output.contains("amount: 5"));
}
