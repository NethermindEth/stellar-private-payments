//! Progress logging for the CLI.
//!
//! Installs a `log` implementation so SDK sync logs (indexer/storage/transact)
//! and the CLI's own progress lines stream to the user on **stderr**: colored
//! human text by default, or one JSON object per line under `--json` (keeping
//! stdout reserved for the command's JSON result).

use std::{
    io::{IsTerminal, Write},
    sync::OnceLock,
};

use log::{Level, LevelFilter, Metadata, Record};

struct CliLogger {
    json: bool,
    color: bool,
}

static LOGGER: OnceLock<CliLogger> = OnceLock::new();

/// Install the logger. `verbose` is the repeat count of `-v`
/// (0 = info, 1 = debug, 2+ = trace).
pub fn init(verbose: u8, json: bool) {
    let level = match verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    let color = !json && std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let logger = LOGGER.get_or_init(|| CliLogger { json, color });
    // Ignore the error if a logger was already installed (e.g. tests).
    let _ = log::set_logger(logger);
    log::set_max_level(level);
}

fn ansi(level: Level) -> &'static str {
    match level {
        Level::Error => "31",
        Level::Warn => "33",
        Level::Info => "32",
        Level::Debug => "36",
        Level::Trace => "90",
    }
}

impl log::Log for CliLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut err = std::io::stderr().lock();
        if self.json {
            let obj = serde_json::json!({
                "level": record.level().to_string(),
                "target": record.target(),
                "message": record.args().to_string(),
            });
            let _ = writeln!(err, "{obj}");
        } else if self.color {
            let _ = writeln!(
                err,
                "\x1b[{}m{:>5}\x1b[0m {}",
                ansi(record.level()),
                record.level(),
                record.args()
            );
        } else {
            let _ = writeln!(err, "{:>5} {}", record.level(), record.args());
        }
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}
