//! `version` — print the `spp` CLI version.

use anyhow::Result;
use serde::Serialize;

use crate::output;

pub fn run(json: bool) -> Result<()> {
    #[derive(Serialize)]
    struct VersionOut<'a> {
        version: &'a str,
    }

    let payload = VersionOut {
        version: env!("CARGO_PKG_VERSION"),
    };

    if json {
        return output::emit(&payload, true);
    }

    println!("{}", payload.version);
    Ok(())
}
