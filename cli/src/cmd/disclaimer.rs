//! `disclaimer` — show the operating disclaimer and (when an account is given)
//! whether that account has accepted it.

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments_sdk::state::CURRENT_DISCLAIMER_TEXT_MD;

use crate::{config::CliConfig, output};

pub fn run(config: &CliConfig, json: bool) -> Result<()> {
    let accepted = match &config.account {
        Some(_) => {
            let account = config.require_account()?;
            let mut storage = config.open_storage()?;
            Some(storage.get_disclaimer_state(&account.address)?.accepted)
        }
        None => None,
    };

    #[derive(Serialize)]
    struct DisclaimerOut<'a> {
        text: &'a str,
        accepted: Option<bool>,
    }
    if json {
        return output::emit(
            &DisclaimerOut {
                text: CURRENT_DISCLAIMER_TEXT_MD,
                accepted,
            },
            true,
        );
    }

    println!("{CURRENT_DISCLAIMER_TEXT_MD}");
    match accepted {
        Some(true) => println!("\nStatus: accepted by this account."),
        Some(false) => println!("\nStatus: not yet accepted. Run `spp onboard` to accept."),
        None => println!("\n(Pass --source-account to see whether an account has accepted.)"),
    }
    Ok(())
}
