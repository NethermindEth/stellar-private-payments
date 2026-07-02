//! Onboarding wizard + the readiness gate for account commands.
//!
//! Mirrors the web app's onboarding, in this order: tooling check → resolve the
//! Stellar CLI account → consent (disclaimer) → derive privacy keys → bootnode
//! → explorer → optional public-key registration. Consent gates every protocol
//! operation; resolving an address via `stellar keys` is not itself an
//! operation. Step texts are reused from the app.

use std::io::Write;

use anyhow::{Context, Result, bail};
use stellar_private_payments_sdk::{
    state::SqliteStorage,
    tx::encryption::{
        KEY_DERIVATION_MESSAGE, derive_encryption_and_note_keypairs, derive_membership_blinding,
    },
};

use crate::{account::Account, cmd::register, config::CliConfig, explorer, stellar_cli};

// Reused from the web app onboarding wizard / index.html.
const KEYS_TEXT: &str = "Your wallet is requested to sign one message. That signature derives your \
    privacy keys locally plus your ASP secret. This does not move funds.";
const BOOTNODE_TEXT: &str = "Choose whether this operator station keeps a bootnode archive URL. You \
    can change bootnode settings later.";
const BOOTNODE_RISKS: &str = "Trust assumptions when using a bootnode:\n\
    - Integrity risk: a bootnode can omit or forge event history.\n\
    - Availability risk: it can be down or rate limit requests.\n\
    - Privacy risk: the operator can observe IP address and sync timing.\n\
    - Handoff risk: it can provide an incorrect ledger handoff point.";
const EXPLORER_TEXT: &str =
    "The UI uses a single explorer base URL across transaction feedback and address shortcuts.";
const REGISTRATION_TEXT: &str = "If you register now, other users can transfer to your Stellar \
    address without asking for note and encryption public keys out of band.";

/// Non-interactive overrides for `onboard`.
#[derive(Debug, Default)]
pub struct OnboardArgs {
    pub accept: bool,
    pub bootnode_url: Option<String>,
    pub no_bootnode: bool,
    pub explorer_url: Option<String>,
    pub register: bool,
    pub no_register: bool,
}

/// Gate for account commands: stellar-cli present, disclaimer accepted, keys
/// derived. Bails with a pointer to `spp onboard` when not ready.
pub fn ensure_ready(config: &CliConfig, account: &Account) -> Result<()> {
    stellar_cli::ensure_installed()?;
    let mut storage = config.open_storage()?;
    if !storage.get_disclaimer_state(&account.address)?.accepted {
        bail!(
            "You must accept the disclaimer first. Run: spp onboard --source-account {}",
            account.alias
        );
    }
    if storage.get_user_keys(&account.address)?.is_none() {
        bail!(
            "Privacy keys are not set up. Run: spp onboard --source-account {}",
            account.alias
        );
    }
    Ok(())
}

pub fn run(config: &CliConfig, args: &OnboardArgs, json: bool) -> Result<()> {
    let interactive = !json;

    // 1. Tooling check (nice install link if missing).
    let version = stellar_cli::ensure_installed()?;
    log::info!("Found Stellar CLI: {version}");

    // 2. Resolve the account (via `stellar keys`).
    let account = config.require_account()?;
    let mut storage = config.open_storage()?;

    // 3. Consent.
    let state = storage.get_disclaimer_state(&account.address)?;
    if state.accepted {
        say(interactive, "Disclaimer already accepted.");
    } else {
        if interactive {
            println!("{}\n", state.disclaimer_text_md);
        }
        let accepted = args.accept
            || (interactive && prompt_yes_no("Do you accept the disclaimer above?", false)?);
        if !accepted {
            bail!("Disclaimer not accepted; aborting. Pass --accept to accept non-interactively.");
        }
        storage.accept_current_disclaimer(&account.address, &state.disclaimer_hash_hex)?;
        say(interactive, "Disclaimer accepted.");
    }

    // 4. Derive privacy keys.
    if storage.get_user_keys(&account.address)?.is_some() {
        say(interactive, "Privacy keys already present.");
    } else {
        if interactive {
            println!("\n{KEYS_TEXT}");
        }
        derive_and_save_keys(config, &account, &mut storage)?;
        say(interactive, "Privacy keys derived and stored.");
    }

    // 5. Bootnode.
    configure_bootnode(&mut storage, args, interactive)?;

    // 6. Explorer.
    configure_explorer(&mut storage, args, interactive)?;

    // 7. Optional registration.
    maybe_register(config, &account, &mut storage, args, interactive)?;

    say(interactive, "\nOnboarding complete.");
    Ok(())
}

/// Delegate the SEP-53 key-derivation signature to the Stellar CLI (the secret
/// never enters this process) and store the derived privacy keys.
fn derive_and_save_keys(
    config: &CliConfig,
    account: &Account,
    storage: &mut SqliteStorage,
) -> Result<()> {
    let signature = stellar_cli::sign_message(
        &account.alias,
        KEY_DERIVATION_MESSAGE,
        config.stellar_config_dir.as_deref(),
    )
    .context("derive privacy-key signature via stellar CLI")?;

    let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(signature.clone())
        .context("derive privacy keypairs from wallet signature")?;
    let membership_blinding = derive_membership_blinding(&signature, &config.deployment.network)?;

    storage
        .save_encryption_and_note_keypairs(
            &account.address,
            &note_keypair,
            &encryption_keypair,
            &membership_blinding,
        )
        .context("save privacy keys to local wallet database")
}

fn configure_bootnode(
    storage: &mut SqliteStorage,
    args: &OnboardArgs,
    interactive: bool,
) -> Result<()> {
    if args.no_bootnode {
        storage.set_bootnode_setting(false, "")?;
        return Ok(());
    }
    if let Some(url) = &args.bootnode_url {
        storage.set_bootnode_setting(true, url)?;
        say(interactive, &format!("Bootnode set to {url}."));
        return Ok(());
    }
    if !interactive {
        return Ok(());
    }
    let current = storage.get_bootnode_setting()?;
    println!("\nBootnode fallback (optional):\n{BOOTNODE_RISKS}\n{BOOTNODE_TEXT}");
    let hint = if current.enabled && !current.url.is_empty() {
        format!(" [{}]", current.url)
    } else {
        String::new()
    };
    let input = prompt_line(&format!("Bootnode archive URL{hint} (blank to skip): "))?;
    if !input.is_empty() {
        storage.set_bootnode_setting(true, &input)?;
    } else if !current.enabled {
        storage.set_bootnode_setting(false, "")?;
    }
    Ok(())
}

fn configure_explorer(
    storage: &mut SqliteStorage,
    args: &OnboardArgs,
    interactive: bool,
) -> Result<()> {
    if let Some(url) = &args.explorer_url {
        explorer::set_base_url(storage, url)?;
        say(interactive, &format!("Explorer set to {url}."));
        return Ok(());
    }
    if !interactive {
        return Ok(());
    }
    let current = explorer::base_url(storage)?;
    println!("\nExplorer:\n{EXPLORER_TEXT}");
    let input = prompt_line(&format!("Explorer base URL [{current}]: "))?;
    let url = if input.is_empty() { current } else { input };
    explorer::set_base_url(storage, &url)?;
    Ok(())
}

fn maybe_register(
    config: &CliConfig,
    account: &Account,
    storage: &mut SqliteStorage,
    args: &OnboardArgs,
    interactive: bool,
) -> Result<()> {
    let do_register = if args.register {
        true
    } else if args.no_register || !interactive {
        false
    } else {
        println!("\n{REGISTRATION_TEXT}");
        prompt_yes_no("Register your public keys now?", false)?
    };
    if !do_register {
        return Ok(());
    }
    let network = config.resolve_network()?;
    let hash = register::register_account(config, account, &network, storage)?;
    say(interactive, &format!("Registered (tx {hash})."));
    Ok(())
}

fn say(interactive: bool, msg: &str) {
    if interactive {
        println!("{msg}");
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read from stdin")?;
    Ok(line.trim().to_string())
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    let answer = prompt_line(&format!("{prompt} {suffix} "))?;
    Ok(match answer.to_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}
