//! Compose and submit one explicit 2-input / 2-output pool
//! transaction.

use std::{collections::HashSet, str::FromStr};

use anyhow::{Context, Result, bail};
use clap::Args;
use stellar_private_payments::{
    planner::Transact,
    types::{
        EncryptionPublicKey, ExtAmount, Field, NoteAmount, NotePublicKey, UserNoteSummary,
        correlation_id_or_new,
    },
};

use super::{map_pool_err, open_session, print_tx_results};
use crate::{
    config::CliConfig,
    session::{ClientSession, parse_amount},
};

/// Arguments for pool transaction.
#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Pool contract id
    pub pool: String,

    /// Unspent note commitment to consume
    #[arg(long = "input", value_name = "COMMITMENT", action = clap::ArgAction::Append)]
    pub inputs: Vec<String>,

    /// Private output as AMOUNT, AMOUNT@G…, or AMOUNT@NOTE_KEY:ENCRYPTION_KEY
    #[arg(
        long = "output",
        value_name = "AMOUNT[@RECIPIENT]",
        action = clap::ArgAction::Append
    )]
    pub outputs: Vec<OutputArg>,

    /// Public amount entering the pool
    #[arg(long, value_name = "AMOUNT", conflicts_with = "withdraw")]
    pub deposit: Option<String>,

    /// Public amount leaving the pool
    #[arg(long, value_name = "AMOUNT", conflicts_with = "deposit")]
    pub withdraw: Option<String>,

    /// Public withdrawal recipient. defaults to the note owner
    #[arg(long, value_name = "G…", requires = "withdraw")]
    pub withdraw_to: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutputArg {
    amount: NoteAmount,
    recipient: OutputRecipient,
}

#[derive(Debug, Clone)]
enum OutputRecipient {
    SelfAddressed,
    Address(String),
    Keys {
        note: NotePublicKey,
        encryption: EncryptionPublicKey,
    },
}

impl FromStr for OutputArg {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (amount, recipient) = match raw.split_once('@') {
            Some((amount, recipient)) => (amount, Some(recipient)),
            None => (raw, None),
        };
        let amount = parse_amount(amount).context("invalid output amount")?;

        let recipient = match recipient {
            None => OutputRecipient::SelfAddressed,
            Some("") => bail!("output recipient after `@` must not be empty"),
            Some(recipient) => match recipient.split_once(':') {
                None => OutputRecipient::Address(recipient.to_string()),
                Some((note, encryption)) => {
                    if encryption.contains(':') {
                        bail!("explicit output recipient must be NOTE_KEY:ENCRYPTION_KEY");
                    }
                    OutputRecipient::Keys {
                        note: NotePublicKey::parse(note)
                            .context("invalid output recipient note key")?,
                        encryption: EncryptionPublicKey::parse(encryption)
                            .context("invalid output recipient encryption key")?,
                    }
                }
            },
        };

        if amount.is_zero() && !matches!(recipient, OutputRecipient::SelfAddressed) {
            bail!("a zero-value output cannot specify a recipient");
        }

        Ok(Self { amount, recipient })
    }
}

#[tracing::instrument(
    name = "cmd_transact",
    skip_all,
    fields(correlation_id = %correlation_id_or_new())
)]
pub fn run(config: &CliConfig, args: TransactArgs, json: bool) -> Result<()> {
    validate_shape(&args)?;
    let input = parse_inputs(&args.inputs)?;
    let deposit = parse_optional_amount(args.deposit.as_deref(), "deposit")?;
    let withdraw = parse_optional_amount(args.withdraw.as_deref(), "withdraw")?;
    validate_activity(&input, deposit)?;

    let (account, session) = open_session(config, &args.pool)?;
    let pool = session.pool(&args.pool)?;

    let notes = pool
        .notes()
        .map_err(|e| anyhow::anyhow!("list pool notes: {e}"))?;
    let input_total = selected_input_total(&input, &notes)?;
    validate_balance(input_total, &args.outputs, deposit, withdraw)?;

    let (output_amounts, output_note_keys, output_encryption_keys) =
        resolve_outputs(&session, &args.outputs)?;
    let ext_amount = external_amount(deposit, withdraw)?;
    let ext_recipient = if withdraw.is_zero() {
        args.pool.clone()
    } else {
        args.withdraw_to.unwrap_or_else(|| account.address.clone())
    };

    let step = Transact::new(
        input,
        output_amounts,
        ext_amount,
        ext_recipient,
        output_note_keys,
        output_encryption_keys,
    );
    let result = pool
        .transact(step)
        .map_err(|e| map_pool_err(config, e, json))?;
    print_tx_results(config, "Advanced transaction submitted", &[result], json)
}

fn validate_shape(args: &TransactArgs) -> Result<()> {
    if args.inputs.len() > 2 {
        bail!("transact accepts at most 2 --input notes");
    }
    if args.outputs.len() > 2 {
        bail!("transact accepts at most 2 --output values");
    }
    Ok(())
}

fn parse_inputs(raw: &[String]) -> Result<Vec<Field>> {
    let mut parsed = Vec::with_capacity(raw.len());
    let mut unique = HashSet::with_capacity(raw.len());
    for commitment in raw {
        let field = Field::from_str(commitment)
            .with_context(|| format!("invalid input commitment: {commitment}"))?;
        let canonical = field.to_string();
        if !unique.insert(canonical) {
            bail!("input commitment is repeated: {commitment}");
        }
        parsed.push(field);
    }
    Ok(parsed)
}

fn parse_optional_amount(raw: Option<&str>, label: &str) -> Result<NoteAmount> {
    raw.map(parse_amount)
        .transpose()
        .with_context(|| format!("invalid {label} amount"))
        .map(|amount| amount.unwrap_or(NoteAmount::ZERO))
}

fn validate_activity(inputs: &[Field], deposit: NoteAmount) -> Result<()> {
    if inputs.is_empty() && deposit.is_zero() {
        bail!("transact requires at least one --input or a positive --deposit");
    }
    Ok(())
}

fn selected_input_total(inputs: &[Field], notes: &[UserNoteSummary]) -> Result<NoteAmount> {
    let mut total = NoteAmount::ZERO;
    for commitment in inputs {
        let note = notes
            .iter()
            .find(|note| note.id == *commitment)
            .ok_or_else(|| anyhow::anyhow!("input note {commitment} is not owned in this pool"))?;
        if note.spent {
            bail!("input note {commitment} has already been spent");
        }
        total = total
            .checked_add(note.amount)
            .ok_or_else(|| anyhow::anyhow!("input amount total overflow"))?;
    }
    Ok(total)
}

fn validate_balance(
    input_total: NoteAmount,
    outputs: &[OutputArg],
    deposit: NoteAmount,
    withdraw: NoteAmount,
) -> Result<()> {
    let output_total = outputs.iter().try_fold(NoteAmount::ZERO, |total, output| {
        total
            .checked_add(output.amount)
            .ok_or_else(|| anyhow::anyhow!("output amount total overflow"))
    })?;
    let incoming = input_total
        .checked_add(deposit)
        .ok_or_else(|| anyhow::anyhow!("input plus deposit amount overflow"))?;
    let outgoing = output_total
        .checked_add(withdraw)
        .ok_or_else(|| anyhow::anyhow!("output plus withdrawal amount overflow"))?;
    if incoming != outgoing {
        bail!(
            "transaction is not balanced: inputs ({input_total}) + deposit ({deposit}) != outputs ({output_total}) + withdrawal ({withdraw})"
        );
    }
    Ok(())
}

type ResolvedOutputs = (
    [NoteAmount; 2],
    [Option<NotePublicKey>; 2],
    [Option<EncryptionPublicKey>; 2],
);

fn resolve_outputs(session: &ClientSession, outputs: &[OutputArg]) -> Result<ResolvedOutputs> {
    let mut amounts = [NoteAmount::ZERO; 2];
    let mut note_keys = [None, None];
    let mut encryption_keys = [None, None];

    for (index, output) in outputs.iter().enumerate() {
        let slot = index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("output slot overflow"))?;
        amounts[index] = output.amount;
        let keys = match &output.recipient {
            OutputRecipient::SelfAddressed => None,
            OutputRecipient::Keys { note, encryption } => Some((note.clone(), encryption.clone())),
            OutputRecipient::Address(address) => {
                let lookup = session.recipient_lookup(address)?;
                match lookup.entry {
                    Some(entry) => Some((entry.note_key, entry.encryption_key)),
                    None if lookup.registry_fully_synced => bail!(
                        "output {} recipient {address} is not registered; use explicit note and encryption keys or ask the recipient to register",
                        slot
                    ),
                    None => bail!(
                        "output {} recipient {address} is not available locally and the registry is not fully synced; retry after sync or use explicit note and encryption keys",
                        slot
                    ),
                }
            }
        };
        if let Some((note, encryption)) = keys {
            note_keys[index] = Some(note);
            encryption_keys[index] = Some(encryption);
        }
    }

    Ok((amounts, note_keys, encryption_keys))
}

fn external_amount(deposit: NoteAmount, withdraw: NoteAmount) -> Result<ExtAmount> {
    if !deposit.is_zero() {
        let amount = i128::try_from(u128::from(deposit))
            .map_err(|_| anyhow::anyhow!("deposit exceeds the public amount range"))?;
        return Ok(ExtAmount::from(amount));
    }
    if !withdraw.is_zero() {
        let amount = i128::try_from(u128::from(withdraw))
            .map_err(|_| anyhow::anyhow!("withdrawal exceeds the public amount range"))?;
        let amount = amount
            .checked_neg()
            .ok_or_else(|| anyhow::anyhow!("withdrawal amount negation overflow"))?;
        return Ok(ExtAmount::from(amount));
    }
    Ok(ExtAmount::ZERO)
}
