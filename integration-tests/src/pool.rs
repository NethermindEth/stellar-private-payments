use stellar_private_payments::types::{GvkMode, PolicyFlag, PolicyFlags};

#[derive(Debug, Clone)]
pub enum PoolAsset {
    Native,
    Classic {
        code: String,
        issuer: String,
        token_contract_id: String,
    },
}

impl PoolAsset {
    pub(crate) fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }
}

#[derive(Debug, Clone)]
pub struct PoolOptions {
    pub policy_flags: PolicyFlags,
    pub gvk_mode: GvkMode,
    pub asset: PoolAsset,
    /// The pool's own fee, smallest deposit and maximum deposit; `None` takes
    /// the deployment's.
    pub fee: Option<u128>,
    pub min_deposit: Option<u128>,
    pub max_deposit: Option<u128>,
}

impl PoolOptions {
    pub const NONE: Self = Self {
        policy_flags: PolicyFlags::EMPTY,
        gvk_mode: GvkMode::Off,
        asset: PoolAsset::Native,
        fee: None,
        min_deposit: None,
        max_deposit: None,
    };

    pub(crate) fn pool_spec(&self, native_token_id: Option<&str>) -> String {
        format!(
            "{}:{}:{}{}",
            self.policy_flags_spec(),
            self.gvk_mode_spec(),
            self.amounts_spec(),
            self.asset_spec(native_token_id)
        )
    }

    /// The `fee=`, `min=` and `max=` prefixes of the amounts this pool sets.
    fn amounts_spec(&self) -> String {
        [
            ("fee", self.fee),
            ("min", self.min_deposit),
            ("max", self.max_deposit),
        ]
        .into_iter()
        .filter_map(|(name, amount)| amount.map(|amount| format!("{name}={amount}:")))
        .collect()
    }

    fn policy_flags_spec(&self) -> String {
        let names: Vec<&str> = [PolicyFlag::Allowlist, PolicyFlag::Blocklist]
            .into_iter()
            .filter(|flag| self.policy_flags.contains(*flag))
            .map(PolicyFlag::name)
            .collect();
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join("-")
        }
    }

    fn gvk_mode_spec(&self) -> &'static str {
        match self.gvk_mode {
            GvkMode::Off => "gvk-off",
            GvkMode::ViewOnly => "gvk-viewonly",
            GvkMode::Traceable => "gvk-traceable",
        }
    }

    fn asset_spec(&self, native_token_id: Option<&str>) -> String {
        match &self.asset {
            PoolAsset::Native => format!(
                "native:{}",
                native_token_id.expect("native pool requires a resolved native token id")
            ),
            PoolAsset::Classic {
                code,
                issuer,
                token_contract_id,
            } => format!("classic:{code}:{issuer}:{token_contract_id}"),
        }
    }
}
