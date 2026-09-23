use stellar_private_payments::types::{GvkMode, PolicyFlag, PolicyFlags};

#[derive(Debug, Clone)]
pub enum PoolAsset {
    Native,
    Classic {
        code: String,
        issuer: String,
        token_contract_id: String,
    },
    Contract {
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
}

impl PoolOptions {
    pub const NONE: Self = Self {
        policy_flags: PolicyFlags::EMPTY,
        gvk_mode: GvkMode::Off,
        asset: PoolAsset::Native,
    };

    pub(crate) fn pool_spec(&self, native_token_id: Option<&str>) -> String {
        format!(
            "{}:{}:{}",
            self.policy_flags_spec(),
            self.gvk_mode_spec(),
            self.asset_spec(native_token_id)
        )
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
            PoolAsset::Contract { token_contract_id } => format!("contract:{token_contract_id}"),
        }
    }
}
