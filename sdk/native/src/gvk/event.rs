use crate::types::{Field, GlobalViewKeyCiphertext};

/// Indexed pool-gvk event returned during admin audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GvkEvent {
    Commitment {
        ledger: u32,
        event_id: String,
        commitment: Field,
        gvk_ciphertext: GlobalViewKeyCiphertext,
    },
    Nullifier {
        ledger: u32,
        event_id: String,
        nullifier: Field,
        gvk_ciphertext: Option<GlobalViewKeyCiphertext>,
    },
}

impl GvkEvent {
    pub fn ledger(&self) -> u32 {
        match self {
            Self::Commitment { ledger, .. } | Self::Nullifier { ledger, .. } => *ledger,
        }
    }

    pub fn event_id(&self) -> &str {
        match self {
            Self::Commitment { event_id, .. } | Self::Nullifier { event_id, .. } => event_id,
        }
    }
}
