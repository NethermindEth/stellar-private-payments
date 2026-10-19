//! Presentation defaults shared by the CLI and website, keyed by network
//! identity.

use std::{collections::BTreeMap, sync::LazyLock};

use serde::Deserialize;

/// Known-network presentation settings, independent of deployment
/// configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDefaults {
    pub display_name: String,
    pub explorer_url: String,
}

static DEFAULTS: LazyLock<BTreeMap<String, NetworkDefaults>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("network_defaults.json"))
        .expect("valid bundled network presentation defaults")
});

/// Unknown networks have no assumed presentation settings or explorer endpoint.
pub fn for_passphrase(passphrase: &str) -> Option<&'static NetworkDefaults> {
    DEFAULTS.get(passphrase)
}

#[cfg(test)]
mod tests {
    use super::for_passphrase;

    #[test]
    fn presentation_uses_network_identity() {
        let testnet = for_passphrase("Test SDF Network ; September 2015").expect("known network");
        assert_eq!(testnet.display_name, "Testnet");
        assert_eq!(
            testnet.explorer_url,
            "https://stellar.expert/explorer/testnet"
        );
        let mainnet = for_passphrase("Public Global Stellar Network ; September 2015")
            .expect("known network");
        assert_eq!(mainnet.display_name, "Mainnet");
        assert_eq!(
            mainnet.explorer_url,
            "https://stellar.expert/explorer/public"
        );
        assert!(for_passphrase("testnet").is_none());
        assert!(for_passphrase("custom network").is_none());
    }
}
