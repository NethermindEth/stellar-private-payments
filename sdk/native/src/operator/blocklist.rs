use crate::{
    Error,
    chain::{StateFetcher, field_to_scval_u256},
    types::{AspNonMembership, Field, NotePublicKey},
};

use super::UnsignedOperatorCall;

contract_handle! {
    /// Session for the admin of one non-membership tree.
    ///
    /// Open with [`crate::Client::blocklist_operator`] or [`Self::open`].
    BlocklistOperator, blocklist_ids
}

impl BlocklistOperator {
    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspNonMembership, Error> {
        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())?;
        Ok(fetcher.asp_non_membership_state(&self.contract_id).await?)
    }

    /// Blocks `note_keys`, sourced by the tree's admin: one key goes in with
    /// `insert_leaf`, several with `insert_leaves`. Repeats are dropped, since
    /// the tree refuses a key it already holds.
    ///
    /// # Errors
    /// Refuses an empty list.
    pub async fn insert_keys(
        &self,
        note_keys: &[NotePublicKey],
    ) -> Result<UnsignedOperatorCall, Error> {
        let (method, args) = insert_keys_call(note_keys)?;
        self.admin_call(method, args).await
    }

    /// Unblocks `note_key`, sourced by the tree's admin.
    pub async fn delete_key(
        &self,
        note_key: &NotePublicKey,
    ) -> Result<UnsignedOperatorCall, Error> {
        let key = tree_key(note_key)?;
        self.admin_call("delete_leaf", vec![field_to_scval_u256(key)])
            .await
    }
}

/// The method and arguments that insert `note_keys`, each as both key and
/// value.
fn insert_keys_call(
    note_keys: &[NotePublicKey],
) -> Result<(&'static str, Vec<stellar_xdr::ScVal>), Error> {
    let mut keys = Vec::with_capacity(note_keys.len());
    for note_key in note_keys {
        let key = tree_key(note_key)?;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    let pair = |key: Field| vec![field_to_scval_u256(key), field_to_scval_u256(key)];
    match keys.as_slice() {
        [] => Err(Error::Refused("no note keys to block".to_string())),
        [key] => Ok(("insert_leaf", pair(*key))),
        keys => {
            let entries = keys
                .iter()
                .map(|key| Ok(stellar_xdr::ScVal::Vec(Some(pair(*key).try_into()?))))
                .collect::<Result<Vec<_>, stellar_xdr::Error>>()
                .map_err(anyhow::Error::from)?;
            Ok((
                "insert_leaves",
                vec![stellar_xdr::ScVal::Vec(Some(
                    entries.try_into().map_err(anyhow::Error::from)?,
                ))],
            ))
        }
    }
}

/// The tree key of a note public key: its bytes read as a little-endian
/// field element, as the circuits read it.
fn tree_key(note_key: &NotePublicKey) -> Result<Field, Error> {
    Ok(Field::try_from_le_bytes(*note_key.as_ref())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteAmount;

    fn note_key(byte: u8) -> NotePublicKey {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        NotePublicKey(bytes)
    }

    #[test]
    fn one_key_is_inserted_as_its_own_value() {
        let (method, args) = insert_keys_call(&[note_key(5), note_key(5)]).expect("call");
        assert_eq!(method, "insert_leaf");
        let key = field_to_scval_u256(Field::from(NoteAmount::from(5u128)));
        assert_eq!(args, vec![key.clone(), key]);
    }

    #[test]
    fn several_keys_are_inserted_as_pairs_in_order() {
        let (method, args) =
            insert_keys_call(&[note_key(1), note_key(2), note_key(1)]).expect("call");
        assert_eq!(method, "insert_leaves");
        let pair = |byte: u64| {
            let key = field_to_scval_u256(Field::from(NoteAmount::from(u128::from(byte))));
            stellar_xdr::ScVal::Vec(Some(vec![key.clone(), key].try_into().expect("pair")))
        };
        assert_eq!(
            args,
            vec![stellar_xdr::ScVal::Vec(Some(
                vec![pair(1), pair(2)].try_into().expect("entries")
            ))]
        );
    }

    #[test]
    fn an_empty_list_is_refused() {
        assert!(matches!(insert_keys_call(&[]), Err(Error::Refused(_))));
    }
}
