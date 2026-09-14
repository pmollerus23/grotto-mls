//! Independently verified bindings. The relay is never a trust source.
use crate::store::{ClientStore, StoreError};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use grotto_protocol::{UserId, cert_fingerprint_sha256_hex, parse_fingerprint_hex};
use mls_rs_core::{
    extension::ExtensionList,
    identity::{CredentialType, IdentityProvider, MemberValidationContext, SigningIdentity},
    time::MlsTime,
};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;

const DOMAIN: &[u8] = b"GROTTO-CONTACT-V1\0";
const CARD_BYTES: usize = 145;

#[derive(Clone, PartialEq, Eq)]
pub struct ContactCard {
    pub user: UserId,
    pub transport_key: [u8; 32],
    pub mls_key: [u8; 32],
    signature: [u8; 64],
}
impl ContactCard {
    fn transcript(&self) -> Vec<u8> {
        [
            DOMAIN,
            &self.user.to_bytes(),
            &self.transport_key,
            &self.mls_key,
        ]
        .concat()
    }
    pub fn own(store: &ClientStore) -> Result<Self, StoreError> {
        // identity() opens its own short transaction; callers export outside
        // another transaction, using the same serialized service thread.
        let identity = store.identity()?;
        let keys = store
            .load_mls_identity()?
            .ok_or(StoreError::InvalidData("MLS identity missing"))?;
        let mut card = Self {
            user: identity.user_id(),
            transport_key: identity.signing_key().verifying_key().to_bytes(),
            mls_key: keys
                .0
                .try_into()
                .map_err(|_| StoreError::InvalidData("invalid MLS public key"))?,
            signature: [0; 64],
        };
        card.signature = identity.signing_key().sign(&card.transcript()).to_bytes();
        Ok(card)
    }
    pub fn bytes(&self) -> Vec<u8> {
        [
            &[1][..],
            &self.user.to_bytes(),
            &self.transport_key,
            &self.mls_key,
            &self.signature,
        ]
        .concat()
    }
    pub fn encode(&self) -> String {
        self.bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn fingerprint(&self) -> String {
        cert_fingerprint_sha256_hex(&self.bytes())
    }
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        if text.len() != CARD_BYTES * 2 || !text.is_ascii() {
            return Err(StoreError::InvalidData("invalid contact card size"));
        }
        let mut bytes = [0; CARD_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| StoreError::InvalidData("invalid contact encoding"))?;
        }
        if bytes[0] != 1 {
            return Err(StoreError::InvalidData("unsupported contact card version"));
        }
        let card = Self {
            user: UserId::from_bytes(bytes[1..17].try_into().unwrap()),
            transport_key: bytes[17..49].try_into().unwrap(),
            mls_key: bytes[49..81].try_into().unwrap(),
            signature: bytes[81..].try_into().unwrap(),
        };
        VerifyingKey::from_bytes(&card.transport_key)
            .and_then(|key| {
                key.verify_strict(&card.transcript(), &Signature::from_bytes(&card.signature))
            })
            .map_err(|_| StoreError::InvalidData("invalid contact signature"))?;
        Ok(card)
    }
    pub fn import(
        &self,
        store: &ClientStore,
        independent_fingerprint: &str,
    ) -> Result<(), StoreError> {
        if parse_fingerprint_hex(independent_fingerprint)
            .map_err(|_| StoreError::InvalidData("invalid fingerprint"))?
            != parse_fingerprint_hex(&self.fingerprint()).unwrap()
        {
            return Err(StoreError::InvalidData(
                "independent contact fingerprint does not match",
            ));
        }
        // Re-validate signatures even for cards constructed by callers.
        Self::parse(&self.encode())?;
        let connection = store.lock()?;
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT card FROM verified_contacts WHERE user_id=?1",
                [self.user.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = existing {
            if old != self.bytes() {
                return Err(StoreError::InvalidData(
                    "contact keys changed; pin preserved",
                ));
            }
            return Ok(());
        }
        drop(connection);
        store.admit_new_data(CARD_BYTES)?;
        let connection = store.lock()?;
        connection.execute(
            "INSERT INTO verified_contacts VALUES(?1,?2,?3) ON CONFLICT(user_id) DO NOTHING",
            params![
                self.user.to_bytes().as_slice(),
                self.mls_key.as_slice(),
                self.bytes()
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct VerifiedIdentityProvider(pub Arc<ClientStore>);
impl VerifiedIdentityProvider {
    pub fn verify(&self, identity: &SigningIdentity) -> Result<Vec<u8>, StoreError> {
        let credential = identity
            .credential
            .as_basic()
            .ok_or(StoreError::InvalidData("non-basic credential"))?;
        let user: [u8; 16] = credential
            .identifier
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::InvalidData("MLS credential must be a Grotto UserId"))?;
        let pinned: Option<Vec<u8>> = self
            .0
            .lock_provider()?
            .query_row(
                "SELECT mls_key FROM verified_contacts WHERE user_id=?1",
                [user.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match pinned {
            None => Err(StoreError::InvalidData("unverified group member")),
            Some(key) if key.as_slice() != identity.signature_key.as_bytes() => Err(
                StoreError::InvalidData("MLS signing key differs from verified contact"),
            ),
            Some(_) => Ok(user.to_vec()),
        }
    }
}
impl IdentityProvider for VerifiedIdentityProvider {
    type Error = StoreError;
    fn validate_member(
        &self,
        identity: &SigningIdentity,
        _: Option<MlsTime>,
        _: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.verify(identity).map(|_| ())
    }
    fn validate_external_sender(
        &self,
        _: &SigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Err(StoreError::InvalidData(
            "external MLS senders are unsupported",
        ))
    }
    fn identity(
        &self,
        identity: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        self.verify(identity)
    }
    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        self.verify(predecessor)?;
        self.verify(successor)?;
        Ok(predecessor == successor)
    }
    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grotto_mls::generate_key_material;
    use mls_rs_core::{crypto::SignaturePublicKey, identity::BasicCredential};
    #[test]
    fn signatures_fingerprints_changed_keys_and_claimed_names_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ClientStore::open(&dir.path().join("private/client.db")).unwrap());
        let keys = generate_key_material().unwrap();
        store.save_mls_identity(&keys.public, &keys.secret).unwrap();
        let card = ContactCard::own(&store).unwrap();
        assert!(card.import(&store, &"00".repeat(32)).is_err());
        card.import(&store, &card.fingerprint()).unwrap();
        let mut tampered = card.clone();
        tampered.mls_key[0] ^= 1;
        assert!(ContactCard::parse(&tampered.encode()).is_err());
        let signer = store.identity().unwrap();
        tampered.signature = signer.signing_key().sign(&tampered.transcript()).to_bytes();
        assert!(tampered.import(&store, &tampered.fingerprint()).is_err());
        let provider = VerifiedIdentityProvider(store);
        let identity = SigningIdentity::new(
            BasicCredential::new(card.user.to_bytes().to_vec()).into_credential(),
            SignaturePublicKey::new(card.mls_key.to_vec()),
        );
        assert!(provider.verify(&identity).is_ok());
        let substituted = SigningIdentity::new(
            identity.credential.clone(),
            SignaturePublicKey::new(tampered.mls_key.to_vec()),
        );
        assert!(provider.verify(&substituted).is_err());
        let wrong_name = SigningIdentity::new(
            BasicCredential::new(vec![9; 16]).into_credential(),
            identity.signature_key.clone(),
        );
        assert!(provider.verify(&wrong_name).is_err());
        assert!(ContactCard::parse(&"é".repeat(145)).is_err());
    }
}
