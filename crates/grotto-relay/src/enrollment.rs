use crate::storage::{Registration, RelayState, StorageError};
use grotto_protocol::{
    AuthenticationChallenge, Ed25519PublicKeyBytes, UserId, cert_fingerprint_sha256_hex,
    parse_fingerprint_hex,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
fn hash(bytes: &[u8]) -> [u8; 32] {
    parse_fingerprint_hex(&cert_fingerprint_sha256_hex(bytes)).expect("generated SHA256 hex")
}
impl RelayState {
    pub fn issue_enrollment(
        &self,
        user: UserId,
        fingerprint: [u8; 32],
    ) -> Result<String, StorageError> {
        let token =
            AuthenticationChallenge::generate().map_err(|e| StorageError::Random(e.to_string()))?;
        self.lock_connection()?.execute("INSERT INTO enrollment_tokens(hash,user_id,fingerprint,expires) VALUES(?1,?2,?3,unixepoch()+86400)",params![hash(token.as_bytes()).as_slice(),user.to_bytes().as_slice(),fingerprint.as_slice()])?;
        Ok(token
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
    pub fn register_enrolled_identity(
        &self,
        user: UserId,
        key: Ed25519PublicKeyBytes,
        token: Option<[u8; 32]>,
    ) -> Result<Registration, StorageError> {
        let mut connection = self.lock_connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT public_key FROM identities WHERE user_id=?1",
                [user.to_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != key.as_bytes() {
                return Err(StorageError::IdentityKeyConflict);
            }
            return Ok(Registration::Existing);
        }
        let token = token.ok_or(StorageError::EnrollmentRequired)?;
        let consumed=tx.execute("UPDATE enrollment_tokens SET consumed=1 WHERE hash=?1 AND user_id=?2 AND fingerprint=?3 AND expires>unixepoch() AND consumed=0",params![hash(&token).as_slice(),user.to_bytes().as_slice(),hash(key.as_bytes()).as_slice()])?;
        if consumed != 1 {
            return Err(StorageError::EnrollmentRequired);
        }
        tx.execute(
            "INSERT INTO identities VALUES(?1,?2)",
            params![user.to_bytes().as_slice(), key.as_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(Registration::New)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_is_bound_expiring_single_use_and_proof_registration_is_atomic() {
        let dir = crate::private_test_directory().unwrap();
        let state = RelayState::open(&dir.path().join("relay.db")).unwrap();
        let user = UserId::from_bytes([1; 16]);
        let key = Ed25519PublicKeyBytes::new([2; 32]);
        assert!(state.register_enrolled_identity(user, key, None).is_err());
        let text = state.issue_enrollment(user, hash(key.as_bytes())).unwrap();
        let token = parse_fingerprint_hex(&text).unwrap();
        assert!(
            state
                .register_enrolled_identity(UserId::from_bytes([3; 16]), key, Some(token))
                .is_err()
        );
        assert!(
            state
                .register_enrolled_identity(user, Ed25519PublicKeyBytes::new([4; 32]), Some(token))
                .is_err()
        );
        state.lock_connection().unwrap().execute_batch("CREATE TEMP TRIGGER fail_identity BEFORE INSERT ON identities BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            state
                .register_enrolled_identity(user, key, Some(token))
                .is_err()
        );
        state
            .lock_connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_identity")
            .unwrap();
        assert_eq!(
            state
                .register_enrolled_identity(user, key, Some(token))
                .unwrap(),
            Registration::New
        );
        assert_eq!(
            state.register_enrolled_identity(user, key, None).unwrap(),
            Registration::Existing
        );
        state
            .lock_connection()
            .unwrap()
            .execute("DELETE FROM identities", [])
            .unwrap();
        assert!(
            state
                .register_enrolled_identity(user, key, Some(token))
                .is_err()
        );
        let token =
            parse_fingerprint_hex(&state.issue_enrollment(user, hash(key.as_bytes())).unwrap())
                .unwrap();
        state
            .lock_connection()
            .unwrap()
            .execute("UPDATE enrollment_tokens SET expires=unixepoch()-1", [])
            .unwrap();
        assert!(
            state
                .register_enrolled_identity(user, key, Some(token))
                .is_err()
        );
    }
}
