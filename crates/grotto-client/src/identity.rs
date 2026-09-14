//! Transport identity material is stored atomically in ClientStore.
use ed25519_dalek::SigningKey;
use grotto_protocol::UserId;
use std::{env, fmt, path::PathBuf};

pub struct ClientIdentity {
    user_id: UserId,
    signing_key: SigningKey,
}
impl ClientIdentity {
    pub(crate) fn from_seed(user_id: UserId, seed: [u8; 32]) -> Self {
        Self {
            user_id,
            signing_key: SigningKey::from_bytes(&seed),
        }
    }
    pub fn user_id(&self) -> UserId {
        self.user_id
    }
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}
#[derive(Debug)]
pub enum IdentityError {
    InvalidState(String),
}
impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for IdentityError {}

pub(crate) fn default_identity_directory() -> Result<PathBuf, IdentityError> {
    if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
        let data_home = PathBuf::from(data_home);
        if data_home.is_absolute() {
            return Ok(data_home.join("grotto"));
        }
    }

    let home = env::var_os("HOME").ok_or_else(|| {
        IdentityError::InvalidState(
            "cannot locate identity directory: neither absolute XDG_DATA_HOME nor HOME is set"
                .to_owned(),
        )
    })?;

    Ok(PathBuf::from(home).join(".local/share/grotto"))
}

/// Unified local identity, MLS, journal, and application database.
pub(crate) fn default_store_path() -> Result<PathBuf, IdentityError> {
    default_identity_directory().map(|directory| directory.join("client.db"))
}
