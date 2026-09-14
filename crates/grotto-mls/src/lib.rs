//! Minimal mls-rs wrapper for Grotto.
//!
//! All operations are synchronous (mls-rs default `std` mode).
//! Callers on Tokio must wrap these in `spawn_blocking` — never hold
//! a SQLite mutex across `.await`.
//!
//! MLS signing keys are long-lived per client: generate once with
//! [`generate_key_material`], persist the bytes in the client store, and
//! rebuild with `*_with` constructors. The credential identity is the
//! Grotto `UserId`, binding MLS actions to the transport identity.

use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, MlsMessage,
    client_builder::MlsConfig,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    identity::{
        SigningIdentity,
        basic::{BasicCredential, BasicIdentityProvider},
    },
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use mls_rs_provider_sqlite::{
    SqLiteDataStorageEngine,
    connection_strategy::{
        CipheredConnectionStrategy, ConnectionStrategy, FileConnectionStrategy, MemoryStrategy,
        SqlCipherConfig, SqlCipherKey,
    },
};

/// Recommended suite for max compat (AWS-LC supports 1,2,3,5,7).
pub const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Long-lived MLS signing keypair, persistable as opaque bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MlsKeyMaterial {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// Generate a fresh signing keypair for [`CIPHER_SUITE`].
pub fn generate_key_material() -> Result<MlsKeyMaterial, Box<dyn std::error::Error + Send + Sync>> {
    let crypto = AwsLcCryptoProvider::default();
    let provider = crypto
        .cipher_suite_provider(CIPHER_SUITE)
        .ok_or("cipher suite not supported by AWS-LC")?;
    let (secret, public) = provider
        .signature_key_generate()
        .map_err(|e| format!("signature keygen failed: {e:?}"))?;
    Ok(MlsKeyMaterial {
        public: public.as_bytes().to_vec(),
        secret: secret.as_bytes().to_vec(),
    })
}

fn build_client(
    name: &[u8],
    keys: MlsKeyMaterial,
    engine: SqLiteDataStorageEngine<impl ConnectionStrategy + Send + Sync + 'static>,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let crypto = AwsLcCryptoProvider::default();
    let credential = BasicCredential::new(name.to_vec());
    let identity = SigningIdentity::new(
        credential.into_credential(),
        SignaturePublicKey::new(keys.public),
    );

    let client = Client::builder()
        .group_state_storage(
            engine
                .group_state_storage()
                .map_err(|e| format!("group storage failed: {e:?}"))?,
        )
        .key_package_repo(
            engine
                .key_package_storage()
                .map_err(|e| format!("keypackage storage failed: {e:?}"))?,
        )
        .psk_store(
            engine
                .pre_shared_key_storage()
                .map_err(|e| format!("psk storage failed: {e:?}"))?,
        )
        .crypto_provider(crypto)
        .identity_provider(BasicIdentityProvider)
        .signing_identity(identity, SignatureSecretKey::new(keys.secret), CIPHER_SUITE)
        .build();

    Ok(client)
}

/// Create a file-backed client with a stable identity (plain SQLite).
pub fn new_file_client_with(
    db_path: &std::path::Path,
    credential: &[u8],
    keys: MlsKeyMaterial,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let engine = SqLiteDataStorageEngine::new(FileConnectionStrategy::new(db_path))
        .map_err(|e| format!("sqlite file engine failed: {e:?}"))?;
    build_client(credential, keys, engine)
}

/// Create an in-memory client with a stable identity.
pub fn new_memory_client_with(
    credential: &[u8],
    keys: MlsKeyMaterial,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let engine = SqLiteDataStorageEngine::new(MemoryStrategy)
        .map_err(|e| format!("sqlite memory engine failed: {e:?}"))?;
    build_client(credential, keys, engine)
}

/// Create a file-backed encrypted client with a stable identity.
pub fn new_encrypted_file_client_with(
    db_path: &std::path::Path,
    password: &str,
    credential: &[u8],
    keys: MlsKeyMaterial,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let strategy = CipheredConnectionStrategy::new(
        FileConnectionStrategy::new(db_path),
        SqlCipherConfig::new(SqlCipherKey::Passphrase(password.to_owned())),
    );
    let engine = SqLiteDataStorageEngine::new(strategy)
        .map_err(|e| format!("sqlite encrypted engine failed: {e:?}"))?;
    build_client(credential, keys, engine)
}

/// Create an in-memory client with a fresh ephemeral identity (spike/tests).
pub fn new_memory_client(
    name: &str,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let keys = generate_key_material()?;
    new_memory_client_with(name.as_bytes(), keys)
}

/// Create a file-backed encrypted client with a fresh identity (spike/tests).
pub fn new_encrypted_file_client(
    name: &str,
    db_path: &std::path::Path,
    password: &str,
) -> Result<Client<impl MlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let keys = generate_key_material()?;
    new_encrypted_file_client_with(db_path, password, name.as_bytes(), keys)
}

/// Serialize helpers for transport over the existing postcard frame layer.
pub fn to_wire(msg: &MlsMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    msg.to_bytes()
        .map_err(|e| format!("mls serialize failed: {e:?}").into())
}

pub fn from_wire(bytes: &[u8]) -> Result<MlsMessage, Box<dyn std::error::Error + Send + Sync>> {
    let message = MlsMessage::from_bytes(bytes).map_err(|e| format!("mls parse failed: {e:?}"))?;
    if to_wire(&message)? != bytes {
        return Err("noncanonical or trailing MLS bytes".into());
    }
    Ok(message)
}

pub fn default_extensions() -> (ExtensionList, ExtensionList) {
    (ExtensionList::default(), ExtensionList::default())
}

/// Build a client over caller-owned storage and identity validation. The caller
/// supplies the transaction boundary; no separate SQLite connection is opened.
pub fn new_client_with_providers<G, K, I>(
    credential: &[u8],
    keys: MlsKeyMaterial,
    groups: G,
    packages: K,
    identities: I,
) -> Client<impl MlsConfig + use<G, K, I>>
where
    G: mls_rs::GroupStateStorage + Clone,
    K: mls_rs::KeyPackageStorage + Clone,
    I: mls_rs::IdentityProvider + Clone,
{
    Client::builder()
        .group_state_storage(groups)
        .key_package_repo(packages)
        .crypto_provider(AwsLcCryptoProvider::default())
        .identity_provider(identities)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(credential.to_vec()).into_credential(),
                SignaturePublicKey::new(keys.public),
            ),
            SignatureSecretKey::new(keys.secret),
            CIPHER_SUITE,
        )
        .build()
}
