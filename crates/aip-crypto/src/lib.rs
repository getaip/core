//! Cryptographic support for AIP native messages.
//!
//! The crate provides deterministic canonical JSON, Ed25519 signatures,
//! DID-key conversion, receipt hash chains, and optional session encryption
//! primitives. It does not define authorization policy; that belongs in
//! `aip-auth`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use aip_core::{Envelope, Receipt, ReceiptChain};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Crypto operation error.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// JSON canonicalization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Signature input was malformed.
    #[error("signature error: {0}")]
    Signature(String),
    /// DID-key input was malformed.
    #[error("did error: {0}")]
    Did(String),
    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// Decryption failed.
    #[error("decryption failed")]
    Decrypt,
}

/// Result alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Ed25519 public key encoded as `did:key`.
pub const DID_KEY_PREFIX: &str = "did:key:z";

/// Returns deterministic JSON bytes with object keys sorted recursively.
///
/// This function does not omit fields. Callers that sign a structure containing
/// an embedded signature must remove exactly that protocol-defined field before
/// canonicalization. Removing every property named `signature` would leave
/// application payload fields outside the cryptographic integrity boundary.
pub fn canonical_json_bytes(value: &Value) -> CryptoResult<Vec<u8>> {
    let canonical = canonicalize(value);
    serde_json::to_vec(&canonical).map_err(CryptoError::from)
}

/// Converts a typed envelope into canonical signing bytes.
pub fn envelope_signing_bytes(envelope: &Envelope) -> CryptoResult<Vec<u8>> {
    let mut value = serde_json::to_value(envelope)?;
    if let Some(security) = value.get_mut("security").and_then(Value::as_object_mut) {
        security.remove("signature");
    }
    canonical_json_bytes(&value)
}

/// Signs an AIP envelope while excluding only `security.signature`.
pub fn sign_envelope(envelope: &Envelope, signing_key: &SigningKey) -> CryptoResult<String> {
    let bytes = envelope_signing_bytes(envelope)?;
    let signature: Signature = signing_key.sign(&bytes);
    Ok(BASE64_STANDARD.encode(signature.to_bytes()))
}

/// Verifies an AIP envelope signature over the complete envelope payload.
pub fn verify_envelope(
    envelope: &Envelope,
    signature_b64: &str,
    verifying_key: &VerifyingKey,
) -> CryptoResult<()> {
    let bytes = envelope_signing_bytes(envelope)?;
    verify_bytes(&bytes, signature_b64, verifying_key)
}

/// Signs a JSON value with Ed25519 and returns a base64 signature.
pub fn sign_value(value: &Value, signing_key: &SigningKey) -> CryptoResult<String> {
    let bytes = canonical_json_bytes(value)?;
    let signature: Signature = signing_key.sign(&bytes);
    Ok(BASE64_STANDARD.encode(signature.to_bytes()))
}

/// Verifies a base64 Ed25519 signature over a JSON value.
pub fn verify_value(
    value: &Value,
    signature_b64: &str,
    verifying_key: &VerifyingKey,
) -> CryptoResult<()> {
    let bytes = canonical_json_bytes(value)?;
    verify_bytes(&bytes, signature_b64, verifying_key)
}

fn verify_bytes(
    bytes: &[u8],
    signature_b64: &str,
    verifying_key: &VerifyingKey,
) -> CryptoResult<()> {
    let signature_bytes = BASE64_STANDARD
        .decode(signature_b64)
        .map_err(|error| CryptoError::Signature(error.to_string()))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|error| CryptoError::Signature(error.to_string()))?;
    verifying_key
        .verify(bytes, &signature)
        .map_err(|error| CryptoError::Signature(error.to_string()))
}

/// Creates a deterministic signing key from a 32-byte seed.
#[must_use]
pub fn signing_key_from_seed(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

/// Encodes an Ed25519 verifying key as a DID-key.
#[must_use]
pub fn did_key_from_verifying_key(key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(key.as_bytes());
    format!("{DID_KEY_PREFIX}{}", bs58::encode(bytes).into_string())
}

/// Decodes an Ed25519 verifying key from a DID-key.
pub fn verifying_key_from_did_key(did: &str) -> CryptoResult<VerifyingKey> {
    let encoded = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| CryptoError::Did("missing did:key prefix".to_owned()))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|error| CryptoError::Did(error.to_string()))?;
    if bytes.len() != 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(CryptoError::Did(
            "unsupported did:key multicodec".to_owned(),
        ));
    }
    let key_bytes: [u8; 32] = bytes[2..]
        .try_into()
        .map_err(|_| CryptoError::Did("invalid key length".to_owned()))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|error| CryptoError::Did(error.to_string()))
}

/// Public X25519 key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey {
    /// Raw public key bytes.
    pub bytes: [u8; 32],
}

/// Generates an ephemeral X25519 keypair.
#[must_use]
pub fn generate_ephemeral_keypair() -> (EphemeralSecret, X25519PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        secret,
        X25519PublicKey {
            bytes: public.to_bytes(),
        },
    )
}

/// Derives a 256-bit session key from X25519 ECDH and HKDF-SHA256.
pub fn derive_session_key(
    secret: EphemeralSecret,
    peer_public: X25519PublicKey,
    session_id: &str,
) -> CryptoResult<SessionCipher> {
    let peer = PublicKey::from(peer_public.bytes);
    let shared = secret.diffie_hellman(&peer);
    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(b"aip-session-v1", &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(SessionCipher { key })
}

/// AES-256-GCM session cipher.
#[derive(Clone, Debug)]
pub struct SessionCipher {
    key: [u8; 32],
}

impl SessionCipher {
    /// Creates a session cipher from raw key bytes.
    #[must_use]
    pub const fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypts plaintext with a 96-bit nonce and associated data.
    pub fn encrypt(&self, nonce: [u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::Encrypt)?;
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)
    }

    /// Decrypts ciphertext with a 96-bit nonce and associated data.
    pub fn decrypt(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::Decrypt)?;
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Computes the SHA-256 hash of a receipt without its current `hash` field.
pub fn hash_receipt(receipt: &Receipt) -> CryptoResult<String> {
    let mut clone = receipt.clone();
    clone.hash = None;
    let bytes = canonical_json_bytes(&serde_json::to_value(clone)?)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Appends a receipt to a chain and updates hash links.
pub fn append_receipt(chain: &mut ReceiptChain, mut receipt: Receipt) -> CryptoResult<()> {
    receipt.previous_hash = chain.receipts.last().and_then(|item| item.hash.clone());
    receipt.hash = Some(hash_receipt(&receipt)?);
    chain.receipts.push(receipt);
    chain.root_hash = Some(hash_receipt_chain(chain)?);
    Ok(())
}

/// Computes an aggregate hash for the receipt chain.
pub fn hash_receipt_chain(chain: &ReceiptChain) -> CryptoResult<String> {
    let hashes = chain
        .receipts
        .iter()
        .filter_map(|receipt| receipt.hash.as_deref())
        .collect::<Vec<_>>()
        .join("");
    Ok(hex::encode(Sha256::digest(hashes.as_bytes())))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(value) = object.get(&key) {
                    sorted.insert(key, canonicalize(value));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_json_bytes, did_key_from_verifying_key, sign_envelope, signing_key_from_seed,
        verify_envelope, verify_value, verifying_key_from_did_key,
    };
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_without_omitting_payload_fields() {
        let value = json!({"b": 1, "signature": "drop", "a": {"d": 4, "c": 3}});
        let bytes = canonical_json_bytes(&value).expect("canonical json");
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            r#"{"a":{"c":3,"d":4},"b":1,"signature":"drop"}"#
        );
    }

    #[test]
    fn did_key_round_trips() {
        let signing_key = signing_key_from_seed([7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let did = did_key_from_verifying_key(&verifying_key);
        assert_eq!(
            verifying_key_from_did_key(&did).expect("did key"),
            verifying_key
        );
    }

    #[test]
    fn signatures_verify() {
        let signing_key = signing_key_from_seed([9_u8; 32]);
        let value = json!({"hello": "world"});
        let signature = super::sign_value(&value, &signing_key).expect("signature");
        verify_value(&value, &signature, &signing_key.verifying_key()).expect("valid signature");
    }

    #[test]
    fn envelope_signature_covers_application_signature_fields() {
        let signing_key = signing_key_from_seed([11_u8; 32]);
        let mut envelope = aip_core::Envelope::new(aip_core::MessageBody::Action(Box::new(
            aip_core::Action::new(
                aip_core::CapabilityId::trusted("cap:test:signature"),
                json!({"signature": "business-value"}),
            ),
        )));
        envelope.security =
            Some(json!({"did": did_key_from_verifying_key(&signing_key.verifying_key())}));
        let signature = sign_envelope(&envelope, &signing_key).expect("signature");
        envelope
            .security
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("security")
            .insert("signature".to_owned(), json!(signature.clone()));
        verify_envelope(&envelope, &signature, &signing_key.verifying_key()).expect("valid");

        let aip_core::MessageBody::Action(action) = &mut envelope.body else {
            panic!("action body");
        };
        action.input["signature"] = json!("tampered");
        assert!(verify_envelope(&envelope, &signature, &signing_key.verifying_key()).is_err());
    }
}
