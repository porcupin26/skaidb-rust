//! SCRAM-SHA-256 credentials and proof verification (SPEC §8.1, RFC 5802).
//!
//! The server stores only a *verifier* — salt, iteration count, `StoredKey`,
//! and `ServerKey` — never the password. Authentication verifies the client's
//! proof against the stored keys and returns the server signature for mutual
//! authentication. The cryptographic core is exact RFC 5802; the textual
//! message framing (base64, GS2 header) sits above this and is left to the
//! transport layer.

use crate::crypto::{ct_eq, hex, hmac_sha256, pbkdf2_hmac_sha256, random_bytes, sha256};

/// Default PBKDF2 iteration count for new credentials.
pub const DEFAULT_ITERATIONS: u32 = 15_000;

/// Salt length for new credentials, in bytes (RFC 5802 sets no minimum;
/// 16 matches what the deterministic scheme this replaced produced).
const SALT_LEN: usize = 16;

/// A fresh random salt for a NEW credential.
///
/// Salts were derived from the username (`SHA256("skaidb-salt:" || name)`),
/// which is precomputable by anyone who knows the username and identical
/// across every deployment — so one rainbow table per common username
/// covered every skaidb in existence, which is precisely what a salt is
/// supposed to make impossible (2026-08-01 audit). The iteration count was
/// the only real barrier left.
///
/// No storage change was needed: the salt already travels inside
/// [`ScramCredential::encode`], so it persists with the verifier and
/// replicates with it. Credentials written under the old scheme keep
/// working untouched — the salt is read from the stored verifier, never
/// re-derived — they simply do not gain the benefit until the password is
/// next set.
pub fn random_salt() -> Vec<u8> {
    random_bytes::<SALT_LEN>().to_vec()
}

/// A stored SCRAM-SHA-256 verifier for one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramCredential {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl ScramCredential {
    /// Encode as `iterations:salt_hex:stored_hex:server_hex` — the stable
    /// storage/replication form (no plaintext material).
    pub fn encode(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.iterations,
            hex(&self.salt),
            hex(&self.stored_key),
            hex(&self.server_key)
        )
    }

    /// Decode [`ScramCredential::encode`]'s form.
    pub fn decode(s: &str) -> Option<ScramCredential> {
        let mut parts = s.split(':');
        let iterations: u32 = parts.next()?.parse().ok()?;
        let salt = unhex(parts.next()?)?;
        let stored_key: [u8; 32] = unhex(parts.next()?)?.try_into().ok()?;
        let server_key: [u8; 32] = unhex(parts.next()?)?.try_into().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(ScramCredential {
            salt,
            iterations,
            stored_key,
            server_key,
        })
    }

    /// Derive a verifier from a password, salt, and iteration count.
    pub fn new(password: &str, salt: &[u8], iterations: u32) -> ScramCredential {
        let salted = pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let server_key = hmac_sha256(&salted, b"Server Key");
        ScramCredential {
            salt: salt.to_vec(),
            iterations,
            stored_key,
            server_key,
        }
    }

    /// Verify a client's proof over `auth_message`. On success returns the
    /// `ServerSignature` the client can check for mutual authentication.
    pub fn verify(&self, auth_message: &[u8], client_proof: &[u8; 32]) -> Option<[u8; 32]> {
        let client_signature = hmac_sha256(&self.stored_key, auth_message);
        // ClientKey = ClientProof XOR ClientSignature
        let mut client_key = [0u8; 32];
        for i in 0..32 {
            client_key[i] = client_proof[i] ^ client_signature[i];
        }
        if ct_eq(&sha256(&client_key), &self.stored_key) {
            Some(hmac_sha256(&self.server_key, auth_message))
        } else {
            None
        }
    }

    /// Serialize for storage: `SCRAM-SHA-256$<iter>$<salt_hex>$<stored_hex>$<server_hex>`.
    pub fn to_storage_string(&self) -> String {
        format!(
            "SCRAM-SHA-256${}${}${}${}",
            self.iterations,
            hex(&self.salt),
            hex(&self.stored_key),
            hex(&self.server_key)
        )
    }

    /// Parse a verifier produced by [`ScramCredential::to_storage_string`].
    pub fn from_storage_string(s: &str) -> Option<ScramCredential> {
        let mut parts = s.split('$');
        if parts.next()? != "SCRAM-SHA-256" {
            return None;
        }
        let iterations = parts.next()?.parse().ok()?;
        let salt = from_hex(parts.next()?)?;
        let stored_key = from_hex(parts.next()?)?.try_into().ok()?;
        let server_key = from_hex(parts.next()?)?.try_into().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(ScramCredential {
            salt,
            iterations,
            stored_key,
            server_key,
        })
    }
}

/// Client-side: derive the PBKDF2 `SaltedPassword` — the expensive step
/// (15k HMAC iterations at the default). One handshake needs it for both
/// the proof and the server-signature check, and it is identical across
/// connections for the same (password, salt, iterations) — derive once,
/// reuse (see the driver's cache).
pub fn salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations)
}

/// Client-side: the `ClientProof` over `auth_message`, from a pre-derived
/// [`salted_password`]. Cheap (three HMAC/SHA passes).
pub fn client_proof_salted(salted: &[u8; 32], auth_message: &[u8]) -> [u8; 32] {
    let client_key = hmac_sha256(salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let client_signature = hmac_sha256(&stored_key, auth_message);
    let mut proof = [0u8; 32];
    for i in 0..32 {
        proof[i] = client_key[i] ^ client_signature[i];
    }
    proof
}

/// Client-side: the expected `ServerSignature`, from a pre-derived
/// [`salted_password`]. Cheap (two HMAC passes).
pub fn server_signature_salted(salted: &[u8; 32], auth_message: &[u8]) -> [u8; 32] {
    let server_key = hmac_sha256(salted, b"Server Key");
    hmac_sha256(&server_key, auth_message)
}

/// Client-side: compute the `ClientProof` over `auth_message` for a password.
pub fn client_proof(password: &str, salt: &[u8], iterations: u32, auth_message: &[u8]) -> [u8; 32] {
    client_proof_salted(&salted_password(password, salt, iterations), auth_message)
}

/// Client-side: the expected `ServerSignature` for mutual authentication.
pub fn server_signature(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> [u8; 32] {
    server_signature_salted(&salted_password(password, salt, iterations), auth_message)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}


fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"0123456789abcdef";

    #[test]
    fn correct_proof_authenticates_and_yields_server_sig() {
        let cred = ScramCredential::new("pencil", SALT, 4096);
        let auth_message = b"n=user,r=clientnonce,s=...,i=4096,c=biws,r=fullnonce";

        let proof = client_proof("pencil", SALT, 4096, auth_message);
        let server_sig = cred.verify(auth_message, &proof).expect("auth ok");

        // Client verifies the server signature (mutual auth).
        let expected = server_signature("pencil", SALT, 4096, auth_message);
        assert_eq!(server_sig, expected);
    }

    #[test]
    fn wrong_password_fails() {
        let cred = ScramCredential::new("pencil", SALT, 4096);
        let auth_message = b"auth-message";
        let proof = client_proof("WRONG", SALT, 4096, auth_message);
        assert!(cred.verify(auth_message, &proof).is_none());
    }

    #[test]
    fn tampered_auth_message_fails() {
        let cred = ScramCredential::new("pencil", SALT, 4096);
        let proof = client_proof("pencil", SALT, 4096, b"original");
        assert!(cred.verify(b"tampered", &proof).is_none());
    }

    #[test]
    fn credential_storage_roundtrip() {
        let cred = ScramCredential::new("hunter2", SALT, DEFAULT_ITERATIONS);
        let s = cred.to_storage_string();
        assert_eq!(ScramCredential::from_storage_string(&s), Some(cred));
    }

    #[test]
    fn storage_string_has_no_plaintext() {
        let cred = ScramCredential::new("supersecret", SALT, 4096);
        assert!(!cred.to_storage_string().contains("supersecret"));
    }

    /// Salts used to be `SHA256("skaidb-salt:" || username)` — precomputable
    /// from the username alone and identical in every deployment, so one
    /// rainbow table per common username covered every install
    /// (2026-08-01 audit). Two credentials must not share a salt, even for
    /// the same password.
    #[test]
    fn salts_are_random_per_credential() {
        let salts: std::collections::HashSet<Vec<u8>> =
            (0..32).map(|_| random_salt()).collect();
        assert_eq!(salts.len(), 32, "random_salt repeated a draw");
        assert!(salts.iter().all(|s| s.len() == SALT_LEN));

        // Same password, two credentials: different salt AND different
        // stored key, so a precomputed table for one is useless for the
        // other.
        let a = ScramCredential::new("hunter2", &random_salt(), DEFAULT_ITERATIONS);
        let b = ScramCredential::new("hunter2", &random_salt(), DEFAULT_ITERATIONS);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.stored_key, b.stored_key);
    }

    /// Credentials written under the OLD deterministic scheme must keep
    /// authenticating untouched: the salt is read back from the stored
    /// verifier, never re-derived, so an upgrade must not lock anyone out.
    #[test]
    fn credentials_with_a_legacy_derived_salt_still_authenticate() {
        // Exactly what the old scheme produced for user "ada".
        let legacy_salt = sha256(b"skaidb-user:ada")[..16].to_vec();
        let stored = ScramCredential::new("pencil", &legacy_salt, DEFAULT_ITERATIONS).encode();

        // Round-trip through storage the way the catalog does...
        let cred = ScramCredential::decode(&stored).expect("legacy verifier decodes");
        assert_eq!(cred.salt, legacy_salt, "stored salt must be used as-is");

        // ...and the client's proof, computed against the ADVERTISED salt,
        // still verifies.
        let am = b"n=ada,r=cn.deadbeef";
        let proof = client_proof("pencil", &cred.salt, cred.iterations, am);
        assert!(cred.verify(am, &proof).is_some(), "legacy user locked out");
        let wrong = client_proof("WRONG", &cred.salt, cred.iterations, am);
        assert!(cred.verify(am, &wrong).is_none());
    }
}

