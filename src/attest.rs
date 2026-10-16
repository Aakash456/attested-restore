//! Attestation backend abstraction.
//!
//! A real deployment implements [`AttestationBackend`] against SEV-SNP
//! (VCEK-signed attestation reports via the PSP) or TDX (TD quotes via the
//! TDX module / Quoting Enclave). The protocol only needs two primitives:
//! a launch measurement binding (image, policy, nonce), and an unforgeable
//! signature. Everything else — chaining, epoch binding, verifier checks —
//! is hardware-independent and is the actual contribution of this prototype.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hardware attestation backend. Must be `Clone` so the backend can be
/// shared between the snapshot-issuing side and the verifier in demos.
pub trait AttestationBackend: Clone {
    /// Bind (image, policy, nonce) into a 32-byte launch measurement.
    fn launch_measurement(&self, image_id: &[u8], policy_digest: &[u8], nonce: &[u8]) -> [u8; 32];
    /// Unforgeable signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    /// Verify a signature produced by [`AttestationBackend::sign`].
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

/// Mock backend: HMAC-SHA256 under a fixed test key.
///
/// Stands in for PSP/SEAM-protected signing. The test key is compiled in and
/// must NEVER be used outside demos and tests; the `demo` CLI prints a
/// warning to this effect.
#[derive(Clone, Debug)]
pub struct MockBackend {
    key: [u8; 32],
}

impl MockBackend {
    /// Fixed, public, insecure test key. Demos and tests only.
    pub fn with_test_key() -> Self {
        Self {
            key: *b"0123456789abcdef0123456789abcdef",
        }
    }
}

impl AttestationBackend for MockBackend {
    fn launch_measurement(&self, image_id: &[u8], policy_digest: &[u8], nonce: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"AR-LAUNCH-v1");
        h.update((image_id.len() as u64).to_le_bytes());
        h.update(image_id);
        h.update(policy_digest);
        h.update((nonce.len() as u64).to_le_bytes());
        h.update(nonce);
        h.finalize().into()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"AR-SIGN-v1");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"AR-SIGN-v1");
        mac.update(msg);
        mac.verify_slice(sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let b = MockBackend::with_test_key();
        let sig = b.sign(b"hello");
        assert!(b.verify(b"hello", &sig));
    }

    #[test]
    fn tampered_message_fails_verify() {
        let b = MockBackend::with_test_key();
        let sig = b.sign(b"hello");
        assert!(!b.verify(b"hellp", &sig));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let b = MockBackend::with_test_key();
        let mut sig = b.sign(b"hello");
        sig[0] ^= 0xff;
        assert!(!b.verify(b"hello", &sig));
    }

    #[test]
    fn launch_measurement_is_deterministic_and_binding() {
        let b = MockBackend::with_test_key();
        let m1 = b.launch_measurement(b"img", &[1u8; 32], b"nonce");
        let m2 = b.launch_measurement(b"img", &[1u8; 32], b"nonce");
        let m3 = b.launch_measurement(b"img", &[2u8; 32], b"nonce");
        assert_eq!(m1, m2);
        assert_ne!(m1, m3);
    }
}
