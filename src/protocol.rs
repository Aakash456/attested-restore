//! Protocol types and snapshot issuance.
//!
//! Canonical encodings are documented in DESIGN.md. The snapshot flow:
//!
//! 1. `epoch = counter.next_epoch()` (trusted, monotonic).
//! 2. `state_hash = SHA256(state_ciphertext)` — state stays opaque in this
//!    prototype (no real memory-encryption import path; see DESIGN.md).
//! 3. `prev_hash` = content hash of the parent snapshot, or the genesis
//!    hash (hash of the launch record) for the first snapshot.
//! 4. The backend signs the canonical message
//!    `launch_measurement || epoch || state_hash || prev_hash ||
//!     policy_digest || created_at_secs`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attest::AttestationBackend;
use crate::counter::EpochCounter;
use crate::policy::RestorePolicy;

/// Root of the snapshot hash chain. `epoch` is always 0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRecord {
    pub launch_measurement: [u8; 32],
    pub epoch: u64,
    pub policy_digest: [u8; 32],
}

/// A single attested snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub epoch: u64,
    /// Opaque guest state. NOT inspected by the verifier in this prototype;
    /// only `state_hash` is attested. Real deployments need the
    /// encrypted-memory import path (see DESIGN.md).
    pub state_ciphertext: Vec<u8>,
    pub state_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub policy: RestorePolicy,
    /// Backend-stamped creation time (seconds). Covered by the attestation
    /// so the host cannot backdate it.
    pub created_at_secs: u64,
    /// Backend signature over [`signed_content`].
    pub attestation: Vec<u8>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Canonical encoding of a launch record.
pub fn launch_record_encoding(rec: &LaunchRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(72);
    v.extend_from_slice(&rec.launch_measurement);
    push_u64(&mut v, rec.epoch);
    v.extend_from_slice(&rec.policy_digest);
    v
}

/// Genesis hash: the chain root every first snapshot must reference.
pub fn genesis_hash(launch: &LaunchRecord) -> [u8; 32] {
    sha256(&launch_record_encoding(launch))
}

/// Canonical content of a snapshot for chaining (excludes the attestation
/// signature itself to avoid circularity):
/// `epoch || state_hash || prev_hash || policy_digest || created_at_secs`.
pub fn snapshot_content(snap: &Snapshot) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 32 * 3 + 8);
    push_u64(&mut v, snap.epoch);
    v.extend_from_slice(&snap.state_hash);
    v.extend_from_slice(&snap.prev_hash);
    v.extend_from_slice(&snap.policy.digest());
    push_u64(&mut v, snap.created_at_secs);
    v
}

/// Content hash used as the `prev_hash` of the next snapshot in the chain.
pub fn content_hash(snap: &Snapshot) -> [u8; 32] {
    sha256(&snapshot_content(snap))
}

/// Exact bytes the backend signs:
/// `launch_measurement || epoch || state_hash || prev_hash || policy_digest
///  || created_at_secs`.
pub fn signed_content(launch_measurement: &[u8; 32], snap: &Snapshot) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 8 + 32 * 3 + 8);
    v.extend_from_slice(launch_measurement);
    push_u64(&mut v, snap.epoch);
    v.extend_from_slice(&snap.state_hash);
    v.extend_from_slice(&snap.prev_hash);
    v.extend_from_slice(&snap.policy.digest());
    push_u64(&mut v, snap.created_at_secs);
    v
}

/// Issue a new attested snapshot. Draws a fresh epoch from the trusted
/// counter and has the backend sign the canonical content.
pub fn snapshot<B: AttestationBackend, C: EpochCounter>(
    backend: &B,
    counter: &mut C,
    launch: &LaunchRecord,
    parent_hash: &[u8; 32],
    state: &[u8],
    policy: &RestorePolicy,
    created_at_secs: u64,
) -> Snapshot {
    let epoch = counter.next_epoch();
    let snap = Snapshot {
        epoch,
        state_ciphertext: state.to_vec(),
        state_hash: sha256(state),
        prev_hash: *parent_hash,
        policy: policy.clone(),
        created_at_secs,
        attestation: Vec::new(), // filled below
    };
    let msg = signed_content(&launch.launch_measurement, &snap);
    let attestation = backend.sign(&msg);
    Snapshot {
        attestation,
        ..snap
    }
}

/// Build the launch record for a fresh confidential VM.
pub fn launch<B: AttestationBackend>(
    backend: &B,
    image_id: &[u8],
    policy: &RestorePolicy,
    nonce: &[u8],
) -> LaunchRecord {
    let policy_digest = policy.digest();
    LaunchRecord {
        launch_measurement: backend.launch_measurement(image_id, &policy_digest, nonce),
        epoch: 0,
        policy_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::MockBackend;
    use crate::counter::MockCounter;

    fn setup() -> (MockBackend, MockCounter, RestorePolicy, LaunchRecord) {
        let backend = MockBackend::with_test_key();
        let policy = RestorePolicy {
            max_snapshot_age_secs: 3600,
            authorized_restorers: vec!["node-1".to_string()],
        };
        let launch = launch(&backend, b"image-v1", &policy, b"nonce-1");
        (backend, MockCounter::new(), policy, launch)
    }

    #[test]
    fn first_snapshot_references_genesis() {
        let (backend, mut counter, policy, launch) = setup();
        let genesis = genesis_hash(&launch);
        let snap = snapshot(
            &backend,
            &mut counter,
            &launch,
            &genesis,
            b"state",
            &policy,
            1000,
        );
        assert_eq!(snap.epoch, 1);
        assert_eq!(snap.prev_hash, genesis);
        // The attestation verifies against the launch measurement.
        let msg = signed_content(&launch.launch_measurement, &snap);
        assert!(backend.verify(&msg, &snap.attestation));
    }

    #[test]
    fn chain_links_snapshots() {
        let (backend, mut counter, policy, launch) = setup();
        let genesis = genesis_hash(&launch);
        let s1 = snapshot(
            &backend,
            &mut counter,
            &launch,
            &genesis,
            b"s1",
            &policy,
            1000,
        );
        let s2 = snapshot(
            &backend,
            &mut counter,
            &launch,
            &content_hash(&s1),
            b"s2",
            &policy,
            1100,
        );
        assert_eq!(s2.prev_hash, content_hash(&s1));
        assert_eq!((s1.epoch, s2.epoch), (1, 2));
    }

    #[test]
    fn state_hash_binds_state() {
        let (backend, mut counter, policy, launch) = setup();
        let genesis = genesis_hash(&launch);
        let s1 = snapshot(
            &backend,
            &mut counter,
            &launch,
            &genesis,
            b"a",
            &policy,
            1000,
        );
        let s2 = snapshot(
            &backend,
            &mut counter,
            &launch,
            &genesis,
            b"b",
            &policy,
            1000,
        );
        assert_ne!(s1.state_hash, s2.state_hash);
    }
}
