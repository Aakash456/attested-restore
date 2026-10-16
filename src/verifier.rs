//! The verifier: the trusted party that decides whether a snapshot may be
//! restored.
//!
//! Checks run in a fixed order (see DESIGN.md):
//! 1. signature validity → [`RejectReason::BadSignature`]
//! 2. hash-chain lineage → [`RejectReason::BrokenChain`]
//! 3. freshness (strictly increasing epoch) → [`RejectReason::ReplayedEpoch`]
//! 4. policy compliance → [`RejectReason::StaleSnapshot`] /
//!    [`RejectReason::UnauthorizedRestorer`]

use crate::attest::AttestationBackend;
use crate::policy::PolicyError;
use crate::protocol::{content_hash, genesis_hash, signed_content, LaunchRecord, Snapshot};

/// Why a restore was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Attestation signature invalid (forgery or tampered signed fields).
    BadSignature,
    /// `prev_hash` is neither the genesis hash nor a previously accepted
    /// snapshot's content hash.
    BrokenChain,
    /// Epoch is not strictly greater than the last accepted epoch (replay).
    ReplayedEpoch { got: u64, last: u64 },
    /// Snapshot older than `max_snapshot_age_secs`.
    StaleSnapshot,
    /// Restorer not in the authorized set.
    UnauthorizedRestorer,
}

impl RejectReason {
    /// Stable machine-readable code used in the trace dataset.
    pub fn code(&self) -> &'static str {
        match self {
            RejectReason::BadSignature => "bad-signature",
            RejectReason::BrokenChain => "broken-chain",
            RejectReason::ReplayedEpoch { .. } => "replayed-epoch",
            RejectReason::StaleSnapshot => "stale-snapshot",
            RejectReason::UnauthorizedRestorer => "unauthorized-restorer",
        }
    }
}

/// What the verifier reports on accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptInfo {
    pub epoch: u64,
    pub state_hash: [u8; 32],
}

/// Trusted verifier, seeded with the genuine launch record.
pub struct Verifier<B: AttestationBackend> {
    backend: B,
    launch_measurement: [u8; 32],
    genesis: [u8; 32],
    accepted: Vec<[u8; 32]>,
    last_accepted_epoch: u64,
}

impl<B: AttestationBackend> Verifier<B> {
    pub fn new(backend: B, launch: &LaunchRecord) -> Self {
        Self {
            backend,
            launch_measurement: launch.launch_measurement,
            genesis: genesis_hash(launch),
            accepted: Vec::new(),
            last_accepted_epoch: launch.epoch, // 0: nothing accepted yet
        }
    }

    pub fn last_accepted_epoch(&self) -> u64 {
        self.last_accepted_epoch
    }

    /// Decide whether `snap` may be restored, enforcing the four checks in
    /// order. On accept, advances `last_accepted_epoch` and records the
    /// snapshot's content hash for future chain checks.
    pub fn verify_restore(
        &mut self,
        snap: &Snapshot,
        now_secs: u64,
        restorer_id: &str,
    ) -> Result<AcceptInfo, RejectReason> {
        // 1. Signature over the canonical content, bound to our launch.
        let msg = signed_content(&self.launch_measurement, snap);
        if !self.backend.verify(&msg, &snap.attestation) {
            return Err(RejectReason::BadSignature);
        }
        // 2. Chain lineage: parent must be genesis or a previously accepted snapshot.
        if snap.prev_hash != self.genesis && !self.accepted.contains(&snap.prev_hash) {
            return Err(RejectReason::BrokenChain);
        }
        // 3. Freshness: strictly increasing epochs defeat replay/rollback.
        if snap.epoch <= self.last_accepted_epoch {
            return Err(RejectReason::ReplayedEpoch {
                got: snap.epoch,
                last: self.last_accepted_epoch,
            });
        }
        // 4. Policy: age bound and authorized restorer.
        match snap
            .policy
            .check(snap.created_at_secs, now_secs, restorer_id)
        {
            Err(PolicyError::StaleSnapshot { .. }) => return Err(RejectReason::StaleSnapshot),
            Err(PolicyError::UnauthorizedRestorer { .. }) => {
                return Err(RejectReason::UnauthorizedRestorer)
            }
            Ok(()) => {}
        }
        // Accept.
        self.accepted.push(content_hash(snap));
        self.last_accepted_epoch = snap.epoch;
        Ok(AcceptInfo {
            epoch: snap.epoch,
            state_hash: snap.state_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::MockBackend;
    use crate::counter::MockCounter;
    use crate::policy::RestorePolicy;
    use crate::protocol::{genesis_hash, launch, snapshot};

    struct Fixture {
        backend: MockBackend,
        counter: MockCounter,
        policy: RestorePolicy,
        launch: LaunchRecord,
        genesis: [u8; 32],
        now: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let backend = MockBackend::with_test_key();
            let policy = RestorePolicy {
                max_snapshot_age_secs: 3600,
                authorized_restorers: vec!["node-1".to_string()],
            };
            let launch = launch(&backend, b"image-v1", &policy, b"nonce-1");
            let genesis = genesis_hash(&launch);
            Self {
                backend,
                counter: MockCounter::new(),
                policy,
                launch,
                genesis,
                now: 1_700_000_600,
            }
        }

        fn verifier(&self) -> Verifier<MockBackend> {
            Verifier::new(self.backend.clone(), &self.launch)
        }

        fn snap(&mut self, parent: &[u8; 32], state: &[u8], created_at: u64) -> Snapshot {
            snapshot(
                &self.backend,
                &mut self.counter,
                &self.launch,
                parent,
                state,
                &self.policy,
                created_at,
            )
        }
    }

    #[test]
    fn fresh_snapshot_accepts() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let s = f.snap(&genesis, b"state", f.now);
        let info = v.verify_restore(&s, f.now, "node-1").expect("accept");
        assert_eq!(info.epoch, 1);
        assert_eq!(v.last_accepted_epoch(), 1);
    }

    #[test]
    fn replay_of_old_epoch_rejected() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let s1 = f.snap(&genesis, b"s1", f.now);
        let h1 = crate::protocol::content_hash(&s1);
        let s2 = f.snap(&h1, b"s2", f.now);
        v.verify_restore(&s1, f.now, "node-1").unwrap();
        v.verify_restore(&s2, f.now, "node-1").unwrap();
        // Replay s1 after s2 was accepted.
        assert_eq!(
            v.verify_restore(&s1, f.now, "node-1"),
            Err(RejectReason::ReplayedEpoch { got: 1, last: 2 })
        );
    }

    #[test]
    fn forged_signature_rejected() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let mut s = f.snap(&genesis, b"s", f.now);
        s.attestation[0] ^= 0xff;
        assert_eq!(
            v.verify_restore(&s, f.now, "node-1"),
            Err(RejectReason::BadSignature)
        );
    }

    #[test]
    fn broken_chain_rejected() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        // Validly signed, but parent hash is unknown to the verifier.
        let bogus = [0xAAu8; 32];
        let s = f.snap(&bogus, b"s", f.now);
        assert_eq!(
            v.verify_restore(&s, f.now, "node-1"),
            Err(RejectReason::BrokenChain)
        );
    }

    #[test]
    fn tampered_state_hash_rejected_as_bad_signature() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let mut s = f.snap(&genesis, b"s", f.now);
        s.state_hash[0] ^= 0x01; // state_hash is a signed field
        assert_eq!(
            v.verify_restore(&s, f.now, "node-1"),
            Err(RejectReason::BadSignature)
        );
    }

    #[test]
    fn stale_snapshot_rejected() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        // Created 3700s ago; max age is 3600s.
        let s = f.snap(&genesis, b"s", f.now - 3700);
        assert_eq!(
            v.verify_restore(&s, f.now, "node-1"),
            Err(RejectReason::StaleSnapshot)
        );
    }

    #[test]
    fn unauthorized_restorer_rejected() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let s = f.snap(&genesis, b"s", f.now);
        assert_eq!(
            v.verify_restore(&s, f.now, "mallory"),
            Err(RejectReason::UnauthorizedRestorer)
        );
    }

    #[test]
    fn rejection_does_not_advance_epoch() {
        let mut f = Fixture::new();
        let mut v = f.verifier();
        let genesis = f.genesis;
        let bad = f.snap(&[0xAAu8; 32], b"s", f.now); // broken chain
        assert!(v.verify_restore(&bad, f.now, "node-1").is_err());
        assert_eq!(v.last_accepted_epoch(), 0);
        // A subsequent honest snapshot still chains from genesis and accepts.
        let s = f.snap(&genesis, b"s", f.now);
        assert!(v.verify_restore(&s, f.now, "node-1").is_ok());
    }
}
