//! Randomized freshness property test.
//!
//! This is the checkable core of the protocol's rollback-resistance claim:
//! across random sequences of snapshot/restore/replay operations, the
//! verifier must NEVER accept an epoch that is not strictly greater than
//! the last accepted epoch, and must always accept fresh, honestly-built
//! snapshots. Uses a hand-rolled seeded xorshift64* RNG (no extra crates).

use attested_restore::attest::MockBackend;
use attested_restore::counter::MockCounter;
use attested_restore::demo::demo_policy;
use attested_restore::protocol::{self, content_hash, genesis_hash, Snapshot};
use attested_restore::verifier::{RejectReason, Verifier};

/// xorshift64*: small, deterministic, good enough for test fuzzing.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1) // avoid the zero state
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn honest_snapshot(
    backend: &MockBackend,
    counter: &mut MockCounter,
    launch: &attested_restore::protocol::LaunchRecord,
    parent: &[u8; 32],
    policy: &attested_restore::policy::RestorePolicy,
    state_byte: u8,
    now: u64,
) -> Snapshot {
    let state = vec![state_byte; 64];
    protocol::snapshot(backend, counter, launch, parent, &state, policy, now)
}

#[test]
fn verifier_never_accepts_non_increasing_epoch() {
    let now = 1_700_000_600u64;
    for seed in 0..50u64 {
        let mut rng =
            Rng::new(0x9e3779b97f4a7c15u64.wrapping_add(seed.wrapping_mul(0x0010_0000_0001)));
        let backend = MockBackend::with_test_key();
        let policy = demo_policy();
        let launch = protocol::launch(&backend, b"prop-image", &policy, b"prop-nonce");
        let genesis = genesis_hash(&launch);
        let mut counter = MockCounter::new();
        let mut verifier = Verifier::new(backend.clone(), &launch);

        let mut created: Vec<Snapshot> = Vec::new();
        let mut accepted_epochs: Vec<u64> = Vec::new();
        let mut parent = genesis;

        for _step in 0..300 {
            if created.is_empty() || rng.below(100) < 55 {
                // Honest: fresh snapshot chained on the last accepted state.
                let snap = honest_snapshot(
                    &backend,
                    &mut counter,
                    &launch,
                    &parent,
                    &policy,
                    (created.len() % 251) as u8,
                    now,
                );
                created.push(snap.clone());
                let before = verifier.last_accepted_epoch();
                let res = verifier.verify_restore(&snap, now, "node-1");
                assert!(
                    res.is_ok(),
                    "seed {seed}: fresh honest snapshot (epoch {}) must accept, last={before}",
                    snap.epoch
                );
                assert!(snap.epoch > before);
                accepted_epochs.push(snap.epoch);
                parent = content_hash(&snap);
            } else {
                // Adversarial: restore a random previously created snapshot.
                // It may be an already-accepted epoch (replay) or a
                // never-restored one; the model decides the expectation.
                let idx = rng.below(created.len() as u64) as usize;
                let snap = &created[idx];
                let before = verifier.last_accepted_epoch();
                let expect_accept = snap.epoch > before;
                let res = verifier.verify_restore(snap, now, "node-1");
                assert_eq!(
                    res.is_ok(),
                    expect_accept,
                    "seed {seed}: epoch {} vs last {before}",
                    snap.epoch
                );
                if expect_accept {
                    accepted_epochs.push(snap.epoch);
                    parent = content_hash(snap);
                } else {
                    assert!(
                        matches!(res, Err(RejectReason::ReplayedEpoch { .. })),
                        "seed {seed}: non-increasing epoch must fail as replay, got {res:?}"
                    );
                }
            }
        }

        // Global invariant: accepted epochs are strictly increasing, so no
        // rollback was ever accepted.
        for w in accepted_epochs.windows(2) {
            assert!(
                w[0] < w[1],
                "seed {seed}: accepted epochs not strictly increasing: {w:?}"
            );
        }
        assert_eq!(
            verifier.last_accepted_epoch(),
            *accepted_epochs.last().unwrap()
        );
    }
}

#[test]
fn rng_is_deterministic() {
    let mut a = Rng::new(12345);
    let mut b = Rng::new(12345);
    for _ in 0..1000 {
        assert_eq!(a.next(), b.next());
    }
    let mut c = Rng::new(12346);
    assert_ne!(a.next(), c.next());
}
