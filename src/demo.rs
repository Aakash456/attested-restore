//! Demo harness: honest and adversarial trials producing a trace dataset
//! suitable for publication (e.g., as an IEEE DataPort artifact).
//!
//! `run_demo` executes the full protocol end-to-end:
//! - honest restore trials across varying synthetic state sizes (1KB–64MB)
//!   and snapshot ages, recording per-trial accept decisions and latencies
//!   (snapshot creation, attestation signing, verification) in microseconds;
//! - adversarial trials: replay of an old epoch, forged signature, tampered
//!   chain parent, stale snapshot, unauthorized restorer — each must be
//!   rejected with the expected [`RejectReason`].
//!
//! `replay_trace` re-checks a recorded trace offline by re-running every
//! trial's verification deterministically and comparing decisions.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::attest::{AttestationBackend, MockBackend};
use crate::counter::MockCounter;
use crate::policy::RestorePolicy;
use crate::protocol::{self, LaunchRecord, Snapshot};
use crate::verifier::{RejectReason, Verifier};

pub const DEMO_IMAGE_ID: &[u8] = b"attested-restore-demo-image-v1";
pub const DEMO_NONCE: &[u8] = b"demo-nonce-0001";
pub const DEMO_MAX_AGE_SECS: u64 = 3600;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let v = unhex(s)?;
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatenciesUs {
    pub snapshot: u128,
    pub sign: u128,
    pub verify: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotView {
    pub epoch: u64,
    pub state_size_bytes: usize,
    pub state_hash_hex: String,
    pub prev_hash_hex: String,
    pub created_at_secs: u64,
    pub policy: RestorePolicy,
    pub attestation_hex: String,
}

/// The verifier never inspects `state_ciphertext` (only its attested hash),
/// so the trace omits the (potentially large) ciphertext and records its
/// size. This keeps the dataset small without affecting replay fidelity.
fn view_of(snap: &Snapshot, state_size: usize) -> SnapshotView {
    SnapshotView {
        epoch: snap.epoch,
        state_size_bytes: state_size,
        state_hash_hex: hex(&snap.state_hash),
        prev_hash_hex: hex(&snap.prev_hash),
        created_at_secs: snap.created_at_secs,
        policy: snap.policy.clone(),
        attestation_hex: hex(&snap.attestation),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialRecord {
    pub trial: usize,
    pub kind: String, // "honest" | "adversarial"
    pub attack: Option<String>,
    pub snapshot: SnapshotView,
    pub now_secs: u64,
    pub restorer_id: String,
    pub decision: String, // "accept" | "reject"
    pub reason: Option<String>,
    pub latency_us: LatenciesUs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFile {
    pub tool: String,
    pub version: String,
    pub created_unix: u64,
    pub backend: String,
    pub launch_image_id_hex: String,
    pub launch_nonce_hex: String,
    pub launch_measurement_hex: String,
    pub trials: Vec<TrialRecord>,
}

pub struct DemoConfig {
    pub seed: u64,
    pub state_sizes: Vec<usize>,
    pub base_time: u64,
}

pub fn demo_policy() -> RestorePolicy {
    RestorePolicy {
        max_snapshot_age_secs: DEMO_MAX_AGE_SECS,
        authorized_restorers: vec!["node-1".to_string(), "node-2".to_string()],
    }
}

/// Deterministic synthetic guest state.
fn demo_state(seed: u64, idx: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|j| {
            seed.wrapping_add(idx as u64 * 31)
                .wrapping_add(j as u64 * 7)
                .rem_euclid(251) as u8
        })
        .collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn record(
    trial: usize,
    kind: &str,
    attack: Option<&str>,
    snap: &Snapshot,
    state_size: usize,
    now_secs: u64,
    restorer_id: &str,
    decision: &str,
    reason: Option<&str>,
    latency_us: LatenciesUs,
) -> TrialRecord {
    TrialRecord {
        trial,
        kind: kind.to_string(),
        attack: attack.map(str::to_string),
        snapshot: view_of(snap, state_size),
        now_secs,
        restorer_id: restorer_id.to_string(),
        decision: decision.to_string(),
        reason: reason.map(str::to_string),
        latency_us,
    }
}

/// Run the full demo: honest trials, adversarial trials, recovery trials.
/// Panics if any trial's outcome differs from the protocol's specification
/// (the demo is self-checking).
pub fn run_demo(cfg: &DemoConfig) -> TraceFile {
    assert!(
        cfg.state_sizes.len() >= 3,
        "demo needs at least 3 state sizes"
    );
    let backend = MockBackend::with_test_key();
    let policy = demo_policy();
    let launch: LaunchRecord = protocol::launch(&backend, DEMO_IMAGE_ID, &policy, DEMO_NONCE);
    let genesis = protocol::genesis_hash(&launch);
    let mut counter = MockCounter::new();
    let mut verifier = Verifier::new(backend.clone(), &launch);
    let now = cfg.base_time + 600;

    let mut trials = Vec::new();
    let mut trial_no = 0usize;
    let mut parent = genesis;
    let mut accepted: Vec<Snapshot> = Vec::new();

    // (a) Honest trials across state sizes and ages.
    for (i, &size) in cfg.state_sizes.iter().enumerate() {
        trial_no += 1;
        let state = demo_state(cfg.seed, i, size);
        let created_at = cfg.base_time + (i as u64) * 30;
        let t0 = Instant::now();
        let snap = protocol::snapshot(
            &backend,
            &mut counter,
            &launch,
            &parent,
            &state,
            &policy,
            created_at,
        );
        let t_snapshot = t0.elapsed();
        // Attestation component, measured separately on identical content.
        let t1 = Instant::now();
        let _ = backend.sign(&protocol::signed_content(&launch.launch_measurement, &snap));
        let t_sign = t1.elapsed();
        let t2 = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-1");
        let t_verify = t2.elapsed();
        assert!(res.is_ok(), "honest trial {trial_no} must accept: {res:?}");
        parent = protocol::content_hash(&snap);
        accepted.push(snap.clone());
        trials.push(record(
            trial_no,
            "honest",
            None,
            &snap,
            size,
            now,
            "node-1",
            "accept",
            None,
            LatenciesUs {
                snapshot: t_snapshot.as_micros(),
                sign: t_sign.as_micros(),
                verify: t_verify.as_micros(),
            },
        ));
    }

    // (b) Adversarial trials.
    // A1: replay — re-verify an old accepted epoch after later ones accepted.
    {
        trial_no += 1;
        let snap = accepted[1].clone(); // epoch 2
        let last = verifier.last_accepted_epoch();
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-1");
        let dt = t.elapsed();
        assert_eq!(
            res,
            Err(RejectReason::ReplayedEpoch {
                got: snap.epoch,
                last
            }),
            "replay must be rejected"
        );
        trials.push(record(
            trial_no,
            "adversarial",
            Some("replay-old-epoch"),
            &snap,
            0,
            now,
            "node-1",
            "reject",
            Some(RejectReason::ReplayedEpoch { got: 0, last: 0 }.code()),
            LatenciesUs {
                snapshot: 0,
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }
    // A2: forged signature — flip a byte of a valid attestation.
    {
        trial_no += 1;
        let mut snap = accepted[2].clone();
        snap.attestation[0] ^= 0xff;
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-1");
        let dt = t.elapsed();
        assert_eq!(res, Err(RejectReason::BadSignature));
        trials.push(record(
            trial_no,
            "adversarial",
            Some("forged-signature"),
            &snap,
            0,
            now,
            "node-1",
            "reject",
            Some(RejectReason::BadSignature.code()),
            LatenciesUs {
                snapshot: 0,
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }
    // A3: broken chain — validly signed, but parent unknown to the verifier.
    {
        trial_no += 1;
        let bogus = [0xAAu8; 32];
        let state = demo_state(cfg.seed, 900, 1024);
        let t0 = Instant::now();
        let snap = protocol::snapshot(
            &backend,
            &mut counter,
            &launch,
            &bogus,
            &state,
            &policy,
            now,
        );
        let t_snapshot = t0.elapsed();
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-1");
        let dt = t.elapsed();
        assert_eq!(res, Err(RejectReason::BrokenChain));
        trials.push(record(
            trial_no,
            "adversarial",
            Some("broken-chain"),
            &snap,
            state.len(),
            now,
            "node-1",
            "reject",
            Some(RejectReason::BrokenChain.code()),
            LatenciesUs {
                snapshot: t_snapshot.as_micros(),
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }
    // A4: stale snapshot — fresh epoch, but older than max age.
    {
        trial_no += 1;
        let state = demo_state(cfg.seed, 901, 1024);
        let t0 = Instant::now();
        let snap = protocol::snapshot(
            &backend,
            &mut counter,
            &launch,
            &parent,
            &state,
            &policy,
            now - DEMO_MAX_AGE_SECS - 300,
        );
        let t_snapshot = t0.elapsed();
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-1");
        let dt = t.elapsed();
        assert_eq!(res, Err(RejectReason::StaleSnapshot));
        trials.push(record(
            trial_no,
            "adversarial",
            Some("stale-snapshot"),
            &snap,
            state.len(),
            now,
            "node-1",
            "reject",
            Some(RejectReason::StaleSnapshot.code()),
            LatenciesUs {
                snapshot: t_snapshot.as_micros(),
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }
    // A5: unauthorized restorer.
    {
        trial_no += 1;
        let state = demo_state(cfg.seed, 902, 1024);
        let t0 = Instant::now();
        let snap = protocol::snapshot(
            &backend,
            &mut counter,
            &launch,
            &parent,
            &state,
            &policy,
            now,
        );
        let t_snapshot = t0.elapsed();
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "mallory-node");
        let dt = t.elapsed();
        assert_eq!(res, Err(RejectReason::UnauthorizedRestorer));
        trials.push(record(
            trial_no,
            "adversarial",
            Some("unauthorized-restorer"),
            &snap,
            state.len(),
            now,
            "mallory-node",
            "reject",
            Some(RejectReason::UnauthorizedRestorer.code()),
            LatenciesUs {
                snapshot: t_snapshot.as_micros(),
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }

    // (c) Recovery: honest trials still accept after the attacks.
    for (j, &size) in cfg.state_sizes.iter().take(2).enumerate() {
        trial_no += 1;
        let state = demo_state(cfg.seed, 1000 + j, size);
        let snap = protocol::snapshot(
            &backend,
            &mut counter,
            &launch,
            &parent,
            &state,
            &policy,
            now,
        );
        let t = Instant::now();
        let res = verifier.verify_restore(&snap, now, "node-2");
        let dt = t.elapsed();
        assert!(res.is_ok(), "recovery trial {trial_no} must accept");
        parent = protocol::content_hash(&snap);
        trials.push(record(
            trial_no,
            "honest",
            Some("post-attack-recovery"),
            &snap,
            size,
            now,
            "node-2",
            "accept",
            None,
            LatenciesUs {
                snapshot: 0,
                sign: 0,
                verify: dt.as_micros(),
            },
        ));
    }

    TraceFile {
        tool: "attested-restore".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_unix: now_unix(),
        backend: "mock-hmac-sha256 (TEST KEY — not for production use)".to_string(),
        launch_image_id_hex: hex(DEMO_IMAGE_ID),
        launch_nonce_hex: hex(DEMO_NONCE),
        launch_measurement_hex: hex(&launch.launch_measurement),
        trials,
    }
}

/// Re-check a recorded trace offline: re-run every trial's verification
/// deterministically and compare decisions. Returns the mismatch count.
pub fn replay_trace(trace: &TraceFile) -> usize {
    let backend = MockBackend::with_test_key();
    let first = match trace.trials.first() {
        Some(t) => t,
        None => {
            eprintln!("trace has no trials");
            return 1;
        }
    };
    let image_id = unhex(&trace.launch_image_id_hex).unwrap_or_default();
    let nonce = unhex(&trace.launch_nonce_hex).unwrap_or_default();
    let launch = protocol::launch(&backend, &image_id, &first.snapshot.policy, &nonce);
    if hex(&launch.launch_measurement) != trace.launch_measurement_hex {
        eprintln!("launch measurement mismatch: trace was not produced by this demo setup");
        return trace.trials.len();
    }
    let mut verifier = Verifier::new(backend, &launch);
    let mut mismatches = 0usize;
    for t in &trace.trials {
        let snap = (|| -> Result<Snapshot, String> {
            Ok(Snapshot {
                epoch: t.snapshot.epoch,
                state_ciphertext: Vec::new(), // not inspected by the verifier
                state_hash: unhex32(&t.snapshot.state_hash_hex)?,
                prev_hash: unhex32(&t.snapshot.prev_hash_hex)?,
                policy: t.snapshot.policy.clone(),
                created_at_secs: t.snapshot.created_at_secs,
                attestation: unhex(&t.snapshot.attestation_hex)?,
            })
        })();
        let (decision, reason) = match snap {
            Ok(s) => match verifier.verify_restore(&s, t.now_secs, &t.restorer_id) {
                Ok(_) => ("accept".to_string(), None),
                Err(r) => ("reject".to_string(), Some(r.code().to_string())),
            },
            Err(e) => {
                eprintln!("trial {}: cannot reconstruct snapshot: {e}", t.trial);
                ("error".to_string(), None)
            }
        };
        if decision != t.decision || reason != t.reason {
            eprintln!(
                "trial {}: recorded=({},{:?}) replayed=({},{:?})",
                t.trial, t.decision, t.reason, decision, reason
            );
            mismatches += 1;
        }
    }
    mismatches
}
