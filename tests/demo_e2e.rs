//! End-to-end: the demo harness runs, the trace is well-formed, adversarial
//! trials are decided correctly, and latencies are sane (positive and
//! scaling with state size).

use attested_restore::demo::{self, DemoConfig};

fn test_config() -> DemoConfig {
    DemoConfig {
        seed: 7,
        // Keep the e2e fast; the full 1KB–64MB sweep runs in the CLI demo.
        state_sizes: vec![1024, 64 * 1024, 256 * 1024],
        base_time: 1_700_000_000,
    }
}

#[test]
fn demo_produces_well_formed_trace() {
    let trace = demo::run_demo(&test_config());
    assert_eq!(trace.tool, "attested-restore");
    assert!(!trace.trials.is_empty());

    let honest: Vec<_> = trace.trials.iter().filter(|t| t.kind == "honest").collect();
    let adversarial: Vec<_> = trace
        .trials
        .iter()
        .filter(|t| t.kind == "adversarial")
        .collect();
    assert!(!honest.is_empty());
    assert_eq!(adversarial.len(), 5, "five adversarial trials expected");

    // Every honest trial accepted; every adversarial trial rejected.
    for t in &honest {
        assert_eq!(t.decision, "accept", "trial {}", t.trial);
        assert!(t.reason.is_none());
    }
    for t in &adversarial {
        assert_eq!(t.decision, "reject", "trial {}", t.trial);
        assert!(t.reason.is_some());
    }

    // Each adversarial trial got its expected rejection reason.
    let reasons: Vec<&str> = adversarial
        .iter()
        .map(|t| t.reason.as_deref().unwrap())
        .collect();
    for expected in [
        "replayed-epoch",
        "bad-signature",
        "broken-chain",
        "stale-snapshot",
        "unauthorized-restorer",
    ] {
        assert!(
            reasons.contains(&expected),
            "missing adversarial reason {expected}: {reasons:?}"
        );
    }
}

#[test]
fn adversarial_attacks_are_labeled() {
    let trace = demo::run_demo(&test_config());
    let attacks: Vec<&str> = trace
        .trials
        .iter()
        .filter_map(|t| t.attack.as_deref())
        .collect();
    for expected in [
        "replay-old-epoch",
        "forged-signature",
        "broken-chain",
        "stale-snapshot",
        "unauthorized-restorer",
    ] {
        assert!(attacks.contains(&expected), "missing attack {expected}");
    }
}

#[test]
fn latencies_are_sane_and_scale_with_state_size() {
    let trace = demo::run_demo(&test_config());
    let honest: Vec<_> = trace
        .trials
        .iter()
        .filter(|t| t.kind == "honest" && t.attack.is_none())
        .collect();
    assert!(honest.len() >= 2);
    for t in &honest {
        assert!(t.latency_us.snapshot > 0, "trial {}", t.trial);
        assert!(t.latency_us.verify > 0, "trial {}", t.trial);
    }
    // Snapshot cost must grow with state size (hashing dominates).
    let first = honest.first().unwrap();
    let last = honest.last().unwrap();
    assert!(
        last.snapshot.state_size_bytes > first.snapshot.state_size_bytes,
        "test config must use increasing sizes"
    );
    assert!(
        last.latency_us.snapshot > first.latency_us.snapshot,
        "snapshot latency should scale with state size: {}us vs {}us",
        first.latency_us.snapshot,
        last.latency_us.snapshot
    );
}

#[test]
fn trace_roundtrips_through_json() {
    let trace = demo::run_demo(&test_config());
    let json = serde_json::to_string_pretty(&trace).expect("serialize");
    let back: demo::TraceFile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.trials.len(), trace.trials.len());
    assert_eq!(back.launch_measurement_hex, trace.launch_measurement_hex);
}

#[test]
fn replay_reproduces_every_decision() {
    let trace = demo::run_demo(&test_config());
    let mismatches = demo::replay_trace(&trace);
    assert_eq!(mismatches, 0, "offline replay must reproduce all decisions");
}
