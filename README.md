# attested-restore

Research prototype of a **novel protocol: attested, rollback-resistant
snapshot/restore for confidential VMs**.

## The problem

Restoring a confidential VM (SEV-SNP / TDX) from a snapshot breaks attestation
lineage: the launch measurement covers the boot chain, not restored state —
and a host that can snapshot at will can *replay* stale-but-once-valid state
undetectably. Fast snapshot/restore research (Firecracker, REAP, Catalyzer)
assumes host-readable guest memory; TEE attestation assumes fresh launch
(SNP/TDX document restore as unsupported). No published work demonstrates
VM-level snapshot restore of a confidential VM with freshness, rollback
resistance, and policy-bound re-attestation. This prototype defines and
implements that protocol. See [DESIGN.md](DESIGN.md) for the threat model,
protocol messages, canonical encodings, and what's mocked vs. hardware.

## Protocol in brief

Every snapshot carries a backend-signed attestation binding
`(launch_measurement, epoch, state_hash, prev_hash, policy_digest,
created_at)`. Snapshots form a hash chain rooted at the launch record; a
trusted monotonic epoch counter makes replay detectable; the verifier
enforces, in order: (1) signature validity, (2) chain lineage, (3) strictly
increasing epochs, (4) policy (max age, authorized restorers).

## Run the demo

```sh
cargo run --release -- demo --trace-out demo.trace.json
```

This runs honest restore trials across synthetic state sizes (1KB–64MB) plus
five adversarial trials — replay of an old epoch, forged signature, broken
chain, stale snapshot, unauthorized restorer — and writes a trace dataset.
Expected output: all honest trials `accept`, all adversarial trials `reject`
with the matching reason.

Re-verify the trace offline (deterministic replay of every decision):

```sh
cargo run --release -- verify --trace demo.trace.json
```

## The trace dataset

`demo.trace.json` is designed as a publishable artifact (e.g., IEEE
DataPort): every trial records epoch, state size, snapshot age, restorer,
decision, rejection reason, and microsecond latencies for snapshot creation,
attestation signing, and verification — plus the launch parameters needed to
reproduce every decision offline via `verify`.

## Honest limitations

- **Mock attestation backend** (HMAC-SHA256, compiled-in test key). Real
  deployments need PSP/SEAM-protected signing; SNP/TDX backends implement the
  `AttestationBackend` trait.
- **In-memory epoch counter.** Production needs a crash-consistent monotonic
  counter.
- **State stored opaquely.** The prototype does not implement the
  encrypted-memory import path; the protocol guarantees *which* state may be
  restored and *by whom*.
- **Policy carried per-snapshot.** Recommended hardening (see DESIGN.md):
  require `policy_digest == launch.policy_digest` so policy can't weaken
  after launch.

## Layout

- `DESIGN.md` — threat model, protocol, encodings, verifier checks
- `src/attest.rs` — `AttestationBackend` trait + HMAC mock
- `src/counter.rs` — trusted monotonic epoch counter + mock
- `src/policy.rs` — restore policy and checks
- `src/protocol.rs` — `LaunchRecord`/`Snapshot`, canonical encodings, issuance
- `src/verifier.rs` — the four ordered checks
- `src/demo.rs` — honest + adversarial trial harness, trace dataset, replay
- `tests/freshness.rs` — randomized property test: the verifier never accepts
  a non-increasing epoch (the checkable core of the rollback-resistance claim)
- `tests/demo_e2e.rs` — end-to-end demo, adversarial decisions, latency sanity

No network calls, no telemetry. MIT license.
