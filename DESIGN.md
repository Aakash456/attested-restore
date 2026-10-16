# attested-restore — Protocol Design

## Problem

Restoring a confidential VM (SEV-SNP / TDX) from a snapshot breaks attestation
lineage: the launch measurement covers the boot chain, not restored state —
and a host that can snapshot at will can *replay* stale-but-once-valid state
undetectably. Fast snapshot/restore research (Firecracker, REAP, Catalyzer)
assumes host-readable guest memory; TEE attestation research assumes fresh
launch (SNP/TDX document restore as unsupported; KubeVirt marks confidential
VMs non-migratable). No published work demonstrates VM-level snapshot restore
of a confidential VM with **freshness**, **rollback resistance**, and
**policy-bound re-attestation**. This prototype defines and implements that
protocol.

The core idea: every snapshot carries a backend-signed attestation binding
`(launch_measurement, epoch, state_hash, prev_hash, policy_digest,
created_at)`. Snapshots form a hash chain rooted at the launch record; a
trusted monotonic epoch counter makes replay detectable; the verifier enforces
a restore policy (max age, authorized restorers). The attestation backend is a
trait — the mock here stands in for PSP/SEAM-protected signing.

## Threat model

**The host is untrusted.** It can:

- snapshot guest state at arbitrary times,
- replay old snapshots (rollback attack),
- present forged or tampered snapshots (without the backend signing key),
- attempt restore on behalf of unauthorized parties,
- restore snapshots that violate policy (too old).

**Trusted components / assumptions:**

- The attestation backend's signing key is protected. In the mock it lives
  in-process (test key — never production); real deployments need
  PSP/SEAM-equivalent key protection.
- The epoch counter service is trusted, monotonic, never repeats, never goes
  backward, and survives crashes (the mock is in-memory and documents this
  limitation).
- The verifier runs in a trusted context (e.g., the tenant's control plane or
  a relying party), seeded with the genuine launch measurement.
- Guest memory encryption on restore (the import path) is out of scope for
  this prototype: state is stored opaquely. The protocol guarantees
  *which* state may be restored and *by whom*, not the confidentiality of the
  restore channel itself.

**Out of scope:** side channels, TOCTOU between snapshot and restore,
compromised backend/counter/verifier, denial of service.

## Protocol messages

```
  Host (untrusted)          Attestation backend (trusted)        Verifier (trusted)
  ================          =============================        ==================

  LAUNCH
  ------
  image_id, policy_digest, nonce
  ─────────────────────────────────────────►
                                   launch_measurement =
                                     SHA256("AR-LAUNCH-v1" ||
                                            image_id || policy_digest || nonce)
                                   epoch := 0
  ◄─────────────────────────────────────────
  LaunchRecord { measurement, epoch = 0, policy_digest }

  SNAPSHOT (epoch k, k >= 1)
  --------------------------
  epoch      := counter.next_epoch()      [trusted monotonic counter]
  state_hash := SHA256(state_ciphertext)
  prev_hash  := content hash of parent
                (genesis = hash(launch record) for k = 1)
  created_at := backend timestamp
  ─────────────────────────────────────────►
  msg := launch_measurement || epoch || state_hash ||
         prev_hash || policy_digest || created_at
  attestation := Sign_backend(msg)
  ◄─────────────────────────────────────────
  Host stores Snapshot { epoch, state_ciphertext (opaque),
                         state_hash, prev_hash, policy,
                         created_at, attestation }

  RESTORE + VERIFY
  ----------------
  Host ─── Snapshot ───► Verifier
  Verifier, in order:
    1. signature over msg valid? ................. else BadSignature
    2. prev_hash ∈ {genesis} ∪ accepted .......... else BrokenChain
    3. epoch > last_accepted_epoch ............... else ReplayedEpoch
    4. age ≤ max_age AND restorer ∈ authorized ... else StaleSnapshot /
                                                        UnauthorizedRestorer
    ✓ accept: last_accepted_epoch := epoch;
              record snapshot content hash
```

## Data structures

```rust
LaunchRecord {
    launch_measurement: [u8; 32],
    epoch: u64,            // always 0; the chain root
    policy_digest: [u8; 32],
}

Snapshot {
    epoch: u64,
    state_ciphertext: Vec<u8>,  // opaque in this prototype
    state_hash: [u8; 32],       // SHA256(state_ciphertext)
    prev_hash: [u8; 32],        // content hash of parent snapshot, or genesis
    policy: RestorePolicy,
    created_at_secs: u64,       // backend-stamped; covered by attestation
    attestation: Vec<u8>,       // backend signature over the canonical
                               // encoding of (launch_measurement || epoch ||
                               // state_hash || prev_hash || policy_digest ||
                               // created_at_secs)
}

RestorePolicy {
    max_snapshot_age_secs: u64,
    authorized_restorers: Vec<String>,
}
```

Note: `created_at_secs` extends the assigned field list — it is required for
the staleness check and is covered by the attestation signature so the host
cannot backdate it (only the backend can mint a valid attestation).

## Canonical byte encoding (for signing and hashing)

- `u64` → 8 bytes, little-endian.
- Fixed `[u8; 32]` digests → raw 32 bytes (no length prefix).
- Variable bytes → `u64` length prefix + bytes.
- `String` → UTF-8 bytes with length prefix.
- `RestorePolicy` → `max_snapshot_age_secs` || `u64` restorer count ||
  each restorer length-prefixed.
- `policy_digest` = SHA256(canonical `RestorePolicy`).
- Launch-record encoding = `launch_measurement` || `epoch` || `policy_digest`;
  `genesis_hash` = SHA256 of that encoding.
- Snapshot *content hash* (used for chaining) = SHA256(
  `epoch` || `state_hash` || `prev_hash` || `policy_digest` || `created_at_secs`).
  The attestation signature itself is excluded to avoid circularity.
- Signed message = `launch_measurement` || `epoch` || `state_hash` ||
  `prev_hash` || `policy_digest` || `created_at_secs`.

## Verifier checks (in order)

1. **Signature validity** — recompute the signed message from the snapshot
   fields plus the verifier's own `launch_measurement`; `BadSignature` on
   mismatch. (Catches forgery and any tampering with signed fields.)
2. **Hash-chain lineage** — `prev_hash` must equal the genesis hash or the
   content hash of a previously accepted snapshot; else `BrokenChain`.
3. **Freshness / rollback** — `epoch` must be strictly greater than
   `last_accepted_epoch`; equal-or-lower is a replay → `ReplayedEpoch`.
4. **Policy compliance** — `now - created_at ≤ max_snapshot_age_secs` else
   `StaleSnapshot`; `restorer_id ∈ authorized_restorers` else
   `UnauthorizedRestorer`.

## What's mocked vs. what needs hardware

| Component | Prototype | Production |
|---|---|---|
| Attestation signing | HMAC-SHA256, in-process test key | PSP (SEV-SNP VCEK) / TDX module + QE; key never leaves hardware |
| Launch measurement | SHA256 over image/policy/nonce | Real measured-boot digest (SNP launch digest / TDX MRTD+RTMRs) |
| Epoch counter | In-memory monotonic `u64` | Crash-consistent monotonic counter (PSP-backed or replicated ROTE) |
| State encryption | Opaque bytes (not implemented) | Encrypted-memory import path on restore |
| Guest cooperation | None needed | Guest agent to quiesce / re-measure on restore |

The **protocol logic** — chaining, epoch binding, the four verifier checks —
is hardware-independent and is the actual contribution. The mock backend is
standard practice (cf. the Tamarin SNP formal model, which likewise reasons
about the protocol, not the silicon).

## Limitations and future work

- In-memory epoch counter loses state on restart (documented; a file-backed
  variant is trivial but still not crash-safe without fsync discipline).
- Policy is carried per-snapshot and enforced as carried. Recommended
  hardening: require `snapshot.policy_digest == launch.policy_digest` so
  policy cannot be weakened after launch.
- No confidentiality for the restore channel itself (out of scope per threat
  model).
- Mock key is a fixed test key; the `demo`/`verify` CLI documents this.
