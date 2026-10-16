//! Restore policy: who may restore, and how fresh the snapshot must be.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Policy bound into every snapshot attestation and enforced by the
/// verifier (check 4). Serialized into the demo trace dataset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePolicy {
    /// Maximum permitted age of a snapshot at restore time, in seconds.
    pub max_snapshot_age_secs: u64,
    /// Restorer identities allowed to perform the restore.
    pub authorized_restorers: Vec<String>,
}

/// Why a snapshot failed the policy check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    StaleSnapshot { age_secs: u64, max_age_secs: u64 },
    UnauthorizedRestorer { restorer: String },
}

impl RestorePolicy {
    /// Enforce the policy. `created_at_secs` is the backend-stamped snapshot
    /// time (covered by the attestation signature, so the host cannot
    /// backdate it); `now_secs` is the verifier's clock.
    pub fn check(
        &self,
        created_at_secs: u64,
        now_secs: u64,
        restorer_id: &str,
    ) -> Result<(), PolicyError> {
        let age_secs = now_secs.saturating_sub(created_at_secs);
        if age_secs > self.max_snapshot_age_secs {
            return Err(PolicyError::StaleSnapshot {
                age_secs,
                max_age_secs: self.max_snapshot_age_secs,
            });
        }
        if !self.authorized_restorers.iter().any(|r| r == restorer_id) {
            return Err(PolicyError::UnauthorizedRestorer {
                restorer: restorer_id.to_string(),
            });
        }
        Ok(())
    }

    /// Canonical digest bound into the launch record and every snapshot
    /// attestation. Encoding: `max_age` (u64 LE) || restorer count (u64 LE)
    /// || each restorer length-prefixed.
    pub fn digest(&self) -> [u8; 32] {
        let mut v = Vec::new();
        v.extend_from_slice(&self.max_snapshot_age_secs.to_le_bytes());
        v.extend_from_slice(&(self.authorized_restorers.len() as u64).to_le_bytes());
        for r in &self.authorized_restorers {
            let b = r.as_bytes();
            v.extend_from_slice(&(b.len() as u64).to_le_bytes());
            v.extend_from_slice(b);
        }
        Sha256::digest(&v).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RestorePolicy {
        RestorePolicy {
            max_snapshot_age_secs: 3600,
            authorized_restorers: vec!["node-1".to_string(), "node-2".to_string()],
        }
    }

    #[test]
    fn fresh_authorized_passes() {
        assert!(policy().check(1000, 2000, "node-1").is_ok());
    }

    #[test]
    fn boundary_age_passes() {
        assert!(policy().check(1000, 4600, "node-2").is_ok());
    }

    #[test]
    fn stale_rejected() {
        assert_eq!(
            policy().check(1000, 4601, "node-1"),
            Err(PolicyError::StaleSnapshot {
                age_secs: 3601,
                max_age_secs: 3600
            })
        );
    }

    #[test]
    fn unauthorized_rejected() {
        assert_eq!(
            policy().check(1000, 2000, "mallory"),
            Err(PolicyError::UnauthorizedRestorer {
                restorer: "mallory".to_string()
            })
        );
    }

    #[test]
    fn digest_is_deterministic_and_binding() {
        let p = policy();
        assert_eq!(p.digest(), p.digest());
        let mut q = p.clone();
        q.max_snapshot_age_secs = 1;
        assert_ne!(p.digest(), q.digest());
    }
}
