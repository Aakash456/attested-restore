//! Trusted monotonic epoch counter.
//!
//! Rollback resistance rests on this counter: every snapshot is bound to a
//! fresh, never-repeating epoch, and the verifier only moves its accepted
//! epoch forward. A real deployment needs a crash-consistent monotonic
//! counter (PSP-backed storage, or a replicated ROTE-style service). The
//! mock below is in-memory: it is monotonic within a process but loses state
//! on restart — documented as a prototype limitation, not a protocol flaw.

/// Trusted monotonic counter: yields strictly increasing epochs.
pub trait EpochCounter {
    /// Return the next epoch. Must never repeat or go backward, including
    /// across restarts (for production backends).
    fn next_epoch(&mut self) -> u64;
}

/// In-memory mock counter. Epoch 0 is reserved for the launch record;
/// the first snapshot gets epoch 1.
#[derive(Debug, Default)]
pub struct MockCounter {
    next: u64,
}

impl MockCounter {
    pub fn new() -> Self {
        Self { next: 1 }
    }
}

impl EpochCounter for MockCounter {
    fn next_epoch(&mut self) -> u64 {
        let e = self.next;
        self.next = self.next.saturating_add(1);
        debug_assert!(e != 0, "epoch wrapped past u64::MAX");
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_are_strictly_increasing_from_one() {
        let mut c = MockCounter::new();
        let vals: Vec<u64> = (0..100).map(|_| c.next_epoch()).collect();
        assert_eq!(vals[0], 1);
        for w in vals.windows(2) {
            assert!(w[0] < w[1]);
        }
    }
}
