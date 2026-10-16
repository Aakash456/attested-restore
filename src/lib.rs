//! attested-restore: attested, rollback-resistant snapshot/restore for
//! confidential VMs (research prototype).
//!
//! See `DESIGN.md` for the threat model, protocol, and what's mocked.

pub mod attest;
pub mod counter;
pub mod demo;
pub mod policy;
pub mod protocol;
pub mod verifier;
