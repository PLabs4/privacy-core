//! privacy-core — shared, halo2-free foundation for the privacy-indexer and privacy-relayer.
//!
//! Contains only the light, proving-stack-free pieces both services need:
//!   * `ethereum` — event-log decode + bundle/erc/finalize calldata encode (ethabi).
//!   * `types`    — plain serde data structures (stored bundle, indexed notes/bundles).
//!   * `intent`   — BTC shield-intent helpers (single-sig federation V1).
//!
//! The Fr/circuit/witness machinery (proving, note decryption, key derivation, Poseidon)
//! deliberately stays out of this crate so the services don't pull in halo2.

pub mod commitment_tree;
pub mod ethereum;
pub mod intent;
pub mod types;

// Convenience re-exports.
pub use intent::{build_shield_intent_v1, bundle_content_sha256, BridgeError, BtcDepositConfigV1, ShieldIntentV1};
pub use types::{
    OrchardIndexBatch, OrchardIndexedAbiNote, OrchardIndexedBundle, OrchardStoredAction,
    OrchardStoredBundle,
};
