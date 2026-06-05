//! Bridge / federation helpers — V1 single-signature BTC deposit address.
//!
//! Operators import BTC to one watch-only (or hot) address, then submit `shield(...)` on
//! Ethereum after observing the expected `ShieldIntent` on disk or queue.
//! (Extracted from `privacybtc-bridge`; the unused commitment-tree import was dropped.)

use crate::types::OrchardStoredBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Operator-configured Bitcoin deposit destination (single-sig).
#[derive(Debug, Clone)]
pub struct BtcDepositConfigV1 {
    /// Bech32 (`bc1...`) or Base58 (legacy / P2SH) deposit address.
    pub btc_deposit_address: String,
}

/// JSON artifact the user exchanges with the operator (or stores for polling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldIntentV1 {
    pub protocol_version: u32,
    pub btc_deposit_address: String,
    pub amount_sats: u64,
    /// SHA-256 of canonical `OrchardStoredBundle` JSON bytes (operator verifies file matches).
    pub bundle_sha256_hex: String,
    /// First output note commitment (hex, no `0x`).
    pub orchard_cmx_hex: String,
    /// Optional human-readable note (e.g. email ticket id).
    pub operator_reference: Option<String>,
    /// BTC txid of the user's deposit transaction (for exact UTXO matching).
    #[serde(default)]
    pub btc_txid: Option<String>,
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("stored bundle must contain at least one action")]
    NoActions,
}

/// Stable content hash for an `OrchardStoredBundle` (serialized JSON, pretty=false).
pub fn bundle_content_sha256(bundle: &OrchardStoredBundle) -> [u8; 32] {
    let bytes = serde_json::to_vec(bundle).expect("OrchardStoredBundle serializes");
    Sha256::digest(bytes).into()
}

/// Builds the V1 shield intent JSON struct.
pub fn build_shield_intent_v1(
    bundle: &OrchardStoredBundle,
    cfg: &BtcDepositConfigV1,
    amount_sats: u64,
    operator_reference: Option<String>,
    btc_txid: Option<String>,
) -> Result<ShieldIntentV1, BridgeError> {
    let action = bundle.actions.first().ok_or(BridgeError::NoActions)?;
    Ok(ShieldIntentV1 {
        protocol_version: 1,
        btc_deposit_address: cfg.btc_deposit_address.clone(),
        amount_sats,
        bundle_sha256_hex: hex::encode(bundle_content_sha256(bundle)),
        orchard_cmx_hex: hex::encode(action.cmx),
        operator_reference,
        btc_txid,
    })
}
