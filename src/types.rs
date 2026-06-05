//! Plain serde data types shared by the indexer and relayer.
//!
//! These are byte-only containers (no field-element / circuit dependency), extracted from
//! the original `privacybtc-core` so the services don't pull in the proving stack.
//! The Fr/witness-based local-validation helpers stay in the wallet/prover side.

use serde::{Deserialize, Serialize};

// ─── Stored bundle (the relayer submits this; the prover produces it) ──────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardStoredAction {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub spend_auth_sig: Vec<u8>,
    /// keccak256(sharedSecret) for Phase 2 hash-lock confirmation.
    /// Present only on `transfer()` actions; absent for `shield()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_hash: Option<[u8; 32]>,
    /// Per-action Groth16 proof bytes (`abi.encode(pA,pB,pC)`, 256 B).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_bn254: Option<Vec<u8>>,
    /// Per-action calldata pub fields (8 × 32 bytes BE): anchor, cv, nf, rk, cmx, rt_frozen.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pub_inputs_bn254")]
    pub pub_fields_bn254: Option<Vec<[u8; 32]>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardStoredBundle {
    pub flags_orchard: u8,
    pub value_balance_orchard: i64,
    pub anchor_orchard: [u8; 32],
    /// Legacy Orchard (Pallas) proof bytes — kept for reference / local validation.
    pub proofs_orchard: Vec<u8>,
    pub actions: Vec<OrchardStoredAction>,
    pub binding_sig_orchard: Vec<u8>,
    /// Groth16 proof bytes from the local prover (legacy field name `proof_bn254`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_bn254: Option<Vec<u8>>,
    /// Legacy bundle-level pub fields (prefer per-action `pub_fields_bn254`).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pub_inputs_bn254")]
    pub pub_fields_bn254: Option<Vec<[u8; 32]>>,
    /// Baby JubJub Schnorr binding signature [Rx, Ry, s] (each 32-byte big-endian BN254 Fr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_sig_bn254: Option<[[u8; 32]; 3]>,
    /// Net value change for this bundle (v_new_total - v_old_total).
    #[serde(default)]
    pub value_balance_bn254: i64,
}

// ─── Indexed data (what the indexer derives from on-chain events) ──────────────

/// One `NoteAdded` event (`PrivacyBTC.sol` ABI logs). Encrypted — no plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardIndexedAbiNote {
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
    pub cmx: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub epk: [u8; 32],
    /// 80-byte outgoing ciphertext (`NoteAdded.outCiphertext`, or legacy calldata parse).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_ciphertext: Vec<u8>,
    /// `pubFields[1]` = `cv_net_x` (BE), for OCK derivation. Empty if unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_net_x: Option<[u8; 32]>,
    pub nf_old: [u8; 32],
    pub ack_hash: [u8; 32],
    /// Leaf position in the indexer's commitment tree after append, if known.
    #[serde(default)]
    pub cmx_position: Option<u64>,
    /// From `ShieldCompleted` in the same transaction, if present.
    #[serde(default)]
    pub shield_amount_sats: Option<u64>,
    /// True once a `NoteConfirmed` event for this cmx has been observed (Phase 2 complete).
    #[serde(default)]
    pub is_confirmed: bool,
}

/// One indexed `bundle()` transaction (full stored bundle + per-action tree positions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardIndexedBundle {
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
    pub bundle: OrchardStoredBundle,
    /// Position of each action's cmx in the commitment tree (index i ↔ actions[i].cmx).
    #[serde(default)]
    pub cmx_positions: Vec<u64>,
}

/// A range of scanned blocks with the bundles/notes found in them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardIndexBatch {
    pub from_block: u64,
    pub to_block: u64,
    pub bundles: Vec<OrchardIndexedBundle>,
    /// `PrivacyBTC.sol` `NoteAdded` (+ optional `ShieldCompleted` amount).
    #[serde(default)]
    pub abi_notes: Vec<OrchardIndexedAbiNote>,
    /// Latest confirmed commitment tree root after processing this batch.
    #[serde(default)]
    pub latest_root: Option<[u8; 32]>,
}
