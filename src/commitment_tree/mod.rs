//! BN254 Poseidon note-commitment tree (halo2-free).
//!
//! Extracted from `orchard-commitment-tree`, with the Poseidon hashing re-sourced to
//! `privacy-core::commitment_tree::poseidon` (via `halo2_poseidon` + `halo2curves`).
//! The Pallas-typed legacy stubs (`to_orchard_path`, `root`) were dropped — clients use
//! the `siblings` (LE hex) directly.

mod poseidon_primitives;
pub mod frozen;
pub mod poseidon;

use ff::PrimeField;
use halo2curves::bn256::Fr;
use poseidon::Bn254IncrementalMerkleTree;
use serde::{Deserialize, Serialize};

/// A Merkle authentication path for a BN254 note commitment.
///
/// `siblings` are 32-byte LE hex strings (0x-prefixed) — pass directly to the prover's
/// `parse_fr_le()` witness builder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrchardMerklePath {
    /// 0-based leaf index in the commitment tree.
    pub position: u32,
    /// 32 sibling hashes from leaf to root (each a 0x-prefixed LE 32-byte hex string).
    pub siblings: Vec<String>,
}

/// BN254 Poseidon note commitment tree.
///
/// Leaf values are BN254 `Fr` elements encoded big-endian (as emitted by the EVM
/// `NoteAdded` event); internally the tree works in little-endian field representation.
pub struct OrchardCommitmentTree {
    inner: Bn254IncrementalMerkleTree,
    size: u64,
    latest_checkpoint: Option<u64>,
}

impl OrchardCommitmentTree {
    pub fn new() -> Self {
        Self { inner: Bn254IncrementalMerkleTree::new(), size: 0, latest_checkpoint: None }
    }

    /// Append a big-endian `cmx` (as from an EVM log) as the next leaf. Always `Some(pos)`.
    pub fn append(&mut self, cmx_be: [u8; 32]) -> Option<u64> {
        self.inner.append(be_bytes_to_fr(cmx_be));
        let pos = self.size;
        self.size += 1;
        Some(pos)
    }

    /// Register a checkpoint label (Ethereum block number). The tree is append-only.
    pub fn checkpoint(&mut self, checkpoint_id: u64) -> bool {
        self.latest_checkpoint = Some(checkpoint_id);
        true
    }

    /// Merkle root (LE 32 bytes). `None` when the tree is empty.
    pub fn latest_root(&self) -> Option<[u8; 32]> {
        if self.size == 0 {
            return None;
        }
        Some(fr_to_le_bytes(self.inner.root()))
    }

    /// Authentication path for the leaf at `position` (current tree state). `None` if OOB.
    pub fn merkle_path(&self, position: u64, _checkpoint_id: u64) -> Option<OrchardMerklePath> {
        if position >= self.size {
            return None;
        }
        let siblings = self
            .inner
            .witness(position as u32)
            .iter()
            .map(|fr| format!("0x{}", hex::encode(fr_to_le_bytes(*fr))))
            .collect();
        Some(OrchardMerklePath { position: position as u32, siblings })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn latest_checkpoint_id(&self) -> Option<u64> {
        self.latest_checkpoint
    }
}

impl Default for OrchardCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Field element conversion helpers ────────────────────────────────────────

/// Big-endian 32-byte array (EVM representation) → BN254 `Fr` (via `from_raw`).
fn be_bytes_to_fr(be: [u8; 32]) -> Fr {
    let mut le = be;
    le.reverse();
    let mut limbs = [0u64; 4];
    for (i, chunk) in le.chunks(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fr::from_raw(limbs)
}

/// BN254 `Fr` → little-endian 32-byte array.
fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
    fr.to_repr().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    /// Byte-identity guard: the halo2-free Poseidon tree must reproduce the live on-chain
    /// root for the real Sepolia leaves. If this fails, the Poseidon constants drifted.
    #[test]
    fn root_matches_onchain() {
        let leaves = [
            "16c1a78d9bf2a808a1f71e93b9caff5c86a28c79ea5cc5f1bebc52cbd5a936ff",
            "2c421b91ff2f9ef6a4f024e56c29491eb2d26a6ae65ec34a420d6a70432a1fc0",
            "1369c5ef5db9200ba955725e65855b1a4f77321a01a336a37e5807c6190e0fa0",
            "11fe8d42f8ae822ccf7261f40e87c5695dff7853d942d308a8e4b7e5155cd781",
        ];
        let mut tree = OrchardCommitmentTree::new();
        for l in leaves {
            tree.append(be(l));
        }
        // Live Sepolia treeSize=4 root: indexer /root (LE) = 70c14793…; on-chain
        // activeRoot()/indexer_meta (BE) = 22e4ff3d… latest_root() returns LE.
        let expected_le = "70c14793de62ea1c6b3f134efc7900bdd5d81c71ee041e5b6481c17d3dffe422";
        assert_eq!(hex::encode(tree.latest_root().unwrap()), expected_le);
    }
}
