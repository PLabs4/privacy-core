//! Poseidon-based Merkle hashing on the BN254 scalar field (`Fr`).
//!
//! Lifted verbatim from `orchard-bn254`'s `poseidon_merkle_bn254` (the merkle-tree parts
//! only), re-sourced to the **standalone** crates `halo2_poseidon` (Poseidon primitives)
//! and `halo2curves` (BN254 `Fr`) so it carries **no `halo2_proofs` / `halo2_gadgets`
//! dependency**. The Poseidon spec/constants are byte-identical to the prover + on-chain
//! `PoseidonT3` (verified against the live commitment-tree root).

use super::poseidon_primitives::{generate_constants, ConstantLength, Hash, Mds, Spec};
use ff::Field;
use halo2curves::bn256::Fr;

/// Orchard-compatible depth for the incremental note commitment tree.
pub const MERKLE_DEPTH_EVM: usize = 32;

/// Poseidon-128, width 3, rate 2, x^5 S-box; Grain-generated constants for BN254 `Fr`.
#[derive(Clone, Copy, Debug)]
pub struct Bn254PoseidonMerkleSpec;

impl Spec<Fr, 3, 2> for Bn254PoseidonMerkleSpec {
    fn full_rounds() -> usize {
        8
    }
    fn partial_rounds() -> usize {
        56
    }
    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }
    fn secure_mds() -> usize {
        0
    }
    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>, Mds<Fr, 3>) {
        generate_constants::<Fr, Self, 3, 2>()
    }
}

/// One Merkle layer: `H(level || left || right)` with domain separation on `level`.
#[inline]
pub fn merkle_compress(level: u8, left: Fr, right: Fr) -> Fr {
    Hash::<Fr, Bn254PoseidonMerkleSpec, ConstantLength<3>, 3, 2>::init().hash([
        Fr::from(level as u64),
        left,
        right,
    ])
}

/// `Poseidon(domain, a, b)` over `ConstantLength<3>` — the width-3 two-input hash with
/// a `u64` domain tag. Byte-identical to the prover's `poseidon_merkle_bn254::poseidon2`
/// and to `merkle_compress` when `domain == level`. Used for the frozen Indexed MT,
/// whose node domains exceed the `u8` range of `merkle_compress`.
#[inline]
pub fn poseidon_domain_pair(domain: u64, a: Fr, b: Fr) -> Fr {
    Hash::<Fr, Bn254PoseidonMerkleSpec, ConstantLength<3>, 3, 2>::init().hash([
        Fr::from(domain),
        a,
        b,
    ])
}

/// Full Merkle root (depth [`MERKLE_DEPTH_EVM`]) over `Fr` leaves from a sibling path.
pub fn merkle_root(position: u32, leaf: Fr, siblings: &[Fr; MERKLE_DEPTH_EVM]) -> Fr {
    let mut node = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        let l = level as u8;
        if (position >> level) & 1 == 0 {
            node = merkle_compress(l, node, *sibling);
        } else {
            node = merkle_compress(l, *sibling, node);
        }
    }
    node
}

/// Append-only incremental Merkle tree of fixed depth [`MERKLE_DEPTH_EVM`] (32) over BN254
/// scalar leaves. Empty leaves default to [`Fr::ZERO`].
#[derive(Debug)]
pub struct Bn254IncrementalMerkleTree {
    leaves: Vec<Fr>,
    /// `empty[l]` is the root of a depth-`l` all-zero subtree (`empty[0]` = `Fr::ZERO`).
    empty: [Fr; MERKLE_DEPTH_EVM + 1],
}

impl Bn254IncrementalMerkleTree {
    pub fn new() -> Self {
        let mut empty = [Fr::ZERO; MERKLE_DEPTH_EVM + 1];
        for i in 1..=MERKLE_DEPTH_EVM {
            empty[i] = merkle_compress((i - 1) as u8, empty[i - 1], empty[i - 1]);
        }
        Self { leaves: Vec::new(), empty }
    }

    pub fn append(&mut self, leaf: Fr) {
        self.leaves.push(leaf);
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> Fr {
        self.subtree_hash(MERKLE_DEPTH_EVM, 0)
    }

    /// Authentication path (siblings) for the leaf at `pos`. Panics if `pos >= len()`.
    pub fn witness(&self, pos: u32) -> [Fr; MERKLE_DEPTH_EVM] {
        assert!((pos as usize) < self.leaves.len(), "position out of tree");
        let mut siblings = [Fr::ZERO; MERKLE_DEPTH_EVM];
        for level in 0..MERKLE_DEPTH_EVM {
            let sibling_node_idx = ((pos >> level) ^ 1) as usize;
            siblings[level] = self.subtree_hash(level, sibling_node_idx);
        }
        siblings
    }

    fn subtree_hash(&self, level: usize, idx: usize) -> Fr {
        let start = idx << level; // idx * 2^level
        if start >= self.leaves.len() {
            return self.empty[level];
        }
        if level == 0 {
            return self.leaves[start];
        }
        let left = self.subtree_hash(level - 1, idx * 2);
        let right = self.subtree_hash(level - 1, idx * 2 + 1);
        merkle_compress((level - 1) as u8, left, right)
    }
}

impl Default for Bn254IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
