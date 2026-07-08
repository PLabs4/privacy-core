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
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

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
        // Grain-based constant generation is ~10x the cost of the hash itself and the
        // output is fixed for this spec, so generate once and clone (a 64-entry Vec plus
        // two 3x3 matrices — negligible next to one round of field exponentiation).
        static CONSTANTS: OnceLock<(Vec<[Fr; 3]>, Mds<Fr, 3>, Mds<Fr, 3>)> = OnceLock::new();
        CONSTANTS
            .get_or_init(generate_constants::<Fr, Self, 3, 2>)
            .clone()
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
    /// Memoized hashes of *complete* subtrees, keyed by `(level, idx)`. The tree is
    /// append-only, so a complete subtree's hash never changes and the cache never needs
    /// invalidation. Without this, every `root()`/`witness()` call rehashes the whole
    /// tree — O(leaves) Poseidon compressions per query, which made indexer Merkle-path
    /// queries degrade linearly as notes accumulated.
    node_cache: RwLock<HashMap<(usize, usize), Fr>>,
}

impl Bn254IncrementalMerkleTree {
    pub fn new() -> Self {
        let mut empty = [Fr::ZERO; MERKLE_DEPTH_EVM + 1];
        for i in 1..=MERKLE_DEPTH_EVM {
            empty[i] = merkle_compress((i - 1) as u8, empty[i - 1], empty[i - 1]);
        }
        Self { leaves: Vec::new(), empty, node_cache: RwLock::new(HashMap::new()) }
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

    /// Root of the tree as it was when only the first `size` leaves were present
    /// (leaves beyond `size` treated as empty). Used by the batch-update model, where
    /// the on-chain `confirmedRoot` lags the locally ingested leaves: anchors/witnesses
    /// must be computed against the CONFIRMED prefix, not the full local tree.
    pub fn root_at_size(&self, size: usize) -> Fr {
        assert!(size <= self.leaves.len(), "size beyond tree");
        self.subtree_hash_at(MERKLE_DEPTH_EVM, 0, size)
    }

    /// Authentication path (siblings) for the leaf at `pos`. Panics if `pos >= len()`.
    pub fn witness(&self, pos: u32) -> [Fr; MERKLE_DEPTH_EVM] {
        self.witness_at_size(pos, self.leaves.len())
    }

    /// Authentication path for `pos` in the prefix tree of the first `size` leaves
    /// (leaves beyond `size` treated as empty). Opens to [`Self::root_at_size`].
    pub fn witness_at_size(&self, pos: u32, size: usize) -> [Fr; MERKLE_DEPTH_EVM] {
        assert!(size <= self.leaves.len(), "size beyond tree");
        assert!((pos as usize) < size, "position out of prefix tree");
        let mut siblings = [Fr::ZERO; MERKLE_DEPTH_EVM];
        for level in 0..MERKLE_DEPTH_EVM {
            let sibling_node_idx = ((pos >> level) ^ 1) as usize;
            siblings[level] = self.subtree_hash_at(level, sibling_node_idx, size);
        }
        siblings
    }

    /// `subtree_hash` bounded to the first `size` leaves. A subtree fully inside the
    /// prefix is identical to the full-tree subtree (append-only ⇒ those leaves never
    /// change), so it delegates to the cached path; only frontier-crossing nodes are
    /// recomputed (uncached — they differ per `size`).
    fn subtree_hash_at(&self, level: usize, idx: usize, size: usize) -> Fr {
        let start = idx << level;
        if start >= size {
            return self.empty[level];
        }
        if start + (1usize << level) <= size {
            return self.subtree_hash(level, idx);
        }
        // level >= 1 here: a level-0 node is a single leaf, always fully inside or outside.
        let left = self.subtree_hash_at(level - 1, idx * 2, size);
        let right = self.subtree_hash_at(level - 1, idx * 2 + 1, size);
        merkle_compress((level - 1) as u8, left, right)
    }

    fn subtree_hash(&self, level: usize, idx: usize) -> Fr {
        let start = idx << level; // idx * 2^level
        if start >= self.leaves.len() {
            return self.empty[level];
        }
        if level == 0 {
            return self.leaves[start];
        }
        // Only complete subtrees are cacheable: an incomplete one (right frontier)
        // still changes as leaves are appended.
        let complete = start + (1usize << level) <= self.leaves.len();
        if complete {
            if let Some(cached) = self.node_cache.read().unwrap().get(&(level, idx)) {
                return *cached;
            }
        }
        let left = self.subtree_hash(level - 1, idx * 2);
        let right = self.subtree_hash(level - 1, idx * 2 + 1);
        let node = merkle_compress((level - 1) as u8, left, right);
        if complete {
            self.node_cache.write().unwrap().insert((level, idx), node);
        }
        node
    }
}

impl Default for Bn254IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
