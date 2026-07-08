//! EVM batch-update frontier tree — the off-chain mirror of the on-chain
//! `IncrementalMerkleTree` state that `OrchardVerifier.updateRoot` advances.
//!
//! Under the batch-update model the pool no longer inserts leaves on-chain: bundles
//! only ENQUEUE each `cmx`, and a permissionless crank submits a Groth16
//! `cmxconfirm_evm` proof that folding the next `j` queued leaves into the tree whose
//! state is `(confirmed_root, frontier_commit, confirmed_count)` yields
//! `(new_root, new_frontier_commit)`. This module provides:
//!
//!   * [`FrontierTree`] — the exact frontier ("filled subtrees") insert algorithm of
//!     `contracts/crypto/merkle/IncrementalMerkleTree.sol::insert` (32 Poseidon
//!     compressions per insert, O(1) state);
//!   * [`frontier_commit`] — the Poseidon fold (domain [`DOMAIN_FRONTIER`]) binding the
//!     `filled` array, matching `OrchardVerifier._frontierCommit` and the circuit's
//!     `FrontierCommitEvm`;
//!   * [`CmxConfirmWitnessInput`] — the circom witness input JSON for one batch, plus
//!     the resulting public values for the `updateRoot` call.

use super::poseidon::{merkle_compress, poseidon_domain_pair, MERKLE_DEPTH_EVM};
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};

/// Domain tag of the frontier Poseidon fold. Mirrors `OrchardVerifier.DOMAIN_FRONTIER`
/// and the circuit's `DOMAIN_FRONTIER_EVM()` (and the Solana DOMAIN_FRONTIER).
pub const DOMAIN_FRONTIER: u64 = 3006;

/// Max cmx per `updateRoot` batch. MUST equal `OrchardVerifier.MAX_UPDATE_BATCH` and
/// the circuit's `CmxConfirmEvm(maxBatch)` parameter.
pub const CMX_CONFIRM_MAX_BATCH: usize = 8;

/// Poseidon fold over the IMT frontier:
/// `acc_0 = 0; acc_{l+1} = Poseidon(3006, acc_l, filled[l]); commit = acc_32`.
pub fn frontier_commit(filled: &[Fr; MERKLE_DEPTH_EVM]) -> Fr {
    let mut acc = Fr::ZERO;
    for f in filled.iter() {
        acc = poseidon_domain_pair(DOMAIN_FRONTIER, acc, *f);
    }
    acc
}

/// O(1)-state incremental Merkle tree over the frontier (`filled`) array — the exact
/// algorithm of the on-chain `IncrementalMerkleTree.insert`, so roots (and the frontier
/// commit) stay byte-identical with the contract and the `cmxconfirm_evm` circuit.
///
/// Unlike [`super::poseidon::Bn254IncrementalMerkleTree`] (which retains every leaf for
/// witness queries), this tracks only the 32-slot frontier: it is the CRANK-side state
/// used to plan `updateRoot` batches and derive circuit witness inputs.
#[derive(Debug, Clone)]
pub struct FrontierTree {
    filled: [Fr; MERKLE_DEPTH_EVM],
    next_index: u64,
    root: Fr,
    /// `empty[l]` = root of a depth-`l` all-zero subtree.
    empty: [Fr; MERKLE_DEPTH_EVM + 1],
}

impl FrontierTree {
    pub fn new() -> Self {
        let mut empty = [Fr::ZERO; MERKLE_DEPTH_EVM + 1];
        for l in 1..=MERKLE_DEPTH_EVM {
            empty[l] = merkle_compress((l - 1) as u8, empty[l - 1], empty[l - 1]);
        }
        Self {
            filled: [Fr::ZERO; MERKLE_DEPTH_EVM],
            next_index: 0,
            root: empty[MERKLE_DEPTH_EVM],
            empty,
        }
    }

    /// Rebuild the frontier state from raw parts (e.g. after replaying `NoteConfirmed`
    /// events or loading a persisted snapshot). The caller must guarantee that `filled`
    /// / `next_index` / `root` are mutually consistent.
    pub fn from_parts(filled: [Fr; MERKLE_DEPTH_EVM], next_index: u64, root: Fr) -> Self {
        let fresh = Self::new();
        Self { filled, next_index, root, empty: fresh.empty }
    }

    /// Append one big-endian leaf (as read from EVM logs / storage). See [`Self::insert`].
    pub fn insert_be(&mut self, leaf_be: [u8; 32]) -> Fr {
        self.insert(fr_from_be(leaf_be))
    }

    /// Append one leaf; returns the new root. Mirrors `IncrementalMerkleTree.insert`.
    pub fn insert(&mut self, leaf: Fr) -> Fr {
        let idx = self.next_index;
        assert!(idx < 1 << MERKLE_DEPTH_EVM, "IMT: tree full");
        self.next_index = idx + 1;

        let mut node = leaf;
        for l in 0..MERKLE_DEPTH_EVM {
            if (idx >> l) & 1 == 0 {
                self.filled[l] = node;
                node = merkle_compress(l as u8, node, self.empty[l]);
            } else {
                node = merkle_compress(l as u8, self.filled[l], node);
            }
        }
        self.root = node;
        node
    }

    pub fn root(&self) -> Fr {
        self.root
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn filled(&self) -> &[Fr; MERKLE_DEPTH_EVM] {
        &self.filled
    }

    /// Poseidon frontier commit of the CURRENT state (what the chain stores as
    /// `frontierCommit` next to `confirmedRoot`).
    pub fn frontier_commit(&self) -> Fr {
        frontier_commit(&self.filled)
    }

    /// Plan one `updateRoot` batch: insert `cmxs` (1..=[`CMX_CONFIRM_MAX_BATCH`] leaves,
    /// big-endian as read from the on-chain queue / `NoteAdded` logs) and return the
    /// full circom witness input capturing the state transition. `self` advances to the
    /// post-batch state (call on a clone if the confirm tx may fail).
    pub fn plan_batch(&mut self, cmxs_be: &[[u8; 32]]) -> CmxConfirmWitnessInput {
        assert!(
            !cmxs_be.is_empty() && cmxs_be.len() <= CMX_CONFIRM_MAX_BATCH,
            "batch size must be 1..={CMX_CONFIRM_MAX_BATCH}"
        );
        let old_root = self.root;
        let old_frontier_commit = self.frontier_commit();
        let start_idx = self.next_index;
        let filled_start = self.filled;

        let mut cmxs = [Fr::ZERO; CMX_CONFIRM_MAX_BATCH];
        for (i, be) in cmxs_be.iter().enumerate() {
            let leaf = fr_from_be(*be);
            cmxs[i] = leaf;
            self.insert(leaf);
        }

        CmxConfirmWitnessInput {
            old_root: fr_dec(old_root),
            new_root: fr_dec(self.root),
            j: cmxs_be.len().to_string(),
            start_idx: start_idx.to_string(),
            old_frontier_commit: fr_dec(old_frontier_commit),
            new_frontier_commit: fr_dec(self.frontier_commit()),
            cmxs: cmxs.iter().map(|f| fr_dec(*f)).collect(),
            filled_start: filled_start.iter().map(|f| fr_dec(*f)).collect(),
        }
    }
}

impl Default for FrontierTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Witness input for one `cmxconfirm_evm` proof, serializable directly to the circom
/// input JSON (all values decimal strings; signal names match the circuit).
///
/// The first six fields (+ zero-padded `cmxs`) are also the proof's PUBLIC signals in
/// on-chain order; `new_root` / `new_frontier_commit` / `j` are the `updateRoot` args.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmxConfirmWitnessInput {
    pub old_root: String,
    pub new_root: String,
    pub j: String,
    pub start_idx: String,
    pub old_frontier_commit: String,
    pub new_frontier_commit: String,
    /// Length [`CMX_CONFIRM_MAX_BATCH`], zero-padded beyond `j`.
    pub cmxs: Vec<String>,
    /// Length [`MERKLE_DEPTH_EVM`] — the private frontier before the batch.
    pub filled_start: Vec<String>,
}

impl CmxConfirmWitnessInput {
    /// `new_root` as big-endian bytes (the `updateRoot(newRoot, ...)` argument).
    pub fn new_root_be(&self) -> [u8; 32] {
        dec_to_be(&self.new_root)
    }

    /// `new_frontier_commit` as big-endian bytes (the `updateRoot(_, newFrontierCommit, ...)` argument).
    pub fn new_frontier_commit_be(&self) -> [u8; 32] {
        dec_to_be(&self.new_frontier_commit)
    }

    pub fn batch_size(&self) -> u64 {
        self.j.parse().expect("j is a small decimal")
    }
}

// ─── Fr conversion helpers ───────────────────────────────────────────────────

/// Big-endian 32 bytes (EVM representation) → `Fr`.
fn fr_from_be(be: [u8; 32]) -> Fr {
    let mut le = be;
    le.reverse();
    let mut limbs = [0u64; 4];
    for (i, chunk) in le.chunks(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fr::from_raw(limbs)
}

/// `Fr` → decimal string (circom witness format).
fn fr_dec(f: Fr) -> String {
    let le: [u8; 32] = f.to_repr().into();
    let mut be = le;
    be.reverse();
    ethabi::Uint::from_big_endian(&be).to_string()
}

/// Decimal string → big-endian 32 bytes.
fn dec_to_be(dec: &str) -> [u8; 32] {
    let u = ethabi::Uint::from_dec_str(dec).expect("valid decimal field element");
    let mut be = [0u8; 32];
    u.to_big_endian(&mut be);
    be
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be_from_dec(dec: &str) -> [u8; 32] {
        dec_to_be(dec)
    }

    fn hex_be(f: Fr) -> String {
        let le: [u8; 32] = f.to_repr().into();
        let mut be = le;
        be.reverse();
        hex::encode(be)
    }

    /// Empty tree root must match `IncrementalMerkleTree._empty(32)`.
    #[test]
    fn empty_root_matches_solidity() {
        let t = FrontierTree::new();
        assert_eq!(
            hex_be(t.root()),
            "2cbe967b6ba6d0faa4e84ea623d11dc747854fd32ecaa48c721635243d37d79f"
        );
    }

    /// Empty frontier commit must match `OrchardVerifier.EMPTY_FRONTIER_COMMIT`.
    #[test]
    fn empty_frontier_commit_matches_solidity() {
        let t = FrontierTree::new();
        assert_eq!(
            hex_be(t.frontier_commit()),
            "0ce89a5624d1c1af332a9f84362034d56886c5f947016df67ce3eb79b99d3ae7"
        );
    }

    /// insert(42) root matches the shared Rust/Solidity test vector.
    #[test]
    fn insert_42_matches_test_vector() {
        let mut t = FrontierTree::new();
        t.insert(Fr::from(42u64));
        assert_eq!(
            hex_be(t.root()),
            "261dd3eef09f9ac35c2e82979754b65461b0f080913bf780964fb30281c0c77e"
        );
    }

    /// insert(1); insert(2) root matches the shared test vector.
    #[test]
    fn insert_1_2_matches_test_vector() {
        let mut t = FrontierTree::new();
        t.insert(Fr::from(1u64));
        t.insert(Fr::from(2u64));
        assert_eq!(
            hex_be(t.root()),
            "2acffa6ebc8752bc99668a083a482d3d0cec6ed4af1d191ac5dc727616593140"
        );
    }

    /// The frontier tree must agree with the full leaf-retaining tree on every prefix.
    #[test]
    fn agrees_with_full_tree() {
        use crate::commitment_tree::poseidon::Bn254IncrementalMerkleTree;
        let mut frontier = FrontierTree::new();
        let mut full = Bn254IncrementalMerkleTree::new();
        for i in 1..=10u64 {
            frontier.insert(Fr::from(i));
            full.append(Fr::from(i));
            assert_eq!(frontier.root(), full.root(), "roots diverge at leaf {i}");
        }
    }

    /// Batch planning must reproduce the values the PERC20 repo's
    /// `GenCmxConfirmInput.s.sol` computed with the on-chain Solidity library for the
    /// e2e fixture batch [mint.cmx, transfer.cmx] (cross-repo byte-identity guard).
    #[test]
    fn plan_batch_matches_solidity_fixture() {
        let mint_cmx = be_from_dec(
            "16480947339746236445511836301455569813334427373054934043584406824035215413176",
        );
        let transfer_cmx = be_from_dec(
            "8268269749193277398124845699527794385688556813252661595554201322283837913615",
        );
        let mut t = FrontierTree::new();
        let input = t.plan_batch(&[mint_cmx, transfer_cmx]);

        assert_eq!(
            hex::encode(input.new_root_be()),
            "18a7284a20fd427d93f42f353fe029b8daac1cb76b3aa87752589b9d0d7efee9"
        );
        assert_eq!(
            hex::encode(input.new_frontier_commit_be()),
            "05f82f90d7593170e1e09d2ab7a2ed9c803b05901fb2aff76d12e6b5586c1974"
        );
        assert_eq!(input.j, "2");
        assert_eq!(input.start_idx, "0");
        assert_eq!(input.batch_size(), 2);
        assert_eq!(input.cmxs.len(), CMX_CONFIRM_MAX_BATCH);
        assert_eq!(input.cmxs[2], "0", "padding beyond j is zero");
        assert_eq!(input.filled_start.len(), MERKLE_DEPTH_EVM);
        // Post-batch state advanced.
        assert_eq!(t.next_index(), 2);
        assert_eq!(hex_be(t.root()), hex::encode(input.new_root_be()));
    }
}
