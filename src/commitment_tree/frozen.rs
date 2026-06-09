//! Frozen-set (compliance blacklist) **Indexed Merkle Tree** over BN254 `Fr`.
//!
//! Mirrors PERC20 `circuits/frozen_cmx_nonmember.circom` and the prover's
//! `poseidon_merkle_bn254` IMT helpers — the root produced here is the on-chain
//! `cmxFrozenRoot()` / circuit `rt_frozen` and **must** match byte-for-byte.
//!
//! Non-membership of `cmx` is proven by a single Merkle inclusion of a sorted
//! "low-leaf" `(val, next_val)` that strictly brackets it (`val < cmx < next_val`,
//! `next_val == 0` being the +inf sentinel). The tree is kept as a sorted linked
//! list: inserting `v` splices it after its predecessor (update the predecessor's
//! `next`, append the new leaf). Depth bounds the blacklist *capacity* (`2^DEPTH`),
//! not the key space, so distinct `cmx` never collide regardless of depth.

use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;

use super::poseidon::poseidon_domain_pair;

/// Indexed-MT depth = log2(capacity). Must equal circom `FROZEN_IMT_DEPTH()` and
/// `poseidon_merkle_bn254::FROZEN_IMT_DEPTH`.
pub const FROZEN_IMT_DEPTH: usize = 20;
/// Leaf domain: `leaf = Poseidon(LEAF_DOMAIN, val, next_val)`.
pub const FROZEN_IMT_LEAF_DOMAIN: u64 = 240;
/// Internal-node domain base: node at level `i` = `Poseidon(NODE_D0 + i, left, right)`.
pub const FROZEN_IMT_NODE_D0: u64 = 256;

/// Low-leaf hash, matching `FrozenCmxNonMember`'s `leaf` gate.
#[inline]
pub fn frozen_imt_leaf(val: Fr, next_val: Fr) -> Fr {
    poseidon_domain_pair(FROZEN_IMT_LEAF_DOMAIN, val, next_val)
}

/// Canonical unsigned compare `a < b` over `Fr` (via little-endian `to_repr`).
fn fr_lt(a: &Fr, b: &Fr) -> bool {
    let (ar, br) = (a.to_repr(), b.to_repr());
    let (a, b) = (ar.as_ref(), br.as_ref());
    // `to_repr` is little-endian; compare most-significant byte first.
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Big-endian 32 bytes (EVM `uint256`) → `Fr`. `None` if not a canonical field element.
pub fn fr_from_be_bytes(be: &[u8; 32]) -> Option<Fr> {
    let mut le = *be;
    le.reverse();
    Option::from(Fr::from_repr(le.into()))
}

/// `Fr` → little-endian 32 bytes (the indexer's on-the-wire convention).
pub fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
    fr.to_repr().into()
}

/// `Fr` → big-endian 32 bytes (EVM `uint256` order; inverse of [`fr_from_be_bytes`]).
pub fn fr_to_be_bytes(fr: Fr) -> [u8; 32] {
    let mut be = fr_to_le_bytes(fr);
    be.reverse();
    be
}

/// `Fr` → `0x`-prefixed little-endian 32-byte hex (matches `/merkle_path` siblings).
pub fn fr_to_le_hex(fr: Fr) -> String {
    format!("0x{}", hex::encode(fr_to_le_bytes(fr)))
}

#[derive(Clone, Copy, Debug)]
struct Leaf {
    val: Fr,
    next_val: Fr,
}

/// Non-membership witness for one `cmx`, matching `FrozenCmxNonMember`'s inputs.
#[derive(Clone, Debug)]
pub struct FrozenNonMembershipWitness {
    pub low_val: Fr,
    pub low_next_val: Fr,
    pub siblings: [Fr; FROZEN_IMT_DEPTH],
    pub path_bits: [Fr; FROZEN_IMT_DEPTH],
}

/// Sorted Indexed Merkle Tree of frozen `cmx` values.
#[derive(Clone, Debug)]
pub struct FrozenImt {
    /// Leaves in insertion order; `leaves[0]` is always the `{0, 0}` sentinel
    /// (val 0, next +inf) so that an empty blacklist still brackets every `cmx > 0`.
    leaves: Vec<Leaf>,
}

impl FrozenImt {
    /// Empty blacklist: just the `{0, 0}` sentinel at index 0.
    pub fn new() -> Self {
        Self { leaves: vec![Leaf { val: Fr::ZERO, next_val: Fr::ZERO }] }
    }

    /// Rebuild a tree from its frozen values (e.g. a persisted checkpoint), in
    /// the order they were inserted. Positions are reproduced exactly.
    pub fn from_frozen_values(values: &[Fr]) -> Self {
        let mut t = Self::new();
        for &v in values {
            t.insert(v);
        }
        t
    }

    /// Number of leaves (including the sentinel).
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// The frozen values in insertion order, excluding the `{0,0}` sentinel.
    pub fn frozen_values(&self) -> Vec<Fr> {
        self.leaves[1..].iter().map(|l| l.val).collect()
    }

    /// True if `v` is currently frozen.
    pub fn contains(&self, v: Fr) -> bool {
        self.leaves.iter().any(|l| l.val == v)
    }

    /// Freeze `v` by splicing it after its predecessor. Returns `false` (no-op) if
    /// `v` is already frozen or `v == 0` (the reserved sentinel value).
    pub fn insert(&mut self, v: Fr) -> bool {
        if v == Fr::ZERO || self.contains(v) {
            return false;
        }
        let pred = self.bracketing_index(v);
        let new_leaf = Leaf { val: v, next_val: self.leaves[pred].next_val };
        self.leaves[pred].next_val = v;
        self.leaves.push(new_leaf);
        true
    }

    /// Index of the leaf whose interval `(val, next_val)` contains `v`
    /// (`next_val == 0` = +inf). For a well-formed tree exactly one such leaf
    /// exists when `v` is not itself a leaf value.
    fn bracketing_index(&self, v: Fr) -> usize {
        for (i, l) in self.leaves.iter().enumerate() {
            let above_low = fr_lt(&l.val, &v);
            let below_high = l.next_val == Fr::ZERO || fr_lt(&v, &l.next_val);
            if above_low && below_high {
                return i;
            }
        }
        0 // unreachable for a well-formed tree; fall back to the sentinel.
    }

    #[inline]
    fn leaf_hash(&self, i: usize) -> Fr {
        frozen_imt_leaf(self.leaves[i].val, self.leaves[i].next_val)
    }

    /// Digest of an all-empty subtree of height `level` (empty leaf slot = 0).
    fn empty_at(&self, level: usize) -> Fr {
        let mut e = Fr::ZERO;
        for i in 0..level {
            e = poseidon_domain_pair(FROZEN_IMT_NODE_D0 + i as u64, e, e);
        }
        e
    }

    /// Hash of the subtree rooted at `(level, idx)` (recursive, empty-padded).
    fn subtree_hash(&self, level: usize, idx: usize) -> Fr {
        let start = idx << level;
        if start >= self.leaves.len() {
            return self.empty_at(level);
        }
        if level == 0 {
            return self.leaf_hash(start);
        }
        let left = self.subtree_hash(level - 1, idx * 2);
        let right = self.subtree_hash(level - 1, idx * 2 + 1);
        poseidon_domain_pair(FROZEN_IMT_NODE_D0 + (level - 1) as u64, left, right)
    }

    /// Compliance root `rt_frozen`.
    pub fn root(&self) -> Fr {
        self.subtree_hash(FROZEN_IMT_DEPTH, 0)
    }

    /// Authentication path (siblings + path bits) for the leaf at `pos`.
    fn witness_at(&self, pos: usize) -> ([Fr; FROZEN_IMT_DEPTH], [Fr; FROZEN_IMT_DEPTH]) {
        let mut siblings = [Fr::ZERO; FROZEN_IMT_DEPTH];
        let mut path_bits = [Fr::ZERO; FROZEN_IMT_DEPTH];
        for level in 0..FROZEN_IMT_DEPTH {
            path_bits[level] = if (pos >> level) & 1 == 1 { Fr::ONE } else { Fr::ZERO };
            siblings[level] = self.subtree_hash(level, (pos >> level) ^ 1);
        }
        (siblings, path_bits)
    }

    /// Non-membership witness for `cmx`, or `None` if `cmx` is currently frozen.
    pub fn non_membership_witness(&self, cmx: Fr) -> Option<FrozenNonMembershipWitness> {
        if self.contains(cmx) {
            return None;
        }
        let pos = self.bracketing_index(cmx);
        let low = self.leaves[pos];
        let (siblings, path_bits) = self.witness_at(pos);
        Some(FrozenNonMembershipWitness {
            low_val: low.val,
            low_next_val: low.next_val,
            siblings,
            path_bits,
        })
    }
}

impl Default for FrozenImt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty-blacklist root must match the PERC20 prover / circuit constant
    /// (`poseidon_merkle_bn254::frozen_empty_tree_root` → MAINNET_RT_FROZEN_DEC).
    #[test]
    fn empty_root_matches_perc20_constant() {
        const DEC: &str =
            "9079151408671112139333676443195611613776084922747126087146403043120709007371";
        let expected = Fr::from_str_vartime(DEC).unwrap();
        assert_eq!(FrozenImt::new().root(), expected);
    }

    /// A non-membership witness recomputes the live root (mirrors the circuit's
    /// inclusion check) and brackets the queried cmx.
    #[test]
    fn witness_reproduces_root_and_brackets() {
        let mut t = FrozenImt::new();
        for v in [50u64, 10, 99, 7] {
            assert!(t.insert(Fr::from(v)));
        }
        let root = t.root();
        let cmx = Fr::from(42u64); // not frozen; sits between 10 and 50
        let w = t.non_membership_witness(cmx).expect("non-member");
        assert!(fr_lt(&w.low_val, &cmx));
        assert!(w.low_next_val == Fr::ZERO || fr_lt(&cmx, &w.low_next_val));
        assert_eq!(recompute_root(&w), root, "witness must reproduce rt_frozen");
    }

    /// A frozen value has no non-membership witness.
    #[test]
    fn frozen_value_has_no_witness() {
        let mut t = FrozenImt::new();
        t.insert(Fr::from(123u64));
        assert!(t.non_membership_witness(Fr::from(123u64)).is_none());
    }

    /// Rebuilding from `frozen_values()` reproduces the exact same tree (positions
    /// and therefore root) — the property persistence relies on. (The IMT root is
    /// position-dependent, so insertion order is part of the committed state and is
    /// preserved by replaying values in order.)
    #[test]
    fn rebuild_from_values_reproduces_root() {
        let mut t = FrozenImt::new();
        for v in [3u64, 1, 4, 1, 5, 9, 2, 6] {
            t.insert(Fr::from(v));
        }
        let rebuilt = FrozenImt::from_frozen_values(&t.frozen_values());
        assert_eq!(rebuilt.frozen_values(), t.frozen_values());
        assert_eq!(rebuilt.root(), t.root());
    }

    /// Recompute the IMT root from a witness exactly as `FrozenCmxNonMember` does.
    fn recompute_root(w: &FrozenNonMembershipWitness) -> Fr {
        let mut level = frozen_imt_leaf(w.low_val, w.low_next_val);
        for i in 0..FROZEN_IMT_DEPTH {
            let bit = w.path_bits[i];
            let diff = level - w.siblings[i];
            let left = level - bit * diff;
            let right = w.siblings[i] + bit * diff;
            level = poseidon_domain_pair(FROZEN_IMT_NODE_D0 + i as u64, left, right);
        }
        level
    }
}
