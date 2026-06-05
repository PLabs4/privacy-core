//! Calldata encoding for `PrivacyBTC.sol` — all operations go through `bundle()`.
//!
//! valueBalance encoding (sign-bit / readable int64 convention, mirrors Zcash §7.1):
//!   0                     → transfer  (Σv_old == Σv_new)
//!   +amount  (bit255 = 0) → unshield  (value leaving pool, positive satoshis)
//!   -amount  (bit255 = 1) → shield    (value entering pool, high bit = sign)
//!
//! The raw satoshi count is always stored in the lower 64 bits; bit 255 is the sign.
//! When doing BJJ cryptography (BindingSig), the contract/prover decodes the sign
//! and computes the actual scalar: positive → scalar, negative → ℓ − scalar.

pub mod groth16_proof;
pub use groth16_proof::{
    encode_groth16_proof_components, encode_groth16_proof_from_snarkjs_json,
    p_a_from_snarkjs_pi_a, p_b_from_snarkjs_pi_b, p_c_from_snarkjs_pi_c, Groth16ProofError,
};

mod bundle_decode;
mod events;
pub use bundle_decode::{
    bundle_actions_by_cmx, decode_bundle_calldata, BundleActionCiphertexts, BundleDecodeError,
};
pub use events::{
    decode_note_added_log, decode_note_confirmed_log, decode_shield_completed_log,
    note_added_legacy_topic0_hex, note_added_topic0_alternatives, note_added_topic0_hex,
    note_confirmed_topic0_hex, shield_completed_topic0_hex,
    DecodedNoteAdded, LogDecodeError,
};

use ethabi::{encode, Token, Uint};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EthEncodeError {
    #[error("enc_ciphertext must be 580 bytes (Orchard in-band), got {0}")]
    BadEncLen(usize),
}

// ── bundle(BundleAction[],uint256,uint256,bytes32,uint256[3]) ─────────────────

/// One action passed to `bundle()`.
#[derive(Debug, Clone)]
pub struct BundleActionArgs {
    pub cmx: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub epk: [u8; 32],
    pub nf_old: [u8; 32],
    pub anchor: [u8; 32],
    pub proof: Vec<u8>,
    /// 8 BN254 calldata fields: [anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, rt_frozen].
    pub pub_fields: [[u8; 32]; 8],
    pub spend_auth_sig: [[u8; 32]; 3],
}

/// Arguments for
/// `bundle(BundleAction[],uint256,uint256,bytes32,uint256[3])`.
#[derive(Debug, Clone)]
pub struct BundleCalldataArgs {
    pub actions: Vec<BundleActionArgs>,
    /// Net value balance (Fr element BE); 0x00 for pure transfer, +v for unshield, Fr−v for shield.
    pub value_balance: [u8; 32],
    /// Absolute satoshi amount for unshield; 0 for transfer.
    pub amount: u64,
    /// BTC recipient hash for unshield; [0u8; 32] for transfer.
    pub recipient_meta: [u8; 32],
    /// Baby JubJub Schnorr binding signature [Rx, Ry, s]; bsk = Σ rcv_i.
    pub binding_sig: [[u8; 32]; 3],
}

/// First 4 bytes of
/// `keccak256("bundle((bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[],…")`.
pub fn bundle_function_selector() -> [u8; 4] {
    Keccak256::digest(
        b"bundle((bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[],uint256,uint256,bytes32,uint256[3])",
    )[..4]
    .try_into()
    .expect("selector is 4 bytes")
}

/// ABI-encode `bundle` calldata (selector + body).
pub fn encode_bundle_calldata(args: &BundleCalldataArgs) -> Result<Vec<u8>, EthEncodeError> {
    let actions_token = Token::Array(
        args.actions
            .iter()
            .map(|a| {
                let pub_fields_token = Token::FixedArray(
                    a.pub_fields
                        .iter()
                        .map(|b| Token::Uint(ethabi::Uint::from_big_endian(b)))
                        .collect(),
                );
                let spend_auth_sig_token = Token::FixedArray(
                    a.spend_auth_sig
                        .iter()
                        .map(|b| Token::Uint(ethabi::Uint::from_big_endian(b)))
                        .collect(),
                );
                Token::Tuple(vec![
                    Token::FixedBytes(a.cmx.to_vec()),
                    Token::Bytes(a.enc_ciphertext.clone()),
                    Token::Bytes(a.out_ciphertext.clone()),
                    Token::FixedBytes(a.epk.to_vec()),
                    Token::FixedBytes(a.nf_old.to_vec()),
                    Token::FixedBytes(a.anchor.to_vec()),
                    Token::Bytes(a.proof.clone()),
                    pub_fields_token,
                    spend_auth_sig_token,
                ])
            })
            .collect(),
    );
    let binding_sig_token = Token::FixedArray(
        args.binding_sig
            .iter()
            .map(|b| Token::Uint(ethabi::Uint::from_big_endian(b)))
            .collect(),
    );
    let tokens = vec![
        actions_token,
        Token::Uint(ethabi::Uint::from_big_endian(&args.value_balance)),
        Token::Uint(ethabi::Uint::from(args.amount)),
        Token::FixedBytes(args.recipient_meta.to_vec()),
        binding_sig_token,
    ];
    let body = encode(&tokens);
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&bundle_function_selector());
    out.extend_from_slice(&body);
    Ok(out)
}

// ── Baby Jubjub binding Schnorr (matches `BindingSignature.verify`) ──────────

/// EIP-2494 prime subgroup order ℓ (`curve_order = 8·ℓ`; differs from BN254 field modulus).
pub const BJJ_SUBGROUP_ORDER_DEC: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

#[inline]
fn bjj_subgroup_order() -> Uint {
    Uint::from_dec_str(BJJ_SUBGROUP_ORDER_DEC).expect("valid EIP-2494 subgroup constant")
}

/// Interpret digest / coefficient integer modulo ℓ (challenge scalar).
#[inline]
pub fn reduce_mod_bjj_subgroup(v: Uint) -> Uint {
    let l = bjj_subgroup_order();
    v % l
}

/// Fiat–Shamir challenge `e = keccak256(R ‖ bvk ‖ sighash) mod ℓ`.
pub fn binding_challenge_e_bn254(
    r_x_be32: &[u8; 32],
    r_y_be32: &[u8; 32],
    bvk_x_be32: &[u8; 32],
    bvk_y_be32: &[u8; 32],
    sighash: &[u8; 32],
) -> Uint {
    let mut h = Keccak256::new();
    h.update(r_x_be32);
    h.update(r_y_be32);
    h.update(bvk_x_be32);
    h.update(bvk_y_be32);
    h.update(sighash);
    let digest: [u8; 32] = h.finalize().into();
    reduce_mod_bjj_subgroup(Uint::from_big_endian(&digest))
}

/// (a * b) mod m using binary doubling — avoids U256 overflow for ~251-bit inputs.
fn mulmod(mut a: Uint, mut b: Uint, m: Uint) -> Uint {
    let mut result = Uint::zero();
    a %= m;
    while !b.is_zero() {
        if b.bit(0) {
            result = (result + a) % m;
        }
        a = (a + a) % m;
        b >>= 1;
    }
    result
}

/// Schnorr scalar `s = (r + e·bsk) mod ℓ`.
#[inline]
pub fn binding_s_scalar_bn254(r_nonce: Uint, e: Uint, bsk: Uint) -> Uint {
    let l = bjj_subgroup_order();
    let r = r_nonce % l;
    let e = e % l;
    let bsk = bsk % l;
    let prod = mulmod(e, bsk, l);
    (r + prod) % l
}

#[inline]
pub fn uint_to_be32(u: &Uint) -> [u8; 32] {
    let mut out = [0u8; 32];
    u.to_big_endian(&mut out);
    out
}

/// Circom / snarkjs decimal field element → 32-byte big-endian for ABI `uint256`.
pub fn circom_field_dec_to_be32(dec: &str) -> [u8; 32] {
    uint_to_be32(
        &Uint::from_dec_str(dec.trim()).expect("circom decimal field element"),
    )
}

/// BN254 `Fr` limb repr (little-endian per `ff`) → big-endian uint, reduced mod ℓ.
#[inline]
pub fn uint_mod_subgroup_from_bn254_fr_repr_le(repr_le: &[u8; 32]) -> Uint {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = repr_le[31 - i];
    }
    reduce_mod_bjj_subgroup(Uint::from_big_endian(&be))
}

/// Sum multiple rcv scalars modulo ℓ (BJJ subgroup order) and return the result
/// as a canonical little-endian `[u8; 32]` suitable for `Fr::from_repr`.
///
/// Using BN254 Fr addition (`mod r`) for this sum is WRONG because `ℓ ≪ r`:
/// when `rcv0 + rcv1 ≥ r`, Fr wraps modulo `r`, but the BJJ group reduces mod ℓ,
/// so `bsk_fr mod ℓ ≠ Σ rcv_i mod ℓ`, breaking `bvk = bsk · G_RANDOM`.
pub fn sum_rcv_mod_bjj(rcv_le_slices: &[[u8; 32]]) -> [u8; 32] {
    let l = bjj_subgroup_order();
    let mut acc = Uint::from(0u64);
    for rcv in rcv_le_slices {
        let u = uint_mod_subgroup_from_bn254_fr_repr_le(rcv);
        // Use checked add + manual mod to avoid overflow of U256 on adversarial input.
        acc = (acc + u) % l;
    }
    let be = uint_to_be32(&acc);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    le
}

// ── BindingSignature.buildSighash (Solidity `abi.encodePacked` mirror) ───────

/// BN254 scalar field modulus as big-endian `uint256` (matches `BabyJubJub.Fr`).
pub const BN254_FR_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
    0xfd, 0x47,
];

#[derive(Debug, Error)]
pub enum BindingSighashError {
    #[error("pool_address must be 20-byte hex (40 hex chars), got len {0}")]
    BadPoolAddress(usize),
    #[error("invalid hex: {0}")]
    Hex(String),
}

/// Encode `chainId` as 32-byte big-endian `uint256` for packed sighash preimage.
pub fn u256_be_chain_id(chain_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&chain_id.to_be_bytes());
    out
}

/// Unified `valueBalance` encoder (sign-bit convention, mirrors Zcash protocol §7.1).
///
/// Encoding:
///   transfer:  `[0u8; 32]`                      → 0 (balanced)
///   unshield:  `bundle_value_balance_be(v, false)` → +v (bit255=0, positive satoshis)
///   shield:    `bundle_value_balance_be(v, true)`  → high-bit flag + v (bit255=1, negative)
///
/// The BindingSignature contract (and prover) decode the sign bit to get the BJJ
/// scalar for bvk computation:
///   bit255=0  → scalar = amount_sats  (unshield: bvk = Σcv − amount·G_VALUE)
///   bit255=1  → scalar = ℓ − amount   (shield:   bvk = Σcv + amount·G_VALUE)
pub fn bundle_value_balance_be(amount_sats: u64, negative: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&amount_sats.to_be_bytes());
    if negative {
        out[0] |= 0x80; // set bit 255 as sign flag
    }
    out
}

/// Decode a sign-bit-encoded `valueBalance` into `(abs_amount_sats, is_negative)`.
pub fn decode_value_balance_be(vb: &[u8; 32]) -> (u64, bool) {
    let negative = (vb[0] & 0x80) != 0;
    let amount = u64::from_be_bytes(vb[24..32].try_into().unwrap());
    (amount, negative)
}

/// Decode a sign-bit-encoded `valueBalance` into the actual BJJ subgroup scalar
/// suitable for `scalarMul(G_VALUE, scalar)` in BindingSignature verification.
///
///   bit255=0 (positive, unshield): scalar = amount_sats
///   bit255=1 (negative, shield):   scalar = ℓ − amount_sats  (additive inverse mod ℓ)
pub fn value_balance_to_bjj_scalar_be(vb: &[u8; 32]) -> [u8; 32] {
    let (amount, negative) = decode_value_balance_be(vb);
    if !negative || amount == 0 {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&amount.to_be_bytes());
        out
    } else {
        // ℓ − amount  (BJJ subgroup order minus abs value)
        let l = bjj_subgroup_order();
        let amt: Uint = amount.into();
        uint_to_be32(&(l - amt % l))
    }
}

// ── Deprecated helpers kept for reference ─────────────────────────────────────

/// Deprecated: use `bundle_value_balance_be(amount, false)` instead.
#[deprecated(note = "use bundle_value_balance_be(amount, false)")]
pub fn shield_bundle_value_balance_be(amount_sats: u64) -> [u8; 32] {
    bundle_value_balance_be(amount_sats, false)
}

/// Deprecated: use `bundle_value_balance_be(amount, true)` instead.
#[deprecated(note = "use bundle_value_balance_be(amount, true)")]
pub fn shield_bundle_value_balance_subgroup_neg_be(amount_sats: u64) -> [u8; 32] {
    bundle_value_balance_be(amount_sats, true)
}

/// Parse `0x`-prefixed 20-byte contract address.
pub fn parse_pool_address_hex(addr: &str) -> Result<[u8; 20], BindingSighashError> {
    let clean = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(clean).map_err(|e| BindingSighashError::Hex(e.to_string()))?;
    if bytes.len() != 20 {
        return Err(BindingSighashError::BadPoolAddress(bytes.len()));
    }
    Ok(bytes.try_into().unwrap())
}

/// Parse `0x`-prefixed 32-byte hash / field element (canonical BE layout).
pub fn parse_bytes32_hex(s: &str) -> Result<[u8; 32], BindingSighashError> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).map_err(|e| BindingSighashError::Hex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(BindingSighashError::Hex(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes.try_into().unwrap())
}

/// Keccak256 preimage matching `BindingSignature.buildSighash`:
/// `abi.encodePacked("PrivacyPool.bundle.v1", chainId, pool, nullifiers[], commitments[], valueBalance, recipientMeta)`.
pub fn binding_sighash_privacy_pool_bundle_v1(
    chain_id_be32: &[u8; 32],
    contract_addr_20: &[u8; 20],
    nullifiers: &[[u8; 32]],
    commitments: &[[u8; 32]],
    value_balance_be32: &[u8; 32],
    recipient_meta: &[u8; 32],
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"PrivacyPool.bundle.v1");
    h.update(chain_id_be32);
    h.update(contract_addr_20);
    for nf in nullifiers {
        h.update(nf);
    }
    for cm in commitments {
        h.update(cm);
    }
    h.update(value_balance_be32);
    h.update(recipient_meta);
    h.finalize().into()
}

/// Keccak256 preimage matching `SpendAuthSignature.buildSighash`:
/// `abi.encodePacked("SpendAuth.action.v1", chainId, contractAddr,
///                   nfOld, cmx, epk, keccak256(encCiphertext), keccak256(outCiphertext))`.
///
/// Mirrors the Solidity `SpendAuthSignature.buildSighash` exactly.
pub fn spend_auth_sighash_v1(
    chain_id_be32: &[u8; 32],
    contract_addr_20: &[u8; 20],
    nf_old_be32: &[u8; 32],
    cmx_be32: &[u8; 32],
    epk_be32: &[u8; 32],
    enc_ciphertext: &[u8],
    out_ciphertext: &[u8],
) -> [u8; 32] {
    let enc_hash: [u8; 32] = Keccak256::digest(enc_ciphertext).into();
    let out_hash: [u8; 32] = Keccak256::digest(out_ciphertext).into();
    let mut h = Keccak256::new();
    h.update(b"SpendAuth.action.v1");
    h.update(chain_id_be32);
    h.update(contract_addr_20);
    h.update(nf_old_be32);
    h.update(cmx_be32);
    h.update(epk_be32);
    h.update(&enc_hash);
    h.update(&out_hash);
    h.finalize().into()
}

// ── finalizeWithdraw(bytes32,uint256,bytes32) — legacy relayer path ──────────

/// Arguments for `finalizeWithdraw(bytes32,uint256,bytes32)`.
///
/// Legacy federation-trusted path — kept for backward-compat.
/// New deployments should prefer `unshield()`.
#[derive(Debug, Clone)]
pub struct FinalizeWithdrawCalldataArgs {
    pub nf: [u8; 32],
    pub amount_sats: u64,
    pub recipient_meta: [u8; 32],
}

/// First 4 bytes of `keccak256("finalizeWithdraw(bytes32,uint256,bytes32)")`.
pub fn finalize_withdraw_function_selector() -> [u8; 4] {
    Keccak256::digest(b"finalizeWithdraw(bytes32,uint256,bytes32)")[..4]
        .try_into()
        .expect("selector is 4 bytes")
}

/// ABI-encode `finalizeWithdraw` calldata (selector + body).
pub fn encode_finalize_withdraw_calldata(args: &FinalizeWithdrawCalldataArgs) -> Vec<u8> {
    let tokens = vec![
        Token::FixedBytes(args.nf.to_vec()),
        Token::Uint(args.amount_sats.into()),
        Token::FixedBytes(args.recipient_meta.to_vec()),
    ];
    let body = encode(&tokens);
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&finalize_withdraw_function_selector());
    out.extend_from_slice(&body);
    out
}

// ── PrivacyERC.shield() calldata ──────────────────────────────────────────────
//
// Signature:
//   shield(
//     (bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[] actions,
//     uint256 amount,
//     address owner,
//     uint256 deadline,
//     uint8   v,
//     bytes32 r,
//     bytes32 s,
//     uint256[3] bindingSig
//   )
//
// For native ETH pools (isNativeEth=true) the permit params (owner/deadline/v/r/s)
// are ignored by the contract; pass zeroes.

/// Arguments for `PrivacyERC.shield()`.
#[derive(Debug, Clone)]
pub struct ErcShieldCalldataArgs {
    pub actions: Vec<BundleActionArgs>,
    /// Token amount in the token's smallest unit (wei / 6-decimal USDC unit / …).
    pub amount: u128,
    /// EIP-2612 permit: token owner address (20 bytes, right-padded to 32).
    pub owner: [u8; 20],
    /// EIP-2612 permit: expiry unix timestamp.
    pub deadline: u64,
    /// EIP-2612 permit: signature v (1 byte).
    pub permit_v: u8,
    /// EIP-2612 permit: signature r (32 bytes).
    pub permit_r: [u8; 32],
    /// EIP-2612 permit: signature s (32 bytes).
    pub permit_s: [u8; 32],
    /// Baby JubJub Schnorr binding signature [Rx, Ry, s].
    pub binding_sig: [[u8; 32]; 3],
}

/// First 4 bytes of the `PrivacyERC.shield()` function selector.
pub fn erc_shield_function_selector() -> [u8; 4] {
    Keccak256::digest(
        b"shield((bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[],uint256,address,uint256,uint8,bytes32,bytes32,uint256[3])",
    )[..4]
    .try_into()
    .expect("selector is 4 bytes")
}

/// ABI-encode `PrivacyERC.shield()` calldata (selector + body).
pub fn encode_erc_shield_calldata(args: &ErcShieldCalldataArgs) -> Result<Vec<u8>, EthEncodeError> {
    let actions_token = Token::Array(
        args.actions
            .iter()
            .map(|a| {
                if a.enc_ciphertext.len() != 580 {
                    return Err(EthEncodeError::BadEncLen(a.enc_ciphertext.len()));
                }
                let pub_fields_token = Token::FixedArray(
                    a.pub_fields
                        .iter()
                        .map(|x| Token::Uint(Uint::from_big_endian(x)))
                        .collect(),
                );
                let spend_auth_token = Token::FixedArray(
                    a.spend_auth_sig
                        .iter()
                        .map(|x| Token::Uint(Uint::from_big_endian(x)))
                        .collect(),
                );
                Ok(Token::Tuple(vec![
                    Token::FixedBytes(a.cmx.to_vec()),
                    Token::Bytes(a.enc_ciphertext.clone()),
                    Token::Bytes(a.out_ciphertext.clone()),
                    Token::FixedBytes(a.epk.to_vec()),
                    Token::FixedBytes(a.nf_old.to_vec()),
                    Token::FixedBytes(a.anchor.to_vec()),
                    Token::Bytes(a.proof.clone()),
                    pub_fields_token,
                    spend_auth_token,
                ]))
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    // owner address as ABI address token
    let owner_addr = ethabi::Address::from(args.owner);

    let binding_sig_token = Token::FixedArray(
        args.binding_sig
            .iter()
            .map(|x| Token::Uint(Uint::from_big_endian(x)))
            .collect(),
    );

    let tokens = vec![
        actions_token,
        Token::Uint(args.amount.into()),
        Token::Address(owner_addr),
        Token::Uint(args.deadline.into()),
        Token::Uint(args.permit_v.into()),
        Token::FixedBytes(args.permit_r.to_vec()),
        Token::FixedBytes(args.permit_s.to_vec()),
        binding_sig_token,
    ];

    let body = encode(&tokens);
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&erc_shield_function_selector());
    out.extend_from_slice(&body);
    Ok(out)
}

// ── PrivacyERC unshield helpers ───────────────────────────────────────────────

/// Encode an EVM address (20 bytes) into the 32-byte `recipientMeta` field used
/// by `PrivacyERC._onAssetRelease()`.  The address occupies the low 20 bytes
/// (right-aligned), matching `address(uint160(uint256(recipientMeta)))`.
pub fn evm_address_to_recipient_meta(addr: &[u8; 20]) -> [u8; 32] {
    let mut meta = [0u8; 32];
    meta[12..].copy_from_slice(addr);
    meta
}

/// Parse a 0x-prefixed EVM address hex string into 20 bytes.
pub fn parse_evm_address_hex(s: &str) -> Result<[u8; 20], BindingSighashError> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    if clean.len() != 40 {
        return Err(BindingSighashError::Hex(format!("expected 40 hex chars, got {}", clean.len())));
    }
    let bytes = hex::decode(clean).map_err(|e| BindingSighashError::Hex(e.to_string()))?;
    Ok(bytes.try_into().expect("40 hex chars = 20 bytes"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unshield_value_balance_roundtrip() {
        // Unshield: positive satoshis, bit255 = 0.
        let amount: u64 = 100_000;
        let vb = bundle_value_balance_be(amount, false);
        let mut expected = [0u8; 32];
        expected[24..32].copy_from_slice(&amount.to_be_bytes());
        assert_eq!(vb, expected);
    }

    #[test]
    fn finalize_withdraw_calldata_prefixes_selector() {
        let cd = encode_finalize_withdraw_calldata(&FinalizeWithdrawCalldataArgs {
            nf: [7u8; 32],
            amount_sats: 123_456,
            recipient_meta: [8u8; 32],
        });
        assert!(cd.len() > 4);
        assert_eq!(&cd[..4], &finalize_withdraw_function_selector());
    }

    /// Decode the actual failing calldata and inspect the BundleAction fields.
    #[test]
    fn decode_failing_calldata_fields() {
        // First 10468 bytes of the failing calldata (skip selector)
        let raw_hex = "00000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000005dc00000000000000000000000000000000000000000000000000000000000005dc00000000000000000000000000000000000000000000000000000000000000001c2fbf7c1d370880bd19943877bf41259025e4e877c56fbf26c4576b0e809b001d9022ffbe1768250cedb08257b1776b2f248a0854cd1a7245c42ae2c63ca5650446c7c76fa1736f7e8c47994073011a534af17c591b3d0b51e25b0c5cf57b5b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000202dab531982047374d79feb10ee3389c3aae694c9d9a76696f1d034c245ac8263000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000004a03955242e589537ceca6b866b35cc16bad5605602c8a2bee463bb72612b6dbd9004cc117c66893f069f160294b22653b890e04abe242379d2dd98956778386fd400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000000003de55e0d54c5787b64a73d7879b67b9386e7262c20b6963c32d543462bdbc0e16858a895cb5ac289f5af0f0ad2918d6167a63370ed12dd7cd2210e53b6daee004cc117c66893f069f160294b22653b890e04abe242379d2dd98956778386fd417bc7b3fea209a7f90bb47b68453956704bcc38c3d32b1e1ef3c1909ec559f871f4fa732aa884e7020dccf264cf39bfade91074f00ec7b684f170b18531c4d4b2dab531982047374d79feb10ee3389c3aae694c9d9a76696f1d034c245ac82630ba6a64dab4e9fa2f31c9f5a35f3a93c323b160c175398b260a271a094c0fa7713460b57b63c8619062eff726135cabd3a4faf6c56e51afbf173a885d698f5ec026015d5bd814267fb2c44bc2a2336dfa946866960315f49761800cae310ed2c0000000000000000000000000000000000000000000000000000000000000244";

        let body = hex::decode(raw_hex).expect("valid hex");

        let read_u256_at = |offset: usize| -> u128 {
            let word = &body[offset..offset+32];
            u128::from_be_bytes(word[16..32].try_into().unwrap())
        };
        let read_bytes32_at = |offset: usize| -> String {
            hex::encode(&body[offset..offset+32])
        };

        // Top-level layout
        println!("=== Top-level ===");
        println!("W0 offset_to_actions: {}", read_u256_at(0));
        println!("W1 valueBalance:       {}", read_u256_at(32));
        println!("W2 amount:             {}", read_u256_at(64));
        println!("W3 recipientMeta:      {}", read_bytes32_at(96));
        println!("W4 bindingSig[0]:      {}", read_bytes32_at(128));
        println!("W5 bindingSig[1]:      {}", read_bytes32_at(160));
        println!("W6 bindingSig[2]:      {}", read_bytes32_at(192));

        // actions[] starts at offset 224 (= 7*32)
        println!("\n=== actions[] at body offset 224 ===");
        println!("W7 length:             {}", read_u256_at(224));
        println!("W8 elem0 offset:       {}", read_u256_at(256));

        // struct elem 0 at body offset 288 (= 9*32)
        let s = 288_usize;
        println!("\n=== BundleAction[0] struct at body offset {} ===", s);
        println!("  cmx:           {}", read_bytes32_at(s));
        let enc_off = read_u256_at(s + 32)  as usize;
        let out_off = read_u256_at(s + 64)  as usize;
        let proof_off= read_u256_at(s + 192) as usize;  // slot 6 (192 = 6*32)
        println!("  enc_offset:    {} (0x{:x})", enc_off, enc_off);
        println!("  out_offset:    {} (0x{:x})", out_off, out_off);
        println!("  epk:           {}", read_bytes32_at(s + 96));
        println!("  nfOld:         {}", read_bytes32_at(s + 128));
        println!("  anchor:        {}", read_bytes32_at(s + 160));
        println!("  proof_offset:  {} (0x{:x}) [should be 1312 = 0x520]", proof_off, proof_off);
        println!("  pubInputs[0]:  {}", read_bytes32_at(s + 224));
        println!("  pubInputs[1]:  {}", read_bytes32_at(s + 256));
        println!("  pubInputs[6]:  {}", read_bytes32_at(s + 224 + 6*32));

        // Check what's at the proof data location
        let proof_data_body_off = s + proof_off;
        println!("\n=== Proof data at body offset {} (struct + {}) ===", proof_data_body_off, proof_off);
        if proof_data_body_off + 32 <= body.len() {
            let claimed_len = read_u256_at(proof_data_body_off);
            println!("  claimed length: {} (0x{:x})", claimed_len, claimed_len);
        } else {
            println!("  OUT OF BOUNDS (body len = {})", body.len());
        }

        // Check enc data
        let enc_abs = s + enc_off;
        if enc_abs + 32 <= body.len() {
            let enc_len = read_u256_at(enc_abs);
            println!("\nenc data at body offset {}: length = {} (expected 580)", enc_abs, enc_len);
        }

        // Confirm proof_offset is wrong
        assert_eq!(proof_off, 82, "confirmed proof_offset = 82 = 0x52 (BUG)");
        assert_ne!(proof_off, 1312, "proof_offset should be 1312 but it is 82");
    }
    ///
    /// BundleAction static header = 9 fields, all 32 bytes each in head:
    ///   cmx(32) + enc_off(32) + out_off(32) + epk(32) + nfOld(32)
    ///   + anchor(32) + proof_off(32) + pubFields[8](256) + spendAuth[3](96)
    ///   = 576 bytes total head
    ///
    /// Dynamic data layout:
    ///   enc  at offset 576        (32 len + 580 data padded to 608)  → end 576+640=1216
    ///   out  at offset 1216       (32 len +  80 data padded to  96)  → end 1216+128=1344
    ///   proof at offset 1344 = 0x540
    #[test]
    fn bundle_calldata_proof_offset_is_correct() {
        let proof_bytes = vec![0xabu8; 256]; // Groth16 abi.encode(pA,pB,pC) size
        let enc = vec![0u8; 580];
        let out = vec![0u8; 80];

        let cd = encode_bundle_calldata(&BundleCalldataArgs {
            actions: vec![BundleActionArgs {
                cmx:            [1u8; 32],
                enc_ciphertext: enc,
                out_ciphertext: out,
                epk:            [2u8; 32],
                nf_old:         [3u8; 32],
                anchor:         [4u8; 32],
                proof:          proof_bytes,
                pub_fields:     [[5u8; 32]; 8],
                spend_auth_sig: [[6u8; 32]; 3],
            }],
            value_balance:  [0u8; 32],
            amount:         0,
            recipient_meta: [0u8; 32],
            binding_sig:    [[7u8; 32]; 3],
        })
        .expect("encode_bundle_calldata failed");

        // Skip selector (4 bytes).  Body layout:
        //   W0  = offset_to_actions (= 0xe0 = 224)
        //   W1  = valueBalance
        //   W2  = amount
        //   W3  = recipientMeta
        //   W4-W6 = bindingSig[3]
        //   W7  = actions.length (1)
        //   W8  = offset_to_elem0 (32)
        //   W9  = struct elem0 starts here
        //
        // Within struct elem0 (offsets relative to W9):
        //   +0   = cmx
        //   +32  = enc_offset    ← should be 576 = 0x240
        //   +64  = out_offset    ← should be 1216 = 0x4c0
        //   +96  = epk
        //   +128 = nfOld
        //   +160 = anchor
        //   +192 = proof_offset  ← should be 1344 = 0x540
        //   +224..+479 = pubFields[8]
        //   +480..+575 = spendAuthSig[3]

        let body = &cd[4..]; // skip selector

        // struct elem0 starts at word 9 (= byte 288)
        let struct_start = 9 * 32_usize;

        let read_u256 = |offset: usize| -> u128 {
            let word = &body[offset..offset + 32];
            u128::from_be_bytes(word[16..32].try_into().unwrap())
        };

        let enc_offset   = read_u256(struct_start + 32);   // +32
        let out_offset   = read_u256(struct_start + 64);   // +64
        let proof_offset = read_u256(struct_start + 192);  // +192

        assert_eq!(enc_offset,   576,  "enc_offset should be 0x240 = 576");
        assert_eq!(out_offset,   1216, "out_offset should be 0x4c0 = 1216");
        assert_eq!(proof_offset, 1344, "proof_offset should be 0x540 = 1344, got {proof_offset:#x}");
    }
}
