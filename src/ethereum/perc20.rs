//! Calldata encoders for the pERC20 standard family — `PERC20` (issuer-minted) and
//! `WrappedPERC20` (backed shield/unshield) — plus the application-layer `SwapCoordinator`.
//!
//! These mirror the on-chain ABI exactly (see the PERC20 repo's `privacybtc-ethereum`):
//! every entrypoint takes a `PrivacyCall` tuple
//!   `(bytes actions, uint256[3] bindingSig)`
//! where `actions == abi.encode(IEndpointCore.BundleAction[])`. The relayer forwards the
//! already-signed bundle (v2 sighash, incl. `executor`) verbatim; it never re-signs.

use super::{BundleActionArgs, EthEncodeError};
use ethabi::{encode, Token, Uint};
use sha3::{Digest, Keccak256};

/// A `PrivacyCall` — an already-proved, already-signed bundle ready for submission.
#[derive(Debug, Clone)]
pub struct PrivacyCallArgs {
    pub actions: Vec<BundleActionArgs>,
    /// Baby JubJub Schnorr binding signature `[Rx, Ry, s]` over the v2 bundle sighash.
    pub binding_sig: [[u8; 32]; 3],
}

fn selector(signature: &[u8]) -> [u8; 4] {
    Keccak256::digest(signature)[..4]
        .try_into()
        .expect("selector is 4 bytes")
}

/// `IEndpointCore.BundleAction[]` as an ethabi token (shared with `bundle()` layout).
fn bundle_actions_token(actions: &[BundleActionArgs]) -> Token {
    Token::Array(
        actions
            .iter()
            .map(|a| {
                let pub_fields_token = Token::FixedArray(
                    a.pub_fields
                        .iter()
                        .map(|b| Token::Uint(Uint::from_big_endian(b)))
                        .collect(),
                );
                let spend_auth_sig_token = Token::FixedArray(
                    a.spend_auth_sig
                        .iter()
                        .map(|b| Token::Uint(Uint::from_big_endian(b)))
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
    )
}

/// The `PrivacyCall` tuple token: `(bytes abi.encode(BundleAction[]), uint256[3] bindingSig)`.
fn privacy_call_token(call: &PrivacyCallArgs) -> Token {
    let actions_bytes = encode(&[bundle_actions_token(&call.actions)]);
    let binding_sig_token = Token::FixedArray(
        call.binding_sig
            .iter()
            .map(|b| Token::Uint(Uint::from_big_endian(b)))
            .collect(),
    );
    Token::Tuple(vec![Token::Bytes(actions_bytes), binding_sig_token])
}

/// `keccak256(abi.encode(PrivacyCall))` — the commitment the `SwapCoordinator` stores for
/// each leg (`commitA`/`commitB`). Must match `keccak256(abi.encode(call))` on-chain.
pub fn privacy_call_commit(call: &PrivacyCallArgs) -> [u8; 32] {
    let encoded = encode(&[privacy_call_token(call)]);
    Keccak256::digest(&encoded).into()
}

fn with_selector(sel: [u8; 4], body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&body);
    out
}

// ── PERC20 transfer (permissionless + executor-gated) ────────────────────────

/// `transfer((bytes,uint256[3]))` — permissionless value-neutral transfer. Selector `0xeda1a0ac`.
pub fn encode_perc20_transfer_calldata(call: &PrivacyCallArgs) -> Vec<u8> {
    let body = encode(&[privacy_call_token(call)]);
    with_selector(selector(b"transfer((bytes,uint256[3]))"), body)
}

/// `transfer(address,(bytes,uint256[3]))` — executor-gated transfer (atomic-swap leg).
/// Selector `0xc7b921d3`. `executor` MUST equal the bound `executor` in the v2 sighash
/// (typically the `SwapCoordinator`).
pub fn encode_perc20_transfer_executor_calldata(
    executor: &[u8; 20],
    call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*executor)),
        privacy_call_token(call),
    ];
    let body = encode(&tokens);
    with_selector(selector(b"transfer(address,(bytes,uint256[3]))"), body)
}

// ── WrappedPERC20 shield / unshield ──────────────────────────────────────────

/// `shield(uint256,(bytes,uint256[3]))` — deposit underlying → mint shielded note.
/// Selector `0x0411cbab`. `amount_units` is in NOTE UNITS (the contract pulls
/// `amount_units * scale` of the underlying from `msg.sender`).
pub fn encode_wrapped_shield_calldata(amount_units: u64, call: &PrivacyCallArgs) -> Vec<u8> {
    let tokens = vec![Token::Uint(Uint::from(amount_units)), privacy_call_token(call)];
    let body = encode(&tokens);
    with_selector(selector(b"shield(uint256,(bytes,uint256[3]))"), body)
}

/// `unshield(uint256,address,(bytes,uint256[3]))` — spend note → release underlying to
/// `recipient`. Selector `0x53644c61`. The recipient is bound into the binding sighash
/// on-chain (`recipientMeta = uint160(recipient)`), so it must match the proved bundle.
pub fn encode_wrapped_unshield_calldata(
    amount_units: u64,
    recipient: &[u8; 20],
    call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Uint(Uint::from(amount_units)),
        Token::Address(ethabi::Address::from(*recipient)),
        privacy_call_token(call),
    ];
    let body = encode(&tokens);
    with_selector(selector(b"unshield(uint256,address,(bytes,uint256[3]))"), body)
}

// ── updateRoot (permissionless batch confirm crank) ──────────────────────────

/// `updateRoot(bytes32,bytes32,uint256,bytes)` — fold the next `j` queued cmx into the
/// confirmed Merkle root with a Groth16 `cmxconfirm_evm` batch proof. Permissionless:
/// the indexer crank (or anyone) self-submits. `proof` is the standard wire format
/// `abi.encode(pA, pB, pC)` (see `encode_groth16_proof_components`).
pub fn encode_update_root_calldata(
    new_root: &[u8; 32],
    new_frontier_commit: &[u8; 32],
    j: u64,
    proof: &[u8],
) -> Vec<u8> {
    let tokens = vec![
        Token::FixedBytes(new_root.to_vec()),
        Token::FixedBytes(new_frontier_commit.to_vec()),
        Token::Uint(Uint::from(j)),
        Token::Bytes(proof.to_vec()),
    ];
    let body = encode(&tokens);
    with_selector(update_root_selector(), body)
}

pub fn update_root_selector() -> [u8; 4] {
    selector(b"updateRoot(bytes32,bytes32,uint256,bytes)")
}

// ── SwapCoordinator (3-tx atomic swap) ───────────────────────────────────────

/// `keccak256(abi.encode(initiator, poolA, poolB, htlcHash, commitA, rkBx, rkBy, salt))` — the
/// swap id the `SwapCoordinator` derives in `initiateSwap`. The relayer recomputes it locally so
/// it can issue `joinSwap`/`settle` without waiting to parse the receipt.
///
/// `rk_bx`/`rk_by` are the joiner's randomised spend-auth key coords (BE), pre-committed by the
/// initiator at `initiateSwap` (audit A-1): they are part of the swap id and the join challenge.
pub fn compute_swap_id(
    initiator: &[u8; 20],
    pool_a: &[u8; 20],
    pool_b: &[u8; 20],
    htlc_hash: &[u8; 32],
    commit_a: &[u8; 32],
    rk_bx: &[u8; 32],
    rk_by: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    let encoded = encode(&[
        Token::Address(ethabi::Address::from(*initiator)),
        Token::Address(ethabi::Address::from(*pool_a)),
        Token::Address(ethabi::Address::from(*pool_b)),
        Token::FixedBytes(htlc_hash.to_vec()),
        Token::FixedBytes(commit_a.to_vec()),
        Token::Uint(Uint::from_big_endian(rk_bx)),
        Token::Uint(Uint::from_big_endian(rk_by)),
        Token::FixedBytes(salt.to_vec()),
    ]);
    Keccak256::digest(&encoded).into()
}

/// `initiateSwap(address,address,(bytes,uint256[3]),bytes32,uint256,uint256,uint64,bytes32)` —
/// plan A (call-on-chain): the FULL leg-A `PrivacyCall` rides in the tx calldata so the joiner
/// can trial-decrypt it from chain (via the indexer) BEFORE signing the join challenge. The
/// coordinator derives `commitA = keccak256(abi.encode(callA))` internally.
/// `rk_bx`/`rk_by` are the joiner's randomised spend-auth key coords (BE),
/// pre-committed by the initiator (audit A-1) so only the real counterparty can `joinSwap`.
pub fn encode_swap_initiate_calldata(
    pool_a: &[u8; 20],
    pool_b: &[u8; 20],
    call_a: &PrivacyCallArgs,
    htlc_hash: &[u8; 32],
    rk_bx: &[u8; 32],
    rk_by: &[u8; 32],
    deadline: u64,
    salt: &[u8; 32],
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool_a)),
        Token::Address(ethabi::Address::from(*pool_b)),
        privacy_call_token(call_a),
        Token::FixedBytes(htlc_hash.to_vec()),
        Token::Uint(Uint::from_big_endian(rk_bx)),
        Token::Uint(Uint::from_big_endian(rk_by)),
        Token::Uint(Uint::from(deadline)),
        Token::FixedBytes(salt.to_vec()),
    ];
    let body = encode(&tokens);
    with_selector(swap_initiate_selector(), body)
}

/// `joinSwap(bytes32,(bytes,uint256[3]),uint256[3])` — plan A (call-on-chain): the FULL leg-B
/// `PrivacyCall` rides in the tx calldata; the coordinator derives
/// `commitB = keccak256(abi.encode(callB))` internally.
/// `rkB` is NOT supplied here — it was committed by the initiator at `initiateSwap` and is read
/// from storage. `joiner_sig` is the Baby JubJub Schnorr signature under `rkB` over the join
/// challenge, proving control of the pre-committed key.
pub fn encode_swap_join_calldata(
    swap_id: &[u8; 32],
    call_b: &PrivacyCallArgs,
    joiner_sig: &[[u8; 32]; 3],
) -> Vec<u8> {
    let joiner_sig_token = Token::FixedArray(
        joiner_sig
            .iter()
            .map(|b| Token::Uint(Uint::from_big_endian(b)))
            .collect(),
    );
    let tokens = vec![
        Token::FixedBytes(swap_id.to_vec()),
        privacy_call_token(call_b),
        joiner_sig_token,
    ];
    let body = encode(&tokens);
    with_selector(swap_join_selector(), body)
}

/// `settle(bytes32,bytes32,(bytes,uint256[3]),(bytes,uint256[3]))` — selector `0xc7ece15f`.
/// Reveals the HTLC preimage and submits both executor-gated legs atomically.
pub fn encode_swap_settle_calldata(
    swap_id: &[u8; 32],
    secret: &[u8; 32],
    call_a: &PrivacyCallArgs,
    call_b: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::FixedBytes(swap_id.to_vec()),
        Token::FixedBytes(secret.to_vec()),
        privacy_call_token(call_a),
        privacy_call_token(call_b),
    ];
    let body = encode(&tokens);
    with_selector(
        selector(b"settle(bytes32,bytes32,(bytes,uint256[3]),(bytes,uint256[3]))"),
        body,
    )
}

// ── selectors (handy for tests / dispatch) ───────────────────────────────────

pub fn perc20_transfer_selector() -> [u8; 4] { selector(b"transfer((bytes,uint256[3]))") }
pub fn perc20_transfer_executor_selector() -> [u8; 4] { selector(b"transfer(address,(bytes,uint256[3]))") }
pub fn wrapped_shield_selector() -> [u8; 4] { selector(b"shield(uint256,(bytes,uint256[3]))") }
pub fn wrapped_unshield_selector() -> [u8; 4] { selector(b"unshield(uint256,address,(bytes,uint256[3]))") }
pub fn swap_initiate_selector() -> [u8; 4] { selector(b"initiateSwap(address,address,(bytes,uint256[3]),bytes32,uint256,uint256,uint64,bytes32)") }
pub fn swap_join_selector() -> [u8; 4] { selector(b"joinSwap(bytes32,(bytes,uint256[3]),uint256[3])") }
pub fn swap_settle_selector() -> [u8; 4] { selector(b"settle(bytes32,bytes32,(bytes,uint256[3]),(bytes,uint256[3]))") }

// ── SwapCoordinator calldata DECODE (indexer-side, plan A) ───────────────────
//
// With plan A the initiate/join tx calldata is the canonical DA source for each swap leg:
// the indexer parses it so wallets can trial-decrypt the counterparty leg BEFORE joining.
// These are the exact inverses of `encode_swap_initiate_calldata` / `encode_swap_join_calldata`.

use super::bundle_decode::{bundle_action_param, parse_action, token_bytes32, BundleDecodeError};
use ethabi::{decode, ParamType};

/// The `PrivacyCall` tuple param: `(bytes actions, uint256[3] bindingSig)`.
fn privacy_call_param() -> ParamType {
    ParamType::Tuple(vec![
        ParamType::Bytes,
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 3),
    ])
}

/// Parse a decoded `PrivacyCall` tuple token back into `PrivacyCallArgs`
/// (inner `actions` bytes are decoded as `abi.encode(BundleAction[])`).
fn parse_privacy_call(token: &Token) -> Result<PrivacyCallArgs, BundleDecodeError> {
    let fields = match token {
        Token::Tuple(v) if v.len() == 2 => v,
        _ => return Err(BundleDecodeError::Layout),
    };
    let actions_bytes = match &fields[0] {
        Token::Bytes(b) => b,
        _ => return Err(BundleDecodeError::Layout),
    };
    let inner = decode(&[ParamType::Array(Box::new(bundle_action_param()))], actions_bytes)
        .map_err(|e| BundleDecodeError::Abi(e.to_string()))?;
    let actions = match inner.first() {
        Some(Token::Array(items)) => items.iter().map(parse_action).collect::<Result<_, _>>()?,
        _ => return Err(BundleDecodeError::Layout),
    };
    let binding_sig = match &fields[1] {
        Token::FixedArray(v) if v.len() == 3 => {
            let mut out = [[0u8; 32]; 3];
            for (i, t) in v.iter().enumerate() {
                out[i] = token_bytes32(t)?;
            }
            out
        }
        _ => return Err(BundleDecodeError::Layout),
    };
    Ok(PrivacyCallArgs { actions, binding_sig })
}

fn token_address20(t: &Token) -> Result<[u8; 20], BundleDecodeError> {
    match t {
        Token::Address(a) => Ok(a.0),
        _ => Err(BundleDecodeError::Layout),
    }
}

/// Decoded `initiateSwap` calldata (plan A layout).
#[derive(Debug, Clone)]
pub struct SwapInitiateCalldata {
    pub pool_a: [u8; 20],
    pub pool_b: [u8; 20],
    pub call_a: PrivacyCallArgs,
    pub htlc_hash: [u8; 32],
    pub rk_bx: [u8; 32],
    pub rk_by: [u8; 32],
    pub deadline: u64,
    pub salt: [u8; 32],
}

impl SwapInitiateCalldata {
    /// `commitA` as the coordinator derives it on-chain.
    pub fn commit_a(&self) -> [u8; 32] {
        privacy_call_commit(&self.call_a)
    }
}

/// Decoded `joinSwap` calldata (plan A layout).
#[derive(Debug, Clone)]
pub struct SwapJoinCalldata {
    pub swap_id: [u8; 32],
    pub call_b: PrivacyCallArgs,
    pub joiner_sig: [[u8; 32]; 3],
}

impl SwapJoinCalldata {
    /// `commitB` as the coordinator derives it on-chain.
    pub fn commit_b(&self) -> [u8; 32] {
        privacy_call_commit(&self.call_b)
    }
}

/// Decode full `initiateSwap` calldata (4-byte selector + ABI body).
pub fn decode_swap_initiate_calldata(
    calldata: &[u8],
) -> Result<SwapInitiateCalldata, BundleDecodeError> {
    if calldata.len() < 4 {
        return Err(BundleDecodeError::TooShort);
    }
    if calldata[..4] != swap_initiate_selector() {
        return Err(BundleDecodeError::BadSelector);
    }
    let params = vec![
        ParamType::Address,
        ParamType::Address,
        privacy_call_param(),
        ParamType::FixedBytes(32),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(64),
        ParamType::FixedBytes(32),
    ];
    let tokens =
        decode(&params, &calldata[4..]).map_err(|e| BundleDecodeError::Abi(e.to_string()))?;
    if tokens.len() != 8 {
        return Err(BundleDecodeError::Layout);
    }
    let deadline = match &tokens[6] {
        Token::Uint(u) => u.as_u64(),
        _ => return Err(BundleDecodeError::Layout),
    };
    Ok(SwapInitiateCalldata {
        pool_a: token_address20(&tokens[0])?,
        pool_b: token_address20(&tokens[1])?,
        call_a: parse_privacy_call(&tokens[2])?,
        htlc_hash: token_bytes32(&tokens[3])?,
        rk_bx: token_bytes32(&tokens[4])?,
        rk_by: token_bytes32(&tokens[5])?,
        deadline,
        salt: token_bytes32(&tokens[7])?,
    })
}

/// Decode full `joinSwap` calldata (4-byte selector + ABI body).
pub fn decode_swap_join_calldata(
    calldata: &[u8],
) -> Result<SwapJoinCalldata, BundleDecodeError> {
    if calldata.len() < 4 {
        return Err(BundleDecodeError::TooShort);
    }
    if calldata[..4] != swap_join_selector() {
        return Err(BundleDecodeError::BadSelector);
    }
    let params = vec![
        ParamType::FixedBytes(32),
        privacy_call_param(),
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 3),
    ];
    let tokens =
        decode(&params, &calldata[4..]).map_err(|e| BundleDecodeError::Abi(e.to_string()))?;
    if tokens.len() != 3 {
        return Err(BundleDecodeError::Layout);
    }
    let joiner_sig = match &tokens[2] {
        Token::FixedArray(v) if v.len() == 3 => {
            let mut out = [[0u8; 32]; 3];
            for (i, t) in v.iter().enumerate() {
                out[i] = token_bytes32(t)?;
            }
            out
        }
        _ => return Err(BundleDecodeError::Layout),
    };
    Ok(SwapJoinCalldata {
        swap_id: token_bytes32(&tokens[0])?,
        call_b: parse_privacy_call(&tokens[1])?,
        joiner_sig,
    })
}

// Keep `EthEncodeError` reachable for symmetry with the other encoders (none of these
// fixed-shape encoders can fail today, but callers may want a uniform error type).
#[allow(dead_code)]
fn _assert_error_in_scope(_e: EthEncodeError) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_action() -> BundleActionArgs {
        BundleActionArgs {
            cmx: [1u8; 32],
            enc_ciphertext: vec![0u8; 580],
            out_ciphertext: vec![0u8; 80],
            epk: [2u8; 32],
            nf_old: [3u8; 32],
            anchor: [4u8; 32],
            proof: vec![0xabu8; 256],
            pub_fields: [[5u8; 32]; 8],
            spend_auth_sig: [[6u8; 32]; 3],
        }
    }

    fn dummy_call() -> PrivacyCallArgs {
        PrivacyCallArgs { actions: vec![dummy_action()], binding_sig: [[7u8; 32]; 3] }
    }

    #[test]
    fn selectors_match_onchain() {
        assert_eq!(perc20_transfer_selector(), [0xed, 0xa1, 0xa0, 0xac]);
        assert_eq!(perc20_transfer_executor_selector(), [0xc7, 0xb9, 0x21, 0xd3]);
        assert_eq!(wrapped_shield_selector(), [0x04, 0x11, 0xcb, 0xab]);
        assert_eq!(wrapped_unshield_selector(), [0x53, 0x64, 0x4c, 0x61]);
        // Plan A (call-on-chain) selectors — full PrivacyCall in initiate/join calldata.
        // Cross-checked with `cast sig` against the new SwapCoordinator ABI.
        assert_eq!(swap_initiate_selector(), [0xe3, 0xb9, 0x2d, 0xfd]);
        assert_eq!(swap_join_selector(), [0x43, 0xfa, 0x07, 0x47]);
        assert_eq!(swap_settle_selector(), [0xc7, 0xec, 0xe1, 0x5f]);
    }

    #[test]
    fn swap_initiate_calldata_roundtrip() {
        let call = dummy_call();
        let cd = encode_swap_initiate_calldata(
            &[0xA1u8; 20], &[0xB2u8; 20], &call, &[0x11u8; 32], &[0x22u8; 32], &[0x33u8; 32],
            1_719_500_000, &[0x44u8; 32],
        );
        assert_eq!(&cd[..4], &swap_initiate_selector());
        let dec = decode_swap_initiate_calldata(&cd).expect("decode initiate");
        assert_eq!(dec.pool_a, [0xA1u8; 20]);
        assert_eq!(dec.pool_b, [0xB2u8; 20]);
        assert_eq!(dec.htlc_hash, [0x11u8; 32]);
        assert_eq!(dec.rk_bx, [0x22u8; 32]);
        assert_eq!(dec.rk_by, [0x33u8; 32]);
        assert_eq!(dec.deadline, 1_719_500_000);
        assert_eq!(dec.salt, [0x44u8; 32]);
        assert_eq!(dec.call_a.actions.len(), 1);
        assert_eq!(dec.call_a.actions[0].enc_ciphertext, call.actions[0].enc_ciphertext);
        assert_eq!(dec.call_a.binding_sig, call.binding_sig);
        // The decoded leg re-derives the exact on-chain commitment.
        assert_eq!(dec.commit_a(), privacy_call_commit(&call));
    }

    #[test]
    fn swap_join_calldata_roundtrip() {
        let call = dummy_call();
        let sig = [[0x51u8; 32], [0x52u8; 32], [0x53u8; 32]];
        let cd = encode_swap_join_calldata(&[0x99u8; 32], &call, &sig);
        assert_eq!(&cd[..4], &swap_join_selector());
        let dec = decode_swap_join_calldata(&cd).expect("decode join");
        assert_eq!(dec.swap_id, [0x99u8; 32]);
        assert_eq!(dec.joiner_sig, sig);
        assert_eq!(dec.call_b.actions.len(), 1);
        assert_eq!(dec.call_b.actions[0].pub_fields, call.actions[0].pub_fields);
        assert_eq!(dec.commit_b(), privacy_call_commit(&call));
    }

    #[test]
    fn swap_decode_rejects_wrong_selector() {
        let call = dummy_call();
        let cd = encode_swap_join_calldata(&[0x99u8; 32], &call, &[[0u8; 32]; 3]);
        assert!(matches!(
            decode_swap_initiate_calldata(&cd),
            Err(BundleDecodeError::BadSelector)
        ));
        assert!(matches!(decode_swap_join_calldata(&cd[..3]), Err(BundleDecodeError::TooShort)));
    }

    #[test]
    fn calldata_prefixes_correct_selector() {
        let call = dummy_call();
        assert_eq!(&encode_perc20_transfer_calldata(&call)[..4], &perc20_transfer_selector());
        assert_eq!(
            &encode_perc20_transfer_executor_calldata(&[0xEFu8; 20], &call)[..4],
            &perc20_transfer_executor_selector()
        );
        assert_eq!(&encode_wrapped_shield_calldata(1000, &call)[..4], &wrapped_shield_selector());
        assert_eq!(
            &encode_wrapped_unshield_calldata(1000, &[0xDEu8; 20], &call)[..4],
            &wrapped_unshield_selector()
        );
    }

    #[test]
    fn shield_and_transfer_share_privacy_call_tail() {
        // shield(amount, call) body = uint256 amount ‖ <same PrivacyCall tail as transfer>.
        let call = dummy_call();
        let transfer = encode_perc20_transfer_calldata(&call);
        let shield = encode_wrapped_shield_calldata(1000, &call);
        // transfer body (after selector) is the offset-encoded PrivacyCall starting at word 0;
        // shield body has the amount in word 0 then the PrivacyCall offset at word 1. The
        // encoded PrivacyCall dynamic tail (actions bytes + bindingSig) must be byte-identical.
        let t_tail = &transfer[4 + 32..]; // skip selector + head offset word
        let s_tail = &shield[4 + 64..]; // skip selector + amount + offset word
        assert_eq!(t_tail, s_tail, "PrivacyCall encoding must be reused verbatim");
    }

    #[test]
    fn commit_is_deterministic_keccak() {
        let call = dummy_call();
        let c1 = privacy_call_commit(&call);
        let c2 = privacy_call_commit(&call);
        assert_eq!(c1, c2);
        // A different binding sig changes the commitment.
        let mut other = call.clone();
        other.binding_sig[2] = [0x9u8; 32];
        assert_ne!(privacy_call_commit(&other), c1);
    }

    #[test]
    fn swap_id_matches_abi_encode_layout() {
        // Deterministic + sensitive to each field (incl. the pre-committed joiner key rkB).
        let base = compute_swap_id(&[1u8; 20], &[2u8; 20], &[3u8; 20], &[4u8; 32], &[5u8; 32], &[8u8; 32], &[9u8; 32], &[6u8; 32]);
        assert_eq!(
            base,
            compute_swap_id(&[1u8; 20], &[2u8; 20], &[3u8; 20], &[4u8; 32], &[5u8; 32], &[8u8; 32], &[9u8; 32], &[6u8; 32])
        );
        assert_ne!(
            base,
            compute_swap_id(&[1u8; 20], &[2u8; 20], &[3u8; 20], &[4u8; 32], &[5u8; 32], &[8u8; 32], &[9u8; 32], &[7u8; 32])
        );
        // Changing rkB alone must change the id.
        assert_ne!(
            base,
            compute_swap_id(&[1u8; 20], &[2u8; 20], &[3u8; 20], &[4u8; 32], &[5u8; 32], &[0xAu8; 32], &[9u8; 32], &[6u8; 32])
        );
    }
}
