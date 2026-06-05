//! Decode `PrivacyPool.bundle()` calldata (inverse of [`super::encode_bundle_calldata`]).
//!
//! Used by the indexer as a fallback for legacy pools whose `NoteAdded` logs omit
//! `outCiphertext` / `cvNetX` (pre-extension event layout).

use ethabi::{decode, ParamType, Token, Uint};
use thiserror::Error;

use super::{bundle_function_selector, BundleActionArgs, BundleCalldataArgs, EthEncodeError};

#[derive(Debug, Error)]
pub enum BundleDecodeError {
    #[error("calldata too short")]
    TooShort,
    #[error("wrong function selector")]
    BadSelector,
    #[error("ABI decode failed: {0}")]
    Abi(String),
    #[error("unexpected token layout")]
    Layout,
    #[error("{0}")]
    Encode(#[from] EthEncodeError),
}

fn bundle_action_param() -> ParamType {
    ParamType::Tuple(vec![
        ParamType::FixedBytes(32),
        ParamType::Bytes,
        ParamType::Bytes,
        ParamType::FixedBytes(32),
        ParamType::FixedBytes(32),
        ParamType::FixedBytes(32),
        ParamType::Bytes,
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 8),
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 3),
    ])
}

fn bundle_top_params() -> Vec<ParamType> {
    vec![
        ParamType::Array(Box::new(bundle_action_param())),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::FixedBytes(32),
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 3),
    ]
}

fn token_bytes32(t: &Token) -> Result<[u8; 32], BundleDecodeError> {
    match t {
        Token::FixedBytes(b) if b.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Ok(out)
        }
        Token::Bytes(b) if b.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Ok(out)
        }
        Token::Uint(u) => Ok(uint_to_be32(u)),
        _ => Err(BundleDecodeError::Layout),
    }
}

fn uint_to_be32(u: &Uint) -> [u8; 32] {
    let mut out = [0u8; 32];
    u.to_big_endian(&mut out);
    out
}

fn parse_action(token: &Token) -> Result<BundleActionArgs, BundleDecodeError> {
    let fields = match token {
        Token::Tuple(v) if v.len() == 9 => v,
        _ => return Err(BundleDecodeError::Layout),
    };
    let cmx = token_bytes32(&fields[0])?;
    let enc_ciphertext = match &fields[1] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(BundleDecodeError::Layout),
    };
    let out_ciphertext = match &fields[2] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(BundleDecodeError::Layout),
    };
    let epk = token_bytes32(&fields[3])?;
    let nf_old = token_bytes32(&fields[4])?;
    let anchor = token_bytes32(&fields[5])?;
    let proof = match &fields[6] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(BundleDecodeError::Layout),
    };
    let pub_fields = match &fields[7] {
        Token::FixedArray(v) if v.len() == 8 => {
            let mut out = [[0u8; 32]; 8];
            for (i, t) in v.iter().enumerate() {
                out[i] = token_bytes32(t)?;
            }
            out
        }
        _ => return Err(BundleDecodeError::Layout),
    };
    let spend_auth_sig = match &fields[8] {
        Token::FixedArray(v) if v.len() == 3 => {
            let mut out = [[0u8; 32]; 3];
            for (i, t) in v.iter().enumerate() {
                out[i] = token_bytes32(t)?;
            }
            out
        }
        _ => return Err(BundleDecodeError::Layout),
    };
    Ok(BundleActionArgs {
        cmx,
        enc_ciphertext,
        out_ciphertext,
        epk,
        nf_old,
        anchor,
        proof,
        pub_fields,
        spend_auth_sig,
    })
}

/// Decode full `bundle()` calldata (4-byte selector + ABI body).
pub fn decode_bundle_calldata(calldata: &[u8]) -> Result<BundleCalldataArgs, BundleDecodeError> {
    if calldata.len() < 4 {
        return Err(BundleDecodeError::TooShort);
    }
    if calldata[..4] != bundle_function_selector() {
        return Err(BundleDecodeError::BadSelector);
    }
    let tokens = decode(&bundle_top_params(), &calldata[4..])
        .map_err(|e| BundleDecodeError::Abi(e.to_string()))?;
    if tokens.len() != 5 {
        return Err(BundleDecodeError::Layout);
    }
    let actions: Vec<BundleActionArgs> = match &tokens[0] {
        Token::Array(items) => items.iter().map(parse_action).collect::<Result<_, _>>()?,
        _ => return Err(BundleDecodeError::Layout),
    };
    let value_balance = token_bytes32(&tokens[1])?;
    let amount = match &tokens[2] {
        Token::Uint(u) => u.as_u64(),
        _ => return Err(BundleDecodeError::Layout),
    };
    let recipient_meta = token_bytes32(&tokens[3])?;
    let binding_sig = match &tokens[4] {
        Token::FixedArray(v) if v.len() == 3 => {
            let mut out = [[0u8; 32]; 3];
            for (i, t) in v.iter().enumerate() {
                out[i] = token_bytes32(t)?;
            }
            out
        }
        _ => return Err(BundleDecodeError::Layout),
    };
    Ok(BundleCalldataArgs {
        actions,
        value_balance,
        amount,
        recipient_meta,
        binding_sig,
    })
}

/// Per-action ciphertext fields needed for OVK recovery (keyed by `cmx`).
#[derive(Debug, Clone)]
pub struct BundleActionCiphertexts {
    pub out_ciphertext: Vec<u8>,
    /// `pubFields[1]` = `cv_net_x` (BE uint256).
    pub cv_net_x: [u8; 32],
}

/// Build a `cmx → ciphertexts` map from decoded bundle calldata.
pub fn bundle_actions_by_cmx(
    calldata: &[u8],
) -> Result<std::collections::HashMap<[u8; 32], BundleActionCiphertexts>, BundleDecodeError> {
    let bundle = decode_bundle_calldata(calldata)?;
    let mut map = std::collections::HashMap::new();
    for a in bundle.actions {
        map.insert(
            a.cmx,
            BundleActionCiphertexts {
                out_ciphertext: a.out_ciphertext,
                cv_net_x: a.pub_fields[1],
            },
        );
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::{encode_bundle_calldata, BundleCalldataArgs};

    #[test]
    fn bundle_calldata_roundtrip_decode() {
        let proof_bytes = vec![0xabu8; 256];
        let enc = vec![0xCCu8; 580];
        let out = vec![0xDDu8; 80];
        let args = BundleCalldataArgs {
            actions: vec![BundleActionArgs {
                cmx: [1u8; 32],
                enc_ciphertext: enc.clone(),
                out_ciphertext: out.clone(),
                epk: [2u8; 32],
                nf_old: [3u8; 32],
                anchor: [4u8; 32],
                proof: proof_bytes,
                pub_fields: [
                    [4u8; 32],
                    [5u8; 32],
                    [0u8; 32],
                    [3u8; 32],
                    [0u8; 32],
                    [0u8; 32],
                    [1u8; 32],
                    [0u8; 32],
                ],
                spend_auth_sig: [[6u8; 32]; 3],
            }],
            value_balance: [0u8; 32],
            amount: 0,
            recipient_meta: [0u8; 32],
            binding_sig: [[7u8; 32]; 3],
        };
        let cd = encode_bundle_calldata(&args).expect("encode");
        let decoded = decode_bundle_calldata(&cd).expect("decode");
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0].enc_ciphertext, enc);
        assert_eq!(decoded.actions[0].out_ciphertext, out);
        assert_eq!(decoded.actions[0].pub_fields[1], [5u8; 32]);
        let map = bundle_actions_by_cmx(&cd).expect("map");
        assert_eq!(map.get(&[1u8; 32]).unwrap().out_ciphertext, out);
    }
}
