//! `PrivacyBTC.sol` log topics and ABI decoders (matches `contracts/PrivacyPool.sol`).

use ethabi::{decode, ParamType, Token};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// keccak256("NoteAdded(bytes32,bytes,bytes,bytes32,bytes32,bytes32)")
pub fn note_added_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"NoteAdded(bytes32,bytes,bytes,bytes32,bytes32,bytes32)"
        ))
    )
}

/// Pre-OVK-extension pools (no `outCiphertext` / `cvNetX` in the log).
pub fn note_added_legacy_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"NoteAdded(bytes32,bytes,bytes32,bytes32)"
        ))
    )
}

/// Topic0 values to subscribe for all `NoteAdded` variants.
pub fn note_added_topic0_alternatives() -> Vec<String> {
    vec![
        note_added_topic0_hex(),
        note_added_legacy_topic0_hex(),
    ]
}

/// keccak256("NoteConfirmed(bytes32,bytes32,uint256)")
pub fn note_confirmed_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"NoteConfirmed(bytes32,bytes32,uint256)"))
    )
}

/// keccak256("RootUpdated(bytes32,uint256,uint256,uint32)") — batch-update model: the
/// confirmed root advanced by one verified `updateRoot` batch (leaves `[from, to)`).
pub fn root_updated_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"RootUpdated(bytes32,uint256,uint256,uint32)"))
    )
}

/// keccak256("ShieldCompleted(bytes32,uint256)")
pub fn shield_completed_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"ShieldCompleted(bytes32,uint256)"))
    )
}

/// keccak256("Perc20Created(address,address,string,string,uint8)") — issuer-minted pool genesis.
pub fn perc20_created_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"Perc20Created(address,address,string,string,uint8)"))
    )
}

/// keccak256("Shielded(address,uint256,uint256)") — WrappedPERC20 deposit accounting event.
pub fn shielded_topic0_hex() -> String {
    format!("0x{}", hex::encode(Keccak256::digest(b"Shielded(address,uint256,uint256)")))
}

/// keccak256("Unshielded(address,uint256,uint256)") — WrappedPERC20 withdrawal accounting event.
pub fn unshielded_topic0_hex() -> String {
    format!("0x{}", hex::encode(Keccak256::digest(b"Unshielded(address,uint256,uint256)")))
}

/// keccak256("ShieldPoolCreated(address,address,uint256,string,string,uint8)") — shield-pool init
/// metadata (formerly `WrappedCreated`, renamed in the shield-pool API migration).
pub fn shield_pool_created_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"ShieldPoolCreated(address,address,uint256,string,string,uint8)"
        ))
    )
}

/// keccak256("ShieldPoolDeployed(address,address,address,uint256)") — factory deployment event
/// (formerly `WrappedDeployed`, renamed in the shield-pool API migration).
pub fn shield_pool_deployed_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"ShieldPoolDeployed(address,address,address,uint256)"))
    )
}

// ── SwapCoordinator events (plan A layout) ────────────────────────────────────

/// keccak256("SwapInitiated(bytes32,address,address,address,bytes32,uint64,bytes32,uint256,uint256)")
/// — plan A layout: `commitA` + the pre-committed joiner key `rkB` ride in the event so
/// indexers can track swaps from logs alone (the full `callA` lives in the tx calldata).
pub fn swap_initiated_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"SwapInitiated(bytes32,address,address,address,bytes32,uint64,bytes32,uint256,uint256)"
        ))
    )
}

/// keccak256("SwapJoined(bytes32,address,bytes32,uint256,uint256)")
pub fn swap_joined_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"SwapJoined(bytes32,address,bytes32,uint256,uint256)"))
    )
}

/// keccak256("SwapSettled(bytes32,bytes32)")
pub fn swap_settled_topic0_hex() -> String {
    format!("0x{}", hex::encode(Keccak256::digest(b"SwapSettled(bytes32,bytes32)")))
}

/// keccak256("SwapCancelled(bytes32)")
pub fn swap_cancelled_topic0_hex() -> String {
    format!("0x{}", hex::encode(Keccak256::digest(b"SwapCancelled(bytes32)")))
}

/// Decoded `SwapInitiated` (plan A layout). `swap_id`/`initiator` from indexed topics;
/// the rest from log data.
#[derive(Debug, Clone)]
pub struct DecodedSwapInitiated {
    pub swap_id: [u8; 32],
    pub initiator: [u8; 20],
    pub pool_a: [u8; 20],
    pub pool_b: [u8; 20],
    pub htlc_hash: [u8; 32],
    pub deadline: u64,
    pub commit_a: [u8; 32],
    pub rk_bx: [u8; 32],
    pub rk_by: [u8; 32],
}

/// Decoded `SwapJoined`. `swap_id`/`joiner` from indexed topics; the rest from log data.
#[derive(Debug, Clone)]
pub struct DecodedSwapJoined {
    pub swap_id: [u8; 32],
    pub joiner: [u8; 20],
    pub commit_b: [u8; 32],
    pub rk_bx: [u8; 32],
    pub rk_by: [u8; 32],
}

/// Decoded `Shielded` / `Unshielded` accounting event (the underlying-custody side of a
/// WrappedPERC20 shield/unshield). The note cmx itself arrives via `NoteAdded`; this event
/// carries the public deposit/withdraw amounts and the EVM actor.
#[derive(Debug, Clone)]
pub struct DecodedShielded {
    /// `depositor` (Shielded) or `recipient` (Unshielded), low-20-bytes EVM address.
    pub actor: [u8; 20],
    /// Amount in note units.
    pub amount_units: u128,
    /// Amount in the underlying token's smallest unit (`amount_units * scale`).
    pub wei_amount: u128,
}

/// Decoded `ShieldPoolCreated` pool-init metadata (used for discovery/verification + the
/// pool-metadata API). `pool`/`underlying` come from indexed topics.
#[derive(Debug, Clone)]
pub struct DecodedShieldPoolCreated {
    pub pool: [u8; 20],
    pub underlying: [u8; 20],
    pub scale: u128,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone)]
pub struct DecodedNoteAdded {
    pub cmx: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    /// 80-byte outgoing ciphertext (empty on legacy `NoteAdded` logs).
    pub out_ciphertext: Vec<u8>,
    pub epk: [u8; 32],
    pub nf_old: [u8; 32],
    /// `pubFields[1]` = cv_net_x (BE). `None` on legacy logs.
    pub cv_net_x: Option<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum LogDecodeError {
    #[error("invalid topics/data for NoteAdded")]
    BadNoteAdded,
    #[error("invalid topics/data for NoteConfirmed")]
    BadNoteConfirmed,
    #[error("invalid topics/data for RootUpdated")]
    BadRootUpdated,
    #[error("invalid topics/data for ShieldCompleted")]
    BadShieldCompleted,
    #[error("invalid topics/data for Shielded/Unshielded")]
    BadShielded,
    #[error("invalid topics/data for ShieldPoolCreated")]
    BadShieldPoolCreated,
    #[error("invalid topics/data for SwapInitiated")]
    BadSwapInitiated,
    #[error("invalid topics/data for SwapJoined")]
    BadSwapJoined,
    #[error("ethabi decode: {0}")]
    EthAbi(String),
}

/// Extract a low-20-byte EVM address from a 32-byte indexed topic.
fn topic_to_address(topic: &str) -> Option<[u8; 20]> {
    let b = topic_to_bytes32(topic)?;
    Some(b[12..32].try_into().ok()?)
}

fn topic_to_bytes32(topic: &str) -> Option<[u8; 32]> {
    let t = topic.strip_prefix("0x").unwrap_or(topic);
    let b = hex::decode(t).ok()?;
    if b.len() != 32 {
        return None;
    }
    Some(b.try_into().ok()?)
}

fn decode_note_added_v2(data: &[u8]) -> Result<DecodedNoteAdded, LogDecodeError> {
    let tokens = decode(
        &[
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
        ],
        data,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    if tokens.len() != 5 {
        return Err(LogDecodeError::BadNoteAdded);
    }
    let enc = match &tokens[0] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(LogDecodeError::BadNoteAdded),
    };
    let out = match &tokens[1] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(LogDecodeError::BadNoteAdded),
    };
    let epk = token_bytes32(&tokens[2])?;
    let nf_old = token_bytes32(&tokens[3])?;
    let cv_net_x = token_bytes32(&tokens[4])?;
    Ok(DecodedNoteAdded {
        cmx: [0u8; 32], // filled by caller
        enc_ciphertext: enc,
        out_ciphertext: out,
        epk,
        nf_old,
        cv_net_x: Some(cv_net_x),
    })
}

fn decode_note_added_legacy(data: &[u8]) -> Result<DecodedNoteAdded, LogDecodeError> {
    let tokens = decode(
        &[
            ParamType::Bytes,
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
        ],
        data,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    if tokens.len() != 3 {
        return Err(LogDecodeError::BadNoteAdded);
    }
    let enc = match &tokens[0] {
        Token::Bytes(b) => b.clone(),
        _ => return Err(LogDecodeError::BadNoteAdded),
    };
    let epk = token_bytes32(&tokens[1])?;
    let nf_old = token_bytes32(&tokens[2])?;
    Ok(DecodedNoteAdded {
        cmx: [0u8; 32],
        enc_ciphertext: enc,
        out_ciphertext: Vec::new(),
        epk,
        nf_old,
        cv_net_x: None,
    })
}

/// Decode `NoteAdded` from `eth_getLogs` / WebSocket log entry.
///
/// Supports the current event (with `outCiphertext` + `cvNetX`) and the legacy
/// 4-field layout. `topics[1]` = cmx (indexed).
pub fn decode_note_added_log(topics: &[String], data_hex: &str) -> Result<DecodedNoteAdded, LogDecodeError> {
    let cmx = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadNoteAdded)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadNoteAdded)?;

    let norm = |s: &str| {
        s.strip_prefix("0x")
            .unwrap_or(s)
            .to_ascii_lowercase()
    };
    let topic0 = topics.first().map(|s| norm(s));
    let legacy = norm(&note_added_legacy_topic0_hex());
    let current = norm(&note_added_topic0_hex());
    let mut decoded = if topic0.as_deref() == Some(current.as_str()) {
        decode_note_added_v2(&raw)?
    } else if topic0.as_deref() == Some(legacy.as_str()) {
        // Deployed pools may still use the legacy topic0 while emitting the extended
        // 5-field log body (outCiphertext + cvNetX). Prefer v2 when the payload fits.
        decode_note_added_v2(&raw).or_else(|_| decode_note_added_legacy(&raw))?
    } else {
        decode_note_added_v2(&raw).or_else(|_| decode_note_added_legacy(&raw))?
    };
    decoded.cmx = cmx;
    Ok(decoded)
}

fn token_bytes32(t: &Token) -> Result<[u8; 32], LogDecodeError> {
    match t {
        Token::FixedBytes(b) if b.len() == 32 => Ok(b[..].try_into().unwrap()),
        Token::Bytes(b) if b.len() == 32 => Ok(b[..].try_into().unwrap()),
        _ => Err(LogDecodeError::BadNoteAdded),
    }
}

/// Returns `(cmx, newRoot, position)`.
pub fn decode_note_confirmed_log(topics: &[String], data_hex: &str) -> Result<([u8; 32], [u8; 32], u64), LogDecodeError> {
    let cmx = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadNoteConfirmed)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadNoteConfirmed)?;
    // data: abi.encode(bytes32 newRoot, uint256 position)
    let tokens = decode(&[ParamType::FixedBytes(32), ParamType::Uint(256)], &raw)
        .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    let root = token_bytes32_confirmed(tokens.first().ok_or(LogDecodeError::BadNoteConfirmed)?)?;
    let position = match tokens.get(1) {
        Some(Token::Uint(u)) => u64::try_from(*u).unwrap_or(u64::MAX),
        _ => return Err(LogDecodeError::BadNoteConfirmed),
    };
    Ok((cmx, root, position))
}

fn token_bytes32_confirmed(t: &Token) -> Result<[u8; 32], LogDecodeError> {
    match t {
        Token::FixedBytes(b) if b.len() == 32 => Ok(b[..].try_into().unwrap()),
        _ => Err(LogDecodeError::BadNoteConfirmed),
    }
}

/// Decoded `RootUpdated` — one verified `updateRoot` batch confirmed leaves
/// `[from_count, to_count)` under `new_root`.
#[derive(Debug, Clone)]
pub struct DecodedRootUpdated {
    pub new_root: [u8; 32],
    pub from_count: u64,
    pub to_count: u64,
    pub batch_size: u32,
}

/// Decode `RootUpdated(bytes32 indexed newRoot, uint256 fromCount, uint256 toCount, uint32 batchSize)`.
pub fn decode_root_updated_log(
    topics: &[String],
    data_hex: &str,
) -> Result<DecodedRootUpdated, LogDecodeError> {
    let new_root = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadRootUpdated)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadRootUpdated)?;
    // data: abi.encode(uint256 fromCount, uint256 toCount, uint32 batchSize)
    let tokens = decode(
        &[ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(32)],
        &raw,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    let as_u64 = |t: Option<&Token>| match t {
        Some(Token::Uint(u)) => u64::try_from(*u).map_err(|_| LogDecodeError::BadRootUpdated),
        _ => Err(LogDecodeError::BadRootUpdated),
    };
    let from_count = as_u64(tokens.first())?;
    let to_count = as_u64(tokens.get(1))?;
    let batch_size = as_u64(tokens.get(2))? as u32;
    Ok(DecodedRootUpdated { new_root, from_count, to_count, batch_size })
}

pub fn decode_shield_completed_log(topics: &[String], data_hex: &str) -> Result<([u8; 32], u128), LogDecodeError> {
    let cmx = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadShieldCompleted)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadShieldCompleted)?;
    let tokens =
        decode(&[ParamType::Uint(256)], &raw).map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    let amt = match tokens.get(0) {
        Some(Token::Uint(u)) => u128::try_from(*u).map_err(|_| LogDecodeError::BadShieldCompleted)?,
        _ => return Err(LogDecodeError::BadShieldCompleted),
    };
    Ok((cmx, amt))
}

fn decode_shielded_like(
    topics: &[String],
    data_hex: &str,
) -> Result<DecodedShielded, LogDecodeError> {
    let actor = topics
        .get(1)
        .and_then(|t| topic_to_address(t))
        .ok_or(LogDecodeError::BadShielded)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadShielded)?;
    // data: abi.encode(uint256 amountUnits, uint256 weiAmount)
    let tokens = decode(&[ParamType::Uint(256), ParamType::Uint(256)], &raw)
        .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    let amount_units = match tokens.first() {
        Some(Token::Uint(u)) => u128::try_from(*u).map_err(|_| LogDecodeError::BadShielded)?,
        _ => return Err(LogDecodeError::BadShielded),
    };
    let wei_amount = match tokens.get(1) {
        Some(Token::Uint(u)) => u128::try_from(*u).map_err(|_| LogDecodeError::BadShielded)?,
        _ => return Err(LogDecodeError::BadShielded),
    };
    Ok(DecodedShielded { actor, amount_units, wei_amount })
}

/// Decode a `Shielded(address indexed depositor, uint256 amountUnits, uint256 weiAmount)` log.
pub fn decode_shielded_log(topics: &[String], data_hex: &str) -> Result<DecodedShielded, LogDecodeError> {
    decode_shielded_like(topics, data_hex)
}

/// Decode an `Unshielded(address indexed recipient, uint256 amountUnits, uint256 weiAmount)` log.
pub fn decode_unshielded_log(topics: &[String], data_hex: &str) -> Result<DecodedShielded, LogDecodeError> {
    decode_shielded_like(topics, data_hex)
}

/// Decode a `SwapInitiated(bytes32 indexed swapId, address indexed initiator, address poolA,
/// address poolB, bytes32 htlcHash, uint64 deadline, bytes32 commitA, uint256 rkBx,
/// uint256 rkBy)` log (plan A layout).
pub fn decode_swap_initiated_log(
    topics: &[String],
    data_hex: &str,
) -> Result<DecodedSwapInitiated, LogDecodeError> {
    let swap_id = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadSwapInitiated)?;
    let initiator = topics
        .get(2)
        .and_then(|t| topic_to_address(t))
        .ok_or(LogDecodeError::BadSwapInitiated)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadSwapInitiated)?;
    let tokens = decode(
        &[
            ParamType::Address,
            ParamType::Address,
            ParamType::FixedBytes(32),
            ParamType::Uint(64),
            ParamType::FixedBytes(32),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ],
        &raw,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    if tokens.len() != 7 {
        return Err(LogDecodeError::BadSwapInitiated);
    }
    let addr = |t: &Token| -> Result<[u8; 20], LogDecodeError> {
        match t {
            Token::Address(a) => Ok(a.0),
            _ => Err(LogDecodeError::BadSwapInitiated),
        }
    };
    let b32 = |t: &Token| -> Result<[u8; 32], LogDecodeError> {
        match t {
            Token::FixedBytes(b) if b.len() == 32 => Ok(b[..].try_into().unwrap()),
            Token::Uint(u) => {
                let mut out = [0u8; 32];
                u.to_big_endian(&mut out);
                Ok(out)
            }
            _ => Err(LogDecodeError::BadSwapInitiated),
        }
    };
    let deadline = match &tokens[3] {
        Token::Uint(u) => u64::try_from(*u).map_err(|_| LogDecodeError::BadSwapInitiated)?,
        _ => return Err(LogDecodeError::BadSwapInitiated),
    };
    Ok(DecodedSwapInitiated {
        swap_id,
        initiator,
        pool_a: addr(&tokens[0])?,
        pool_b: addr(&tokens[1])?,
        htlc_hash: b32(&tokens[2])?,
        deadline,
        commit_a: b32(&tokens[4])?,
        rk_bx: b32(&tokens[5])?,
        rk_by: b32(&tokens[6])?,
    })
}

/// Decode a `SwapJoined(bytes32 indexed swapId, address indexed joiner, bytes32 commitB,
/// uint256 rkBx, uint256 rkBy)` log.
pub fn decode_swap_joined_log(
    topics: &[String],
    data_hex: &str,
) -> Result<DecodedSwapJoined, LogDecodeError> {
    let swap_id = topics
        .get(1)
        .and_then(|t| topic_to_bytes32(t))
        .ok_or(LogDecodeError::BadSwapJoined)?;
    let joiner = topics
        .get(2)
        .and_then(|t| topic_to_address(t))
        .ok_or(LogDecodeError::BadSwapJoined)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadSwapJoined)?;
    let tokens = decode(
        &[ParamType::FixedBytes(32), ParamType::Uint(256), ParamType::Uint(256)],
        &raw,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    if tokens.len() != 3 {
        return Err(LogDecodeError::BadSwapJoined);
    }
    let b32 = |t: &Token| -> Result<[u8; 32], LogDecodeError> {
        match t {
            Token::FixedBytes(b) if b.len() == 32 => Ok(b[..].try_into().unwrap()),
            Token::Uint(u) => {
                let mut out = [0u8; 32];
                u.to_big_endian(&mut out);
                Ok(out)
            }
            _ => Err(LogDecodeError::BadSwapJoined),
        }
    };
    Ok(DecodedSwapJoined {
        swap_id,
        joiner,
        commit_b: b32(&tokens[0])?,
        rk_bx: b32(&tokens[1])?,
        rk_by: b32(&tokens[2])?,
    })
}

/// Decode a `ShieldPoolCreated(address indexed pool, address indexed underlying, uint256 scale,
/// string name, string symbol, uint8 decimals)` log.
pub fn decode_shield_pool_created_log(
    topics: &[String],
    data_hex: &str,
) -> Result<DecodedShieldPoolCreated, LogDecodeError> {
    let pool = topics
        .get(1)
        .and_then(|t| topic_to_address(t))
        .ok_or(LogDecodeError::BadShieldPoolCreated)?;
    let underlying = topics
        .get(2)
        .and_then(|t| topic_to_address(t))
        .ok_or(LogDecodeError::BadShieldPoolCreated)?;
    let raw = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
        .map_err(|_| LogDecodeError::BadShieldPoolCreated)?;
    let tokens = decode(
        &[
            ParamType::Uint(256),
            ParamType::String,
            ParamType::String,
            ParamType::Uint(8),
        ],
        &raw,
    )
    .map_err(|e| LogDecodeError::EthAbi(e.to_string()))?;
    let scale = match tokens.first() {
        Some(Token::Uint(u)) => u128::try_from(*u).map_err(|_| LogDecodeError::BadShieldPoolCreated)?,
        _ => return Err(LogDecodeError::BadShieldPoolCreated),
    };
    let name = match &tokens[1] {
        Token::String(s) => s.clone(),
        _ => return Err(LogDecodeError::BadShieldPoolCreated),
    };
    let symbol = match &tokens[2] {
        Token::String(s) => s.clone(),
        _ => return Err(LogDecodeError::BadShieldPoolCreated),
    };
    let decimals = match tokens.get(3) {
        Some(Token::Uint(u)) => u8::try_from(*u).map_err(|_| LogDecodeError::BadShieldPoolCreated)?,
        _ => return Err(LogDecodeError::BadShieldPoolCreated),
    };
    Ok(DecodedShieldPoolCreated { pool, underlying, scale, name, symbol, decimals })
}

#[cfg(test)]
mod tests {
    use ethabi::{encode, Token};

    use super::*;

    #[test]
    fn topic0_lengths() {
        assert_eq!(
            note_added_topic0_hex().len(),
            2 + 64,
            "topic0 is 32 bytes hex"
        );
        assert_ne!(
            note_added_topic0_hex(),
            note_added_legacy_topic0_hex(),
            "new NoteAdded changes topic0"
        );
    }

    #[test]
    fn note_added_v2_roundtrip() {
        let cmx = [0x11u8; 32];
        let enc = vec![0xABu8; 580];
        let out = vec![0xCDu8; 80];
        let epk = [0x22u8; 32];
        let nf = [0x33u8; 32];
        let cv = [0x44u8; 32];
        let data = encode(&[
            Token::Bytes(enc.clone()),
            Token::Bytes(out.clone()),
            Token::FixedBytes(epk.to_vec()),
            Token::FixedBytes(nf.to_vec()),
            Token::FixedBytes(cv.to_vec()),
        ]);
        let topics = vec![
            note_added_topic0_hex(),
            format!("0x{}", hex::encode(cmx)),
        ];
        let decoded =
            decode_note_added_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(decoded.cmx, cmx);
        assert_eq!(decoded.enc_ciphertext, enc);
        assert_eq!(decoded.out_ciphertext, out);
        assert_eq!(decoded.epk, epk);
        assert_eq!(decoded.nf_old, nf);
        assert_eq!(decoded.cv_net_x, Some(cv));
    }

    #[test]
    fn note_added_legacy_roundtrip() {
        let cmx = [0x55u8; 32];
        let enc = vec![0x01u8; 580];
        let epk = [0x66u8; 32];
        let nf = [0x77u8; 32];
        let data = encode(&[
            Token::Bytes(enc.clone()),
            Token::FixedBytes(epk.to_vec()),
            Token::FixedBytes(nf.to_vec()),
        ]);
        let topics = vec![
            note_added_legacy_topic0_hex(),
            format!("0x{}", hex::encode(cmx)),
        ];
        let decoded =
            decode_note_added_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(decoded.cmx, cmx);
        assert_eq!(decoded.enc_ciphertext, enc);
        assert!(decoded.out_ciphertext.is_empty());
        assert_eq!(decoded.cv_net_x, None);
    }

    #[test]
    fn new_topic0s_are_distinct_and_well_formed() {
        for t in [
            shielded_topic0_hex(),
            unshielded_topic0_hex(),
            shield_pool_created_topic0_hex(),
            shield_pool_deployed_topic0_hex(),
            perc20_created_topic0_hex(),
        ] {
            assert_eq!(t.len(), 2 + 64);
        }
        assert_ne!(shielded_topic0_hex(), unshielded_topic0_hex());
        assert_ne!(shield_pool_created_topic0_hex(), shield_pool_deployed_topic0_hex());
    }

    #[test]
    fn shielded_roundtrip() {
        let actor = [0xABu8; 20];
        let mut actor_topic = [0u8; 32];
        actor_topic[12..].copy_from_slice(&actor);
        let data = encode(&[
            Token::Uint(1_000u64.into()),
            Token::Uint(1_000_000_000_000u64.into()),
        ]);
        let topics = vec![shielded_topic0_hex(), format!("0x{}", hex::encode(actor_topic))];
        let d = decode_shielded_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(d.actor, actor);
        assert_eq!(d.amount_units, 1_000);
        assert_eq!(d.wei_amount, 1_000_000_000_000);
    }

    #[test]
    fn shield_pool_created_roundtrip() {
        let pool = [0x11u8; 20];
        let underlying = [0x22u8; 20];
        let mut pool_t = [0u8; 32];
        pool_t[12..].copy_from_slice(&pool);
        let mut und_t = [0u8; 32];
        und_t[12..].copy_from_slice(&underlying);
        let data = encode(&[
            Token::Uint(1_000_000u64.into()),
            Token::String("Shield USDC".to_string()),
            Token::String("sUSDC".to_string()),
            Token::Uint(6u8.into()),
        ]);
        let topics = vec![
            shield_pool_created_topic0_hex(),
            format!("0x{}", hex::encode(pool_t)),
            format!("0x{}", hex::encode(und_t)),
        ];
        let d = decode_shield_pool_created_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(d.pool, pool);
        assert_eq!(d.underlying, underlying);
        assert_eq!(d.scale, 1_000_000);
        assert_eq!(d.name, "Shield USDC");
        assert_eq!(d.symbol, "sUSDC");
        assert_eq!(d.decimals, 6);
    }

    #[test]
    fn swap_initiated_roundtrip() {
        let swap_id = [0x77u8; 32];
        let initiator = [0xAAu8; 20];
        let mut init_t = [0u8; 32];
        init_t[12..].copy_from_slice(&initiator);
        let data = encode(&[
            Token::Address([0x11u8; 20].into()),
            Token::Address([0x22u8; 20].into()),
            Token::FixedBytes([0x33u8; 32].to_vec()),
            Token::Uint(1_800_000_000u64.into()),
            Token::FixedBytes([0x44u8; 32].to_vec()),
            Token::Uint(ethabi::Uint::from_big_endian(&[0x55u8; 32])),
            Token::Uint(ethabi::Uint::from_big_endian(&[0x66u8; 32])),
        ]);
        let topics = vec![
            swap_initiated_topic0_hex(),
            format!("0x{}", hex::encode(swap_id)),
            format!("0x{}", hex::encode(init_t)),
        ];
        let d = decode_swap_initiated_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(d.swap_id, swap_id);
        assert_eq!(d.initiator, initiator);
        assert_eq!(d.pool_a, [0x11u8; 20]);
        assert_eq!(d.pool_b, [0x22u8; 20]);
        assert_eq!(d.htlc_hash, [0x33u8; 32]);
        assert_eq!(d.deadline, 1_800_000_000);
        assert_eq!(d.commit_a, [0x44u8; 32]);
        assert_eq!(d.rk_bx, [0x55u8; 32]);
        assert_eq!(d.rk_by, [0x66u8; 32]);
    }

    #[test]
    fn swap_joined_roundtrip() {
        let swap_id = [0x78u8; 32];
        let joiner = [0xBBu8; 20];
        let mut join_t = [0u8; 32];
        join_t[12..].copy_from_slice(&joiner);
        let data = encode(&[
            Token::FixedBytes([0x99u8; 32].to_vec()),
            Token::Uint(ethabi::Uint::from_big_endian(&[0x55u8; 32])),
            Token::Uint(ethabi::Uint::from_big_endian(&[0x66u8; 32])),
        ]);
        let topics = vec![
            swap_joined_topic0_hex(),
            format!("0x{}", hex::encode(swap_id)),
            format!("0x{}", hex::encode(join_t)),
        ];
        let d = decode_swap_joined_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(d.swap_id, swap_id);
        assert_eq!(d.joiner, joiner);
        assert_eq!(d.commit_b, [0x99u8; 32]);
        assert_eq!(d.rk_bx, [0x55u8; 32]);
        assert_eq!(d.rk_by, [0x66u8; 32]);
    }

    #[test]
    fn swap_topic0s_match_onchain_abi() {
        // Cross-checked with `cast sig-event` against SwapCoordinator.sol (plan A).
        assert_eq!(
            swap_initiated_topic0_hex(),
            "0xad6f71d86a1bf4c97615e06bd201161957d47773e757c01b7608b357c44e575b"
        );
        assert_eq!(
            swap_joined_topic0_hex(),
            "0x71c103931ad034926e87adf6b77e4eda8fcf75ef2d0e8a4d9d9eb06063271702"
        );
        assert_eq!(
            swap_settled_topic0_hex(),
            "0xa203be7e143de4f19560b7726a6b05cefe948b0423aaecdcda00828c5a3e001b"
        );
    }

    #[test]
    fn note_added_legacy_topic_v2_body_roundtrip() {
        let cmx = [0x88u8; 32];
        let enc = vec![0xABu8; 580];
        let out = vec![0xCDu8; 80];
        let epk = [0x22u8; 32];
        let nf = [0x33u8; 32];
        let cv = [0x44u8; 32];
        let data = encode(&[
            Token::Bytes(enc.clone()),
            Token::Bytes(out.clone()),
            Token::FixedBytes(epk.to_vec()),
            Token::FixedBytes(nf.to_vec()),
            Token::FixedBytes(cv.to_vec()),
        ]);
        let topics = vec![
            note_added_legacy_topic0_hex(),
            format!("0x{}", hex::encode(cmx)),
        ];
        let decoded =
            decode_note_added_log(&topics, &format!("0x{}", hex::encode(&data))).unwrap();
        assert_eq!(decoded.out_ciphertext, out);
        assert_eq!(decoded.cv_net_x, Some(cv));
    }
}
