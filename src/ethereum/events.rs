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

/// keccak256("ShieldCompleted(bytes32,uint256)")
pub fn shield_completed_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"ShieldCompleted(bytes32,uint256)"))
    )
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
    #[error("invalid topics/data for ShieldCompleted")]
    BadShieldCompleted,
    #[error("ethabi decode: {0}")]
    EthAbi(String),
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
