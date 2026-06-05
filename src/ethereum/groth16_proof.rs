//! ABI-encode snarkjs Groth16 proofs for `Groth16ProofCodec` on-chain.

use ethabi::{encode, Token, Uint};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Groth16ProofError {
    #[error("invalid snarkjs proof JSON: {0}")]
    BadJson(#[from] serde_json::Error),
    #[error("missing or invalid proof field: {0}")]
    BadField(&'static str),
    #[error("invalid field element: {0}")]
    BadElement(String),
}

/// snarkjs `proof.json` subset (`pi_a`, `pi_b`, `pi_c`).
#[derive(Debug, Deserialize)]
struct SnarkJsProof {
    #[serde(rename = "pi_a")]
    pi_a: Vec<String>,
    #[serde(rename = "pi_b")]
    pi_b: Vec<Vec<String>>,
    #[serde(rename = "pi_c")]
    pi_c: Vec<String>,
}

/// Parse a snarkjs G1/G2 coordinate (hex `0x…` or decimal string).
fn parse_snarkjs_coord(s: &str) -> Result<Uint, Groth16ProofError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Groth16ProofError::BadElement("empty".into()));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Uint::from_str_radix(hex, 16)
            .map_err(|e| Groth16ProofError::BadElement(format!("0x…: {e}")))
    } else {
        Uint::from_dec_str(s).map_err(|e| Groth16ProofError::BadElement(format!("dec: {e}")))
    }
}

/// G2 limb order matches `circuits/scripts/export_groth16_fixture_sol.js` / snarkjs
/// `exportSolidityCalldata` (swap `[0]`/`[1]` within each `pi_b` row).
pub fn p_b_from_snarkjs_pi_b(pi_b: &[Vec<String>]) -> Result<[[Uint; 2]; 2], Groth16ProofError> {
    if pi_b.len() < 2 || pi_b[0].len() < 2 || pi_b[1].len() < 2 {
        return Err(Groth16ProofError::BadField("pi_b"));
    }
    Ok([
        [
            parse_snarkjs_coord(&pi_b[0][1])?,
            parse_snarkjs_coord(&pi_b[0][0])?,
        ],
        [
            parse_snarkjs_coord(&pi_b[1][1])?,
            parse_snarkjs_coord(&pi_b[1][0])?,
        ],
    ])
}

pub fn p_a_from_snarkjs_pi_a(pi_a: &[String]) -> Result<[Uint; 2], Groth16ProofError> {
    if pi_a.len() < 2 {
        return Err(Groth16ProofError::BadField("pi_a"));
    }
    Ok([
        parse_snarkjs_coord(&pi_a[0])?,
        parse_snarkjs_coord(&pi_a[1])?,
    ])
}

pub fn p_c_from_snarkjs_pi_c(pi_c: &[String]) -> Result<[Uint; 2], Groth16ProofError> {
    if pi_c.len() < 2 {
        return Err(Groth16ProofError::BadField("pi_c"));
    }
    Ok([
        parse_snarkjs_coord(&pi_c[0])?,
        parse_snarkjs_coord(&pi_c[1])?,
    ])
}

/// `abi.encode(pA, pB, pC)` — same layout as `Groth16ProofCodec.encode`.
pub fn encode_groth16_proof_components(
    p_a: [Uint; 2],
    p_b: [[Uint; 2]; 2],
    p_c: [Uint; 2],
) -> Vec<u8> {
    encode(&[
        Token::FixedArray(vec![Token::Uint(p_a[0]), Token::Uint(p_a[1])]),
        Token::FixedArray(vec![
            Token::FixedArray(vec![Token::Uint(p_b[0][0]), Token::Uint(p_b[0][1])]),
            Token::FixedArray(vec![Token::Uint(p_b[1][0]), Token::Uint(p_b[1][1])]),
        ]),
        Token::FixedArray(vec![Token::Uint(p_c[0]), Token::Uint(p_c[1])]),
    ])
}

/// Parse snarkjs `proof.json` and ABI-encode for `PrivacyPool` / `Groth16ActionVerifier`.
pub fn encode_groth16_proof_from_snarkjs_json(proof_json: &str) -> Result<Vec<u8>, Groth16ProofError> {
    let proof: SnarkJsProof = serde_json::from_str(proof_json)?;
    let p_a = p_a_from_snarkjs_pi_a(&proof.pi_a)?;
    let p_b = p_b_from_snarkjs_pi_b(&proof.pi_b)?;
    let p_c = p_c_from_snarkjs_pi_c(&proof.pi_c)?;
    Ok(encode_groth16_proof_components(p_a, p_b, p_c))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values from `contracts/test/fixtures/Groth16ActionProofFixture.sol`.
    fn fixture_components() -> ([Uint; 2], [[Uint; 2]; 2], [Uint; 2]) {
        let u = |s: &str| Uint::from_dec_str(s).unwrap();
        let p_a = [
            u("17919778463156149791105683928459099445634456509562464729131084433960213123508"),
            u("13776232620911204615663878077541649720123385851784492142499193909813698234928"),
        ];
        let p_b = [
            [
                u("1000386479692219227267373962725199089383937920754526679415968292405780711566"),
                u("15135249452151867335032705668679475097443966444862672916916327787004436992135"),
            ],
            [
                u("16470907391204460686537008441394566475981984736230375812989527957105479008372"),
                u("20735845801934146073560897851617142237840307950785304952883312076477342435180"),
            ],
        ];
        let p_c = [
            u("20576235549624350877437103157861875509403141295916501628592387226641345396202"),
            u("15408846632919862133008620024569352690024961929408087285772936705251188399687"),
        ];
        (p_a, p_b, p_c)
    }

    #[test]
    fn fixture_encode_non_empty() {
        let (p_a, p_b, p_c) = fixture_components();
        let enc = encode_groth16_proof_components(p_a, p_b, p_c);
        assert!(enc.len() > 64);
    }

    #[test]
    fn pi_b_limb_swap_matches_fixture() {
        // Raw snarkjs order (before swap) for the dev shield sample — from a captured proof.json.
        let pi_b = [
            vec![
                "15135249452151867335032705668679475097443966444862672916916327787004436992135"
                    .into(),
                "1000386479692219227267373962725199089383937920754526679415968292405780711566"
                    .into(),
            ],
            vec![
                "20735845801934146073560897851617142237840307950785304952883312076477342435180"
                    .into(),
                "16470907391204460686537008441394566475981984736230375812989527957105479008372"
                    .into(),
            ],
        ];
        let swapped = p_b_from_snarkjs_pi_b(&pi_b).unwrap();
        let (_, fixture_p_b, _) = fixture_components();
        assert_eq!(swapped[0][0], fixture_p_b[0][0]);
        assert_eq!(swapped[0][1], fixture_p_b[0][1]);
        assert_eq!(swapped[1][0], fixture_p_b[1][0]);
        assert_eq!(swapped[1][1], fixture_p_b[1][1]);
    }
}
