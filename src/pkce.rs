//! Proof Key for Code Exchange: a client proves at the end of a flow that it is the one that
//! started it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::crypto::constant_eq;
use crate::error::{ApiError, ApiResult};

pub const PREFIX: &str = "pkce_";
const MIN: usize = 43;
const MAX: usize = 128;

/// Both or neither of the challenge and its method, and a challenge of the permitted form.
pub fn validate_params(method: &str, challenge: &str) -> ApiResult<()> {
	if challenge.is_empty() != method.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"PKCE flow requires code_challenge_method and code_challenge",
		));
	}
	if challenge.is_empty() {
		return Ok(());
	}
	if challenge.len() < MIN || challenge.len() > MAX {
		return Err(ApiError::bad_request(
			"validation_failed",
			format!("code challenge has to be between {MIN} and {MAX} characters"),
		));
	}
	if !challenge
		.bytes()
		.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
	{
		return Err(ApiError::bad_request(
			"validation_failed",
			"code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes",
		));
	}
	Ok(())
}

pub fn verify(challenge: &str, method: &str, verifier: &str) -> Result<(), String> {
	match method.to_ascii_lowercase().as_str() {
		"s256" => {
			let hashed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
			if constant_eq(challenge.as_bytes(), hashed.as_bytes()) {
				Ok(())
			} else {
				Err(MISMATCH.into())
			}
		}
		"plain" => {
			if constant_eq(challenge.as_bytes(), verifier.as_bytes()) {
				Ok(())
			} else {
				Err(MISMATCH.into())
			}
		}
		_ => Err("code challenge method not supported".into()),
	}
}

const MISMATCH: &str = "code challenge does not match previously saved code verifier";

/// `pkce_<hash>` for a PKCE flow, the hash alone otherwise.
pub fn prefix_token(hash: &str, pkce: bool) -> String {
	if pkce {
		format!("{PREFIX}{hash}")
	} else {
		hash.to_string()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn s256_matches_its_verifier() {
		let verifier = "a".repeat(50);
		let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
		assert!(verify(&challenge, "S256", &verifier).is_ok());
		assert!(verify(&challenge, "s256", "b").is_err());
		assert!(verify("x", "other", "x").is_err());
	}

	#[test]
	fn params_are_both_or_neither() {
		assert!(validate_params("", "").is_ok());
		assert!(validate_params("s256", "").is_err());
		assert!(validate_params("s256", &"a".repeat(43)).is_ok());
		assert!(validate_params("s256", &"a".repeat(42)).is_err());
		assert!(validate_params("s256", &format!("{}!", "a".repeat(43))).is_err());
	}
}
