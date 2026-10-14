//! Access tokens: HS256 JWTs signed with the project's secret.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::crypto::constant_eq;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(claims: &Value, secret: &str) -> String {
	let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
	let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap_or_default());
	let input = format!("{header}.{payload}");
	let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
	mac.update(input.as_bytes());
	format!(
		"{input}.{}",
		URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
	)
}

/// Why a token was refused, in the words a client already matches on.
#[derive(Debug, Clone, PartialEq)]
pub enum JwtError {
	Malformed(&'static str),
	Signature,
	Algorithm(String),
	Expired,
	NotYetValid,
	UsedBeforeIssued,
}

impl std::fmt::Display for JwtError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			JwtError::Malformed(why) => write!(f, "token is malformed: {why}"),
			JwtError::Signature => write!(f, "token signature is invalid: signature is invalid"),
			JwtError::Algorithm(alg) => write!(
				f,
				"token is unverifiable: error while executing keyfunc: unrecognized JWT kid <nil> for algorithm {alg}"
			),
			JwtError::Expired => write!(f, "token has invalid claims: token is expired"),
			JwtError::NotYetValid => write!(f, "token has invalid claims: token is not valid yet"),
			JwtError::UsedBeforeIssued => {
				write!(f, "token has invalid claims: token used before issued")
			}
		}
	}
}

/// The claims of a token signed with `secret`, if it is one and it is current.
pub fn verify(token: &str, secret: &str) -> Result<Map<String, Value>, JwtError> {
	let mut parts = token.split('.');
	let (Some(h), Some(p), Some(s), None) =
		(parts.next(), parts.next(), parts.next(), parts.next())
	else {
		return Err(JwtError::Malformed(
			"token contains an invalid number of segments",
		));
	};
	let header: Value = URL_SAFE_NO_PAD
		.decode(h.trim_end_matches('='))
		.ok()
		.and_then(|b| serde_json::from_slice(&b).ok())
		.ok_or(JwtError::Malformed("could not JSON decode header"))?;
	let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
	if alg != "HS256" {
		return Err(JwtError::Algorithm(if alg.is_empty() {
			"<nil>".into()
		} else {
			alg.to_string()
		}));
	}
	let signature = URL_SAFE_NO_PAD
		.decode(s.trim_end_matches('='))
		.map_err(|_| JwtError::Malformed("could not base64 decode signature"))?;
	let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
	mac.update(format!("{h}.{p}").as_bytes());
	if !constant_eq(&mac.finalize().into_bytes(), &signature) {
		return Err(JwtError::Signature);
	}
	let claims: Map<String, Value> = URL_SAFE_NO_PAD
		.decode(p.trim_end_matches('='))
		.ok()
		.and_then(|b| serde_json::from_slice(&b).ok())
		.ok_or(JwtError::Malformed("could not JSON decode claim"))?;
	let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
	let num = |k: &str| claims.get(k).and_then(Value::as_f64);
	if let Some(exp) = num("exp")
		&& now >= exp
	{
		return Err(JwtError::Expired);
	}
	if let Some(nbf) = num("nbf")
		&& now < nbf
	{
		return Err(JwtError::NotYetValid);
	}
	if let Some(iat) = num("iat")
		&& now < iat
	{
		return Err(JwtError::UsedBeforeIssued);
	}
	Ok(claims)
}

/// The `aud` claim as a list, whether it was written as a string or an array.
pub fn audiences(claims: &Map<String, Value>) -> Vec<String> {
	match claims.get("aud") {
		Some(Value::String(s)) => vec![s.clone()],
		Some(Value::Array(a)) => a
			.iter()
			.filter_map(|v| v.as_str().map(str::to_string))
			.collect(),
		_ => vec![],
	}
}

pub fn string_claim<'a>(claims: &'a Map<String, Value>, k: &str) -> &'a str {
	claims.get(k).and_then(Value::as_str).unwrap_or("")
}

/// The claims an access token carries, in the order they are written.
#[allow(clippy::too_many_arguments)]
pub fn access_claims(
	issuer: &str,
	sub: &str,
	aud: &str,
	exp: i64,
	iat: i64,
	email: &str,
	phone: &str,
	app_metadata: &Value,
	user_metadata: &Value,
	role: &str,
	aal: &str,
	amr: &Value,
	session_id: &str,
	is_anonymous: bool,
) -> Value {
	// serde_json::Map keeps whatever order the crate is built with; a Vec of pairs keeps ours.
	let mut m = Map::new();
	if !issuer.is_empty() {
		m.insert("iss".into(), json!(issuer));
	}
	m.insert("sub".into(), json!(sub));
	m.insert("aud".into(), json!(aud));
	m.insert("exp".into(), json!(exp));
	m.insert("iat".into(), json!(iat));
	m.insert("email".into(), json!(email));
	m.insert("phone".into(), json!(phone));
	m.insert("app_metadata".into(), app_metadata.clone());
	m.insert("user_metadata".into(), user_metadata.clone());
	m.insert("role".into(), json!(role));
	if !aal.is_empty() {
		m.insert("aal".into(), json!(aal));
	}
	if amr.as_array().is_some_and(|a| !a.is_empty()) {
		m.insert("amr".into(), amr.clone());
	}
	if !session_id.is_empty() {
		m.insert("session_id".into(), json!(session_id));
	}
	m.insert("is_anonymous".into(), json!(is_anonymous));
	Value::Object(m)
}

#[cfg(test)]
mod tests {
	use super::*;

	const SECRET: &str = "a-secret-that-is-long-enough-for-hs256-use";

	#[test]
	fn a_signed_token_verifies_and_a_changed_one_does_not() {
		let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 60;
		let t = sign(&json!({"sub": "x", "exp": exp}), SECRET);
		assert_eq!(verify(&t, SECRET).unwrap()["sub"], "x");
		assert_eq!(
			verify(&t, "another-secret-that-is-long-enough-xx").unwrap_err(),
			JwtError::Signature
		);
		let expired = sign(&json!({"sub": "x", "exp": 1}), SECRET);
		assert_eq!(verify(&expired, SECRET).unwrap_err(), JwtError::Expired);
	}

	#[test]
	fn only_hs256_is_accepted() {
		let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
		let p = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
		assert!(matches!(
			verify(&format!("{h}.{p}."), SECRET),
			Err(JwtError::Algorithm(_))
		));
	}
}
