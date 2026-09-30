//! OpenID Connect: an issuer's discovery document and signing keys, and checking an ID token
//! against them.
//!
//! A token is accepted only when its signature verifies with one of the issuer's current keys
//! (RS256 or ES256), its `iss` is the issuer, and it has not expired. Audience and nonce are the
//! caller's to check, since they depend on the flow.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature;
use serde_json::{Map, Value};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Discovery {
	pub issuer: String,
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub userinfo_endpoint: Option<String>,
	pub jwks_uri: String,
}

#[derive(Clone)]
struct Key {
	kid: Option<String>,
	kty: String,
	/// For RSA, the DER RSAPublicKey; for EC P-256, the uncompressed point.
	public: Vec<u8>,
}

struct Entry {
	discovery: Discovery,
	keys: Vec<Key>,
	fetched: Instant,
}

/// Discovery documents and key sets, kept for an hour and refetched when a token names a key
/// the cache does not have (the issuer rotated).
pub struct Cache {
	entries: Mutex<HashMap<String, Entry>>,
}

impl Default for Cache {
	fn default() -> Self {
		Cache {
			entries: Mutex::new(HashMap::new()),
		}
	}
}

fn der_len(n: usize, out: &mut Vec<u8>) {
	if n < 0x80 {
		out.push(n as u8);
	} else {
		let bytes: Vec<u8> = n
			.to_be_bytes()
			.iter()
			.copied()
			.skip_while(|b| *b == 0)
			.collect();
		out.push(0x80 | bytes.len() as u8);
		out.extend(bytes);
	}
}

fn der_uint(bytes: &[u8], out: &mut Vec<u8>) {
	let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
	let mut v = trimmed;
	if v.first().is_some_and(|b| b & 0x80 != 0) {
		v.insert(0, 0);
	}
	out.push(0x02);
	der_len(v.len(), out);
	out.extend(v);
}

/// An RSAPublicKey (PKCS #1) from a JWK's modulus and exponent.
fn rsa_der(n: &[u8], e: &[u8]) -> Vec<u8> {
	let mut body = Vec::new();
	der_uint(n, &mut body);
	der_uint(e, &mut body);
	let mut out = vec![0x30];
	der_len(body.len(), &mut out);
	out.extend(body);
	out
}

fn parse_keys(jwks: &Value) -> Vec<Key> {
	let mut out = Vec::new();
	for k in jwks
		.get("keys")
		.and_then(Value::as_array)
		.into_iter()
		.flatten()
	{
		let s = |f: &str| k.get(f).and_then(Value::as_str);
		let b = |f: &str| s(f).and_then(|v| URL_SAFE_NO_PAD.decode(v.trim_end_matches('=')).ok());
		let kid = s("kid").map(str::to_string);
		match s("kty") {
			Some("RSA") => {
				if let (Some(n), Some(e)) = (b("n"), b("e")) {
					out.push(Key {
						kid,
						kty: "RSA".into(),
						public: rsa_der(&n, &e),
					});
				}
			}
			Some("EC") if s("crv") == Some("P-256") => {
				if let (Some(x), Some(y)) = (b("x"), b("y")) {
					let mut p = vec![0x04];
					p.extend(x);
					p.extend(y);
					out.push(Key {
						kid,
						kty: "EC".into(),
						public: p,
					});
				}
			}
			_ => {}
		}
	}
	out
}

impl Cache {
	async fn load(
		&self,
		http: &reqwest::Client,
		issuer: &str,
		force: bool,
	) -> Result<(Discovery, Vec<Key>), String> {
		let mut entries = self.entries.lock().await;
		if !force
			&& let Some(e) = entries.get(issuer)
			&& e.fetched.elapsed() < Duration::from_secs(3600)
		{
			return Ok((e.discovery.clone(), e.keys.clone()));
		}
		let url = format!(
			"{}/.well-known/openid-configuration",
			issuer.trim_end_matches('/')
		);
		let doc: Value = http
			.get(&url)
			.send()
			.await
			.map_err(|e| e.to_string())?
			.json()
			.await
			.map_err(|e| e.to_string())?;
		let get = |k: &str| doc.get(k).and_then(Value::as_str).map(str::to_string);
		let discovery = Discovery {
			issuer: get("issuer").ok_or("the discovery document has no issuer")?,
			authorization_endpoint: get("authorization_endpoint")
				.ok_or("the discovery document has no authorization endpoint")?,
			token_endpoint: get("token_endpoint")
				.ok_or("the discovery document has no token endpoint")?,
			userinfo_endpoint: get("userinfo_endpoint"),
			jwks_uri: get("jwks_uri").ok_or("the discovery document has no jwks_uri")?,
		};
		if discovery.issuer != issuer {
			return Err(format!(
				"oidc: issuer did not match the issuer returned by provider, expected {issuer:?} got {:?}",
				discovery.issuer
			));
		}
		let jwks: Value = http
			.get(&discovery.jwks_uri)
			.send()
			.await
			.map_err(|e| e.to_string())?
			.json()
			.await
			.map_err(|e| e.to_string())?;
		let keys = parse_keys(&jwks);
		entries.insert(
			issuer.to_string(),
			Entry {
				discovery: discovery.clone(),
				keys: keys.clone(),
				fetched: Instant::now(),
			},
		);
		Ok((discovery, keys))
	}

	pub async fn discovery(
		&self,
		http: &reqwest::Client,
		issuer: &str,
	) -> Result<Discovery, String> {
		Ok(self.load(http, issuer, false).await?.0)
	}

	/// The claims of an ID token issued by `issuer`, if it verifies.
	pub async fn verify(
		&self,
		http: &reqwest::Client,
		issuer: &str,
		token: &str,
	) -> Result<Map<String, Value>, String> {
		let mut parts = token.split('.');
		let (Some(h), Some(p), Some(s), None) =
			(parts.next(), parts.next(), parts.next(), parts.next())
		else {
			return Err("oidc: malformed jwt".into());
		};
		let header: Value = URL_SAFE_NO_PAD
			.decode(h)
			.ok()
			.and_then(|b| serde_json::from_slice(&b).ok())
			.ok_or("oidc: malformed jwt header")?;
		let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
		let kid = header.get("kid").and_then(Value::as_str);
		let sig = URL_SAFE_NO_PAD
			.decode(s)
			.map_err(|_| "oidc: malformed jwt signature")?;
		let input = format!("{h}.{p}");
		let check = |keys: &[Key]| {
			keys.iter()
				.filter(|k| kid.is_none() || k.kid.as_deref() == kid)
				.any(|k| {
					let alg_ref: &dyn signature::VerificationAlgorithm = match (alg, k.kty.as_str())
					{
						("RS256", "RSA") => &signature::RSA_PKCS1_2048_8192_SHA256,
						("ES256", "EC") => &signature::ECDSA_P256_SHA256_FIXED,
						_ => return false,
					};
					signature::UnparsedPublicKey::new(alg_ref, &k.public)
						.verify(input.as_bytes(), &sig)
						.is_ok()
				})
		};
		let (_, keys) = self.load(http, issuer, false).await?;
		if !check(&keys) {
			let (_, fresh) = self.load(http, issuer, true).await?;
			if !check(&fresh) {
				return Err(
					"failed to verify signature: failed to verify id token signature".into(),
				);
			}
		}
		let claims: Map<String, Value> = URL_SAFE_NO_PAD
			.decode(p)
			.ok()
			.and_then(|b| serde_json::from_slice(&b).ok())
			.ok_or("oidc: malformed jwt payload")?;
		let iss = claims.get("iss").and_then(Value::as_str).unwrap_or("");
		if iss != issuer {
			return Err(format!(
				"oidc: id token issued by a different provider, expected {issuer:?} got {iss:?}"
			));
		}
		let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
		match claims.get("exp").and_then(Value::as_f64) {
			Some(exp) if now < exp => {}
			_ => return Err("oidc: token is expired".into()),
		}
		Ok(claims)
	}
}

/// Whether `access_token` is the one an ID token's `at_hash` names (the left half of its SHA-256).
pub fn at_hash_matches(at_hash: &str, access_token: &str) -> bool {
	use sha2::{Digest, Sha256};
	let d = Sha256::digest(access_token.as_bytes());
	URL_SAFE_NO_PAD.encode(&d[..16]) == at_hash
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rsa_der_is_a_sequence_of_two_integers() {
		let d = rsa_der(&[0x80, 1, 2], &[1, 0, 1]);
		assert_eq!(
			d,
			vec![
				0x30, 0x0b, 0x02, 0x04, 0x00, 0x80, 0x01, 0x02, 0x02, 0x03, 0x01, 0x00, 0x01
			]
		);
	}
}
