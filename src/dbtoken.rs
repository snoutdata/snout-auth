//! Database tokens: what a person signs in to a Postgres database WITH (PostgreSQL 18's `oauth`
//! authentication), issued through the device grant (RFC 8628).
//!
//! Everything here is pure, so every rule is tested without a database or a network: the signing
//! keys, the token's claims, reading the project out of the scope, the codes a person types, and
//! the verdict on each poll of the token endpoint. The handlers are `api/database.rs`, the table
//! `models/device.rs`.
//!
//! **A database token can never pass for a session token, in either direction** (the plan's O5
//! and O9). It is signed with its own ES256 key, never the session secret, and that key is
//! published at its own key set, never at `/.well-known/jwks.json`; it carries
//! `"token_use": "db"` and its Postgres role in `db_role`, never `role`; and its audience is the
//! project's ref, never `authenticated`. So `jwt::verify` refuses it (wrong algorithm), the data
//! API reads no role from it, and a session token is refused by a database (no `db_role`).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

/// The grant a client polls the token endpoint with (RFC 8628 §3.4).
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// What `token_use` says on every database token.
pub const TOKEN_USE: &str = "db";

/// The scope token that names the project: `db:<ref>` (the plan's O10). The server's `pg_hba`
/// line sets it, and libpq passes it on, so the person never types which project they meant.
pub const SCOPE_PREFIX: &str = "db:";

// ------------------------------------------------------------------------------------------
// The signing keys.

/// One configured key: its id and the pair, whose public half is published.
struct Key {
	kid: String,
	pair: EcdsaKeyPair,
	/// The public point, uncompressed (`04 || x || y`).
	public: Vec<u8>,
}

/// The database-token keys: one signs, every one is published.
///
/// Rotation with overlap is two edits to the same setting, and neither is a moment where a
/// token in flight stops working: add the next key (published, so every database learns it
/// before it signs anything), then move the signing id to it and keep the old key until the
/// longest-lived token it signed has expired.
pub struct KeySet {
	keys: Vec<Key>,
	signer: usize,
}

impl std::fmt::Debug for KeySet {
	/// The key ids only. A private key never reaches a log line.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("KeySet")
			.field(
				"kids",
				&self.keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
			)
			.field("signer", &self.keys[self.signer].kid)
			.finish()
	}
}

impl KeySet {
	/// The keys from a JSON object of key id to base64 PKCS#8 DER (a P-256 private key, as
	/// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | openssl pkcs8 -topk8
	/// -nocrypt -outform DER | base64` writes it), and the id of the one that signs. The id may be
	/// left out only when there is exactly one key.
	pub fn parse(json_text: &str, signing_kid: Option<&str>) -> Result<KeySet, KeyError> {
		let keys_err = |m: String| KeyError::Keys(m);
		let map: Map<String, Value> = serde_json::from_str(json_text).map_err(|e| {
			keys_err(format!(
				"is not a JSON object of key id to base64 PKCS#8 key: {e}"
			))
		})?;
		if map.is_empty() {
			return Err(keys_err("holds no key".into()));
		}
		let rng = SystemRandom::new();
		let mut keys = Vec::new();
		for (kid, value) in &map {
			if kid.is_empty() || kid.len() > 64 || !kid.chars().all(is_kid_char) {
				return Err(keys_err(format!(
					"key id {kid:?} must be 1 to 64 letters, digits, '-', '_' or '.'"
				)));
			}
			let text = value
				.as_str()
				.ok_or_else(|| keys_err(format!("key {kid:?} is not a string")))?;
			let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
			let der = STANDARD
				.decode(compact.trim_end_matches('='))
				.or_else(|_| {
					base64::engine::general_purpose::STANDARD_NO_PAD
						.decode(compact.trim_end_matches('='))
				})
				.map_err(|_| keys_err(format!("key {kid:?} is not base64")))?;
			let pair =
				EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
					.map_err(|e| {
					keys_err(format!(
						"key {kid:?} is not a P-256 private key in PKCS#8 DER ({e})"
					))
				})?;
			let public = pair.public_key().as_ref().to_vec();
			keys.push(Key {
				kid: kid.clone(),
				pair,
				public,
			});
		}
		let signer = match signing_kid {
			Some(id) => keys
				.iter()
				.position(|k| k.kid == id)
				.ok_or_else(|| KeyError::SigningKid(format!("{id:?} is not one of the keys")))?,
			None if keys.len() == 1 => 0,
			None => {
				return Err(KeyError::SigningKid(
					"is required when there are several keys: it says which one signs".into(),
				));
			}
		};
		Ok(KeySet { keys, signer })
	}

	pub fn signing_kid(&self) -> &str {
		&self.keys[self.signer].kid
	}

	/// The public key set, the signing key first. Never a private half.
	pub fn jwks(&self) -> Value {
		let mut order: Vec<&Key> = vec![&self.keys[self.signer]];
		order.extend(
			self.keys
				.iter()
				.enumerate()
				.filter(|(i, _)| *i != self.signer)
				.map(|(_, k)| k),
		);
		let keys: Vec<Value> = order
			.into_iter()
			.map(|k| {
				json!({
					"kty": "EC",
					"crv": "P-256",
					"x": URL_SAFE_NO_PAD.encode(&k.public[1..33]),
					"y": URL_SAFE_NO_PAD.encode(&k.public[33..65]),
					"kid": k.kid,
					"alg": "ES256",
					"use": "sig",
				})
			})
			.collect();
		json!({ "keys": keys })
	}

	/// The claims as a compact ES256 JWS, signed by the signing key and naming it in `kid`.
	pub fn sign(&self, claims: &Value) -> Result<String, String> {
		let key = &self.keys[self.signer];
		let header = json!({ "alg": "ES256", "typ": "JWT", "kid": key.kid });
		let input = format!(
			"{}.{}",
			URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap_or_default()),
			URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap_or_default())
		);
		let sig = key
			.pair
			.sign(&SystemRandom::new(), input.as_bytes())
			.map_err(|_| "the signature could not be made".to_string())?;
		Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
	}

	/// The claims of a token one of these keys signed. For tests and tools: what a database
	/// checks is the validator's business (`snout_oauth`), from the published key set alone.
	pub fn verify(&self, token: &str) -> Result<Map<String, Value>, String> {
		let mut parts = token.split('.');
		let (Some(h), Some(p), Some(s), None) =
			(parts.next(), parts.next(), parts.next(), parts.next())
		else {
			return Err("malformed".into());
		};
		let header: Value = URL_SAFE_NO_PAD
			.decode(h)
			.ok()
			.and_then(|b| serde_json::from_slice(&b).ok())
			.ok_or("malformed header")?;
		if header.get("alg").and_then(Value::as_str) != Some("ES256") {
			return Err("not ES256".into());
		}
		let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
		let key = self
			.keys
			.iter()
			.find(|k| k.kid == kid)
			.ok_or("unknown kid")?;
		let sig = URL_SAFE_NO_PAD
			.decode(s)
			.map_err(|_| "malformed signature")?;
		signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &key.public)
			.verify(format!("{h}.{p}").as_bytes(), &sig)
			.map_err(|_| "signature does not verify")?;
		URL_SAFE_NO_PAD
			.decode(p)
			.ok()
			.and_then(|b| serde_json::from_slice(&b).ok())
			.ok_or_else(|| "malformed claims".into())
	}
}

/// What is wrong with the key settings, by which setting it is.
#[derive(Debug)]
pub enum KeyError {
	Keys(String),
	SigningKid(String),
}

fn is_kid_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

// ------------------------------------------------------------------------------------------
// The token.

/// Who a token is for and what it opens.
pub struct Grant<'a> {
	pub issuer: &'a str,
	pub user_id: &'a str,
	pub email: &'a str,
	pub project_ref: &'a str,
	pub db_role: &'a str,
	pub client_id: &'a str,
	pub jti: &'a str,
}

/// A database token's claims. No `role` claim, ever (O9): `db_role` is the Postgres role, and
/// `role` is what the HTTP services read a session's privileges from.
pub fn claims(g: &Grant<'_>, iat: i64, lifetime: Duration) -> Value {
	let mut m = Map::new();
	m.insert("iss".into(), json!(g.issuer));
	m.insert("sub".into(), json!(g.user_id));
	m.insert("aud".into(), json!(g.project_ref));
	m.insert("iat".into(), json!(iat));
	m.insert("exp".into(), json!(iat + lifetime.as_secs() as i64));
	if !g.email.is_empty() {
		m.insert("email".into(), json!(g.email));
	}
	m.insert("token_use".into(), json!(TOKEN_USE));
	m.insert("db_role".into(), json!(g.db_role));
	m.insert("client_id".into(), json!(g.client_id));
	m.insert("jti".into(), json!(g.jti));
	Value::Object(m)
}

/// The issuer's metadata (RFC 8414, and the OpenID discovery document libpq reads, which is the
/// same object). Everything libpq needs and nothing it does not: there is no authorization
/// endpoint, because the device grant is the only grant, and no ID tokens.
pub fn discovery(issuer: &str) -> Value {
	json!({
		"issuer": issuer,
		"token_endpoint": format!("{issuer}/db/token"),
		"device_authorization_endpoint": format!("{issuer}/db/device"),
		"jwks_uri": format!("{issuer}/db/jwks"),
		"grant_types_supported": [DEVICE_GRANT],
		"response_types_supported": [],
		"token_endpoint_auth_methods_supported": ["none"],
		"scopes_supported": ["openid"],
	})
}

/// Whether a role the access function named is one this server will put in a token: a plain
/// identifier a database could have provisioned, never one of Postgres's own `pg_` roles.
pub fn is_issuable_role(role: &str) -> bool {
	let mut chars = role.chars();
	let Some(first) = chars.next() else {
		return false;
	};
	role.len() <= 63
		&& (first.is_ascii_alphabetic() || first == '_')
		&& chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
		&& !role.to_ascii_lowercase().starts_with("pg_")
}

// ------------------------------------------------------------------------------------------
// The scope.

/// The project a device authorization is for, read from its scope: exactly one `db:<ref>`, and
/// nothing else but `openid`. Anything else is refused rather than ignored, so a scope this
/// server does not understand is never mistaken for one it does.
pub fn project_from_scope(scope: &str) -> Result<String, &'static str> {
	let mut project = None;
	for token in scope.split(' ').filter(|t| !t.is_empty()) {
		if token == "openid" {
			continue;
		}
		let Some(r) = token.strip_prefix(SCOPE_PREFIX) else {
			return Err("the scope may hold only openid and db:<project ref>");
		};
		if !is_project_ref(r) {
			return Err("the db: scope does not name a project ref");
		}
		if project.is_some() {
			return Err("the scope names more than one project");
		}
		project = Some(r.to_string());
	}
	project.ok_or("the scope must name the project, as db:<project ref>")
}

/// A project ref as a scope may carry one: lowercase letters, digits and dashes, up to 63
/// (a DNS label, which is what a ref becomes in a host name). Whether the project EXISTS, and
/// whether this person may reach it, is the access function's to say.
pub fn is_project_ref(r: &str) -> bool {
	!r.is_empty()
		&& r.len() <= 63
		&& !r.starts_with('-')
		&& r.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ------------------------------------------------------------------------------------------
// The two codes.

/// Crockford's base32: no `I`, `L`, `O` or `U`, so nothing read off a terminal is mistaken.
/// The same code a person types for `snoutdata login --device`, read and typed the same way.
pub const USER_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Twelve characters: 60 bits, shown as three groups of four.
pub const USER_CODE_LENGTH: usize = 12;

/// A fresh user code, stored and compared without its dashes.
pub fn new_user_code() -> String {
	let bytes = crate::crypto::random_bytes::<USER_CODE_LENGTH>();
	bytes
		.iter()
		.map(|b| USER_CODE_ALPHABET[(b & 31) as usize] as char)
		.collect()
}

/// `Q7KM-3XNP-9HWR`: how a user code is printed and typed.
pub fn format_user_code(code: &str) -> String {
	code.as_bytes()
		.chunks(4)
		.map(|c| String::from_utf8_lossy(c).into_owned())
		.collect::<Vec<_>>()
		.join("-")
}

/// What somebody typed, in the stored form, or nothing. Crockford's rule on input: `O` is a
/// zero, `I` and `L` are ones; dashes and spaces are formatting.
pub fn normalise_user_code(typed: &str) -> Option<String> {
	let cleaned: String = typed
		.chars()
		.filter(|c| !c.is_whitespace() && *c != '-')
		.map(|c| match c.to_ascii_uppercase() {
			'O' => '0',
			'I' | 'L' => '1',
			other => other,
		})
		.collect();
	(cleaned.len() == USER_CODE_LENGTH && cleaned.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
		.then_some(cleaned)
}

/// The device code: 256 bits, held by the client alone, stored only as its hash.
pub fn new_device_code() -> String {
	URL_SAFE_NO_PAD.encode(crate::crypto::random_bytes::<32>())
}

/// What is stored for either code: the hex SHA-256, so a read of the table approves nothing and
/// collects nothing.
pub fn code_hash(code: &str) -> String {
	crate::crypto::sha256_hex(code)
}

// ------------------------------------------------------------------------------------------
// The poll.

/// A device authorization's state, as the token endpoint reads it.
pub struct Pending<'a> {
	pub client_id: &'a str,
	pub expires_at: OffsetDateTime,
	/// Seconds the client must wait between polls; grows by five on each `slow_down`.
	pub interval: i32,
	pub last_polled_at: Option<OffsetDateTime>,
	pub approved: bool,
	pub denied: bool,
	pub consumed: bool,
}

/// What one poll of the token endpoint answers (RFC 8628 §3.5).
#[derive(Debug, PartialEq)]
pub enum Poll {
	/// `invalid_grant`: the code was never this client's, or it has been spent.
	InvalidGrant(&'static str),
	/// `access_denied`: the person said no, or has no database access to the project.
	AccessDenied,
	/// `expired_token`: nobody approved it in time.
	Expired,
	/// `slow_down`: polled sooner than the interval; the interval grows by five seconds.
	SlowDown,
	/// `authorization_pending`: not decided yet.
	Pending,
	/// Approved: issue the token.
	Issue,
}

/// How much earlier than the interval a poll may arrive before it is too fast. A client that
/// waits exactly the interval can still land a little early by the server's clock.
const POLL_TOLERANCE: Duration = Duration::from_millis(250);

/// The answer to one poll at `now` by `client_id`. In this order, and each is a refusal of
/// everything below it: a spent or foreign code is no code at all; a "no" outlives the clock;
/// an expired code issues nothing even if it was approved; an approval is answered at once even
/// to an eager client; and only a pending code can be polled too fast.
pub fn poll(p: &Pending<'_>, client_id: &str, now: OffsetDateTime) -> Poll {
	if p.consumed {
		return Poll::InvalidGrant("the device code has already been used");
	}
	if p.client_id != client_id {
		return Poll::InvalidGrant("the device code was issued to another client");
	}
	if p.denied {
		return Poll::AccessDenied;
	}
	if now >= p.expires_at {
		return Poll::Expired;
	}
	if p.approved {
		return Poll::Issue;
	}
	if let Some(last) = p.last_polled_at {
		let earliest = last + Duration::from_secs(p.interval.max(0) as u64) - POLL_TOLERANCE;
		if now < earliest {
			return Poll::SlowDown;
		}
	}
	Poll::Pending
}

/// May a person still decide on this code? `Err` carries the status and the sentence.
pub fn decidable(
	approved: bool,
	denied: bool,
	consumed: bool,
	expires_at: OffsetDateTime,
	now: OffsetDateTime,
) -> Result<(), (u16, &'static str, &'static str)> {
	if denied {
		return Err((
			409,
			"device_code_denied",
			"That code was turned down. Run the command again for a new one.",
		));
	}
	if approved || consumed {
		return Err((
			409,
			"device_code_used",
			"That code has already been approved. Run the command again for a new one.",
		));
	}
	if now >= expires_at {
		return Err((
			410,
			"device_code_expired",
			"That code has expired. Run the command again for a new one.",
		));
	}
	Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use ring::rand::SystemRandom;

	/// A fresh P-256 key as the setting carries it.
	pub fn new_key_b64() -> String {
		let doc = EcdsaKeyPair::generate_pkcs8(
			&signature::ECDSA_P256_SHA256_FIXED_SIGNING,
			&SystemRandom::new(),
		)
		.unwrap();
		STANDARD.encode(doc.as_ref())
	}

	fn keyset(kids: &[&str], signer: Option<&str>) -> Result<KeySet, KeyError> {
		let map: Map<String, Value> = kids
			.iter()
			.map(|k| (k.to_string(), json!(new_key_b64())))
			.collect();
		KeySet::parse(&Value::Object(map).to_string(), signer)
	}

	#[test]
	fn a_token_is_es256_names_its_key_and_verifies() {
		let ks = keyset(&["db-1"], None).unwrap();
		let g = Grant {
			issuer: "https://issuer.test/auth/v1",
			user_id: "6b0e8f4a-0000-4000-8000-000000000001",
			email: "a@example.com",
			project_ref: "abcdefghijklm",
			db_role: "u_alice",
			client_id: "psql",
			jti: "j1",
		};
		let t = ks
			.sign(&claims(&g, 1000, Duration::from_secs(3600)))
			.unwrap();
		let header: Value = serde_json::from_slice(
			&URL_SAFE_NO_PAD
				.decode(t.split('.').next().unwrap())
				.unwrap(),
		)
		.unwrap();
		assert_eq!(header["alg"], "ES256");
		assert_eq!(header["kid"], "db-1");
		let c = ks.verify(&t).unwrap();
		assert_eq!(c["aud"], "abcdefghijklm");
		assert_eq!(c["token_use"], "db");
		assert_eq!(c["db_role"], "u_alice");
		assert_eq!(c["exp"], 4600);
		assert!(
			c.get("role").is_none(),
			"a database token never has role (O9)"
		);
		// The session verifier refuses it: another algorithm, never the session secret.
		assert!(crate::jwt::verify(&t, "a-secret-that-is-long-enough-for-hs256-use").is_err());
		// A changed byte does not verify.
		let mut bad = t.clone().into_bytes();
		let n = bad.len() - 5;
		bad[n] = if bad[n] == b'A' { b'B' } else { b'A' };
		assert!(ks.verify(&String::from_utf8(bad).unwrap()).is_err());
	}

	#[test]
	fn the_key_set_publishes_public_halves_only_signer_first() {
		let ks = keyset(&["old", "new", "next"], Some("new")).unwrap();
		let jwks = ks.jwks();
		let keys = jwks["keys"].as_array().unwrap();
		assert_eq!(keys.len(), 3);
		assert_eq!(keys[0]["kid"], "new");
		for k in keys {
			assert!(k.get("d").is_none());
			assert_eq!(k["alg"], "ES256");
			assert_eq!(k["crv"], "P-256");
			assert_eq!(
				URL_SAFE_NO_PAD
					.decode(k["x"].as_str().unwrap())
					.unwrap()
					.len(),
				32
			);
		}
		assert_eq!(ks.signing_kid(), "new");
		assert!(!format!("{ks:?}").contains("pair"));
	}

	#[test]
	fn keys_refuse_rather_than_guess() {
		assert!(
			keyset(&["a", "b"], None).is_err(),
			"several keys need a signer"
		);
		assert!(keyset(&["a"], Some("b")).is_err(), "the signer must exist");
		assert!(KeySet::parse("{}", None).is_err());
		assert!(KeySet::parse("[]", None).is_err());
		assert!(KeySet::parse(r#"{"a": "bm90IGEga2V5"}"#, None).is_err());
		assert!(KeySet::parse(r#"{"a b": "x"}"#, None).is_err());
	}

	#[test]
	fn the_scope_names_exactly_one_project() {
		assert_eq!(
			project_from_scope("openid db:abcdefghijklm").unwrap(),
			"abcdefghijklm"
		);
		assert_eq!(project_from_scope("db:x1").unwrap(), "x1");
		assert!(project_from_scope("openid").is_err());
		assert!(project_from_scope("").is_err());
		assert!(project_from_scope("openid db:a db:b").is_err());
		assert!(project_from_scope("openid email db:a").is_err());
		assert!(project_from_scope("db:").is_err());
		assert!(project_from_scope("db:UPPER").is_err());
		assert!(project_from_scope("db:a'b").is_err());
	}

	#[test]
	fn roles_are_plain_identifiers() {
		assert!(is_issuable_role("u_alice"));
		assert!(is_issuable_role("_x1"));
		assert!(!is_issuable_role(""));
		assert!(!is_issuable_role("1abc"));
		assert!(!is_issuable_role("pg_read_all_data"));
		assert!(!is_issuable_role("a\"b"));
		assert!(!is_issuable_role(&"a".repeat(64)));
	}

	#[test]
	fn user_codes_are_typed_forgivingly() {
		let c = new_user_code();
		assert_eq!(c.len(), 12);
		assert_eq!(normalise_user_code(&format_user_code(&c)).unwrap(), c);
		assert_eq!(
			normalise_user_code("q7km-3xnp-9hwo").unwrap(),
			"Q7KM3XNP9HW0"
		);
		assert_eq!(
			normalise_user_code(" il00 0000 0000").unwrap(),
			"110000000000"
		);
		assert!(normalise_user_code("Q7KM-3XNP-9HWU").is_none());
		assert!(normalise_user_code("Q7KM-3XNP").is_none());
		assert_eq!(format_user_code("Q7KM3XNP9HWR"), "Q7KM-3XNP-9HWR");
		assert_ne!(new_device_code(), new_device_code());
	}

	fn pending(now: OffsetDateTime) -> Pending<'static> {
		Pending {
			client_id: "psql",
			expires_at: now + Duration::from_secs(600),
			interval: 5,
			last_polled_at: None,
			approved: false,
			denied: false,
			consumed: false,
		}
	}

	#[test]
	fn every_rfc_8628_answer() {
		let now = OffsetDateTime::now_utc();
		let p = pending(now);
		assert_eq!(poll(&p, "psql", now), Poll::Pending);
		assert!(matches!(poll(&p, "other", now), Poll::InvalidGrant(_)));
		let fast = Pending {
			last_polled_at: Some(now - Duration::from_secs(2)),
			..pending(now)
		};
		assert_eq!(poll(&fast, "psql", now), Poll::SlowDown);
		let on_time = Pending {
			last_polled_at: Some(now - Duration::from_millis(4900)),
			..pending(now)
		};
		assert_eq!(poll(&on_time, "psql", now), Poll::Pending);
		let approved = Pending {
			approved: true,
			last_polled_at: Some(now),
			..pending(now)
		};
		assert_eq!(poll(&approved, "psql", now), Poll::Issue);
		let denied = Pending {
			denied: true,
			..pending(now)
		};
		assert_eq!(poll(&denied, "psql", now), Poll::AccessDenied);
		let expired = Pending {
			approved: true,
			expires_at: now,
			..pending(now)
		};
		assert_eq!(poll(&expired, "psql", now), Poll::Expired);
		let spent = Pending {
			approved: true,
			consumed: true,
			..pending(now)
		};
		assert!(matches!(poll(&spent, "psql", now), Poll::InvalidGrant(_)));
	}

	#[test]
	fn a_decided_code_cannot_be_decided_again() {
		let now = OffsetDateTime::now_utc();
		let later = now + Duration::from_secs(60);
		assert!(decidable(false, false, false, later, now).is_ok());
		assert_eq!(
			decidable(true, false, false, later, now).unwrap_err().0,
			409
		);
		assert_eq!(
			decidable(false, true, false, later, now).unwrap_err().1,
			"device_code_denied"
		);
		assert_eq!(decidable(false, false, false, now, now).unwrap_err().0, 410);
	}

	#[test]
	fn discovery_names_the_device_grant() {
		let d = discovery("https://accounts.snoutdata.com/auth/v1");
		assert_eq!(d["issuer"], "https://accounts.snoutdata.com/auth/v1");
		assert_eq!(
			d["device_authorization_endpoint"],
			"https://accounts.snoutdata.com/auth/v1/db/device"
		);
		assert_eq!(d["grant_types_supported"][0], DEVICE_GRANT);
	}
}
