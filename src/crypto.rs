//! Random codes, hashes and the two refresh-token formats.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha224, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

fn fill(buf: &mut [u8]) {
	OsRng
		.try_fill_bytes(buf)
		.expect("the operating system's random source failed");
}

/// A numeric one-time code of `digits` digits, leading zeros kept. The thread generator is a
/// cryptographically secure one, seeded from the operating system.
pub fn otp(digits: usize) -> String {
	let upper = 10u64.pow(digits as u32);
	format!(
		"{:0width$}",
		rand::rng().random_range(0..upper),
		width = digits
	)
}

/// What is stored for a mailed code, and is the token in the mailed link: an HMAC-SHA224 of the
/// address and the code, keyed by a key derived from the project's secret, so a link's token says
/// nothing about its code. 56 hex characters, the length and alphabet the columns already hold.
pub fn token_hash(secret: &str, email_or_phone: &str, otp: &str) -> String {
	let mut derive = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
	derive.update(b"snout-auth email token v1");
	let key = derive.finalize().into_bytes();
	let mut mac = Hmac::<Sha224>::new_from_slice(&key).expect("hmac key");
	mac.update(email_or_phone.as_bytes());
	mac.update(&[0]);
	mac.update(otp.as_bytes());
	hex::encode(mac.finalize().into_bytes())
}

/// Lower-case letters and digits (base32), at least 8 long.
pub fn secure_alphanumeric(length: usize) -> String {
	let length = length.max(8);
	let mut bytes = vec![0u8; (length * 5).div_ceil(8)];
	fill(&mut bytes);
	let s = data_encoding::BASE32_NOPAD
		.encode(&bytes)
		.to_ascii_lowercase();
	s[..length].to_string()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
	let mut b = [0u8; N];
	fill(&mut b);
	b
}

pub fn sha256_hex(s: &str) -> String {
	hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn constant_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ------------------------------------------------------------------------------------------
// Passwords.

const BCRYPT_COST: u32 = 10;

/// A bcrypt hash made once, of nothing anybody knows, so an address with no account costs the
/// same comparison as one with an account and its answer takes as long.
static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
	let mut secret = [0u8; 24];
	fill(&mut secret);
	bcrypt::hash(URL_SAFE_NO_PAD.encode(secret), BCRYPT_COST).expect("bcrypt")
});

pub fn hash_password(password: &str) -> String {
	bcrypt::hash(password, BCRYPT_COST).expect("bcrypt")
}

/// Whether `password` matches `hash`. An empty hash never matches.
pub fn verify_password(hash: &str, password: &str) -> bool {
	if hash.is_empty() {
		return false;
	}
	if hash.starts_with("$argon2") {
		return verify_argon2(hash, password);
	}
	bcrypt::verify(password, hash).unwrap_or(false)
}

/// Spend the time a real comparison would, for an address that has no account.
pub fn verify_nothing(password: &str) {
	let _ = bcrypt::verify(password, &DUMMY_HASH);
}

/// The cost of a bcrypt hash, when it is one.
pub fn bcrypt_cost(hash: &str) -> Option<u32> {
	let parts: Vec<&str> = hash.split('$').collect();
	if parts.len() < 4 || !matches!(parts[1], "2a" | "2b" | "2y" | "2x") {
		return None;
	}
	parts[2].parse().ok()
}

pub fn is_valid_password_hash(hash: &str) -> bool {
	if hash.starts_with("$argon2") {
		return argon2::PasswordHash::new(hash).is_ok();
	}
	bcrypt_cost(hash).is_some() && hash.len() == 60
}

fn verify_argon2(hash: &str, password: &str) -> bool {
	use argon2::PasswordVerifier;
	let Ok(parsed) = argon2::PasswordHash::new(hash) else {
		return false;
	};
	// Refuse hashes that would cost more than a sign-in should (the same ceilings as a params
	// block: 1 GiB of memory, 20 passes, 16 lanes), so an imported hash cannot stall the server.
	let get = |k: &str| parsed.params.get_decimal(k).unwrap_or(0);
	if get("m") > 1024 * 1024 || get("t") > 20 || get("p") > 16 {
		return false;
	}
	argon2::Argon2::default()
		.verify_password(password.as_bytes(), &parsed)
		.is_ok()
}

// ------------------------------------------------------------------------------------------
// Refresh tokens.

/// The signed format: version 0, the session's id, a counter, the first 128 bits of an
/// HMAC-SHA-256 over those, and four bytes of SHA-256 as a checksum, in unpadded base64url.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedRefreshToken {
	pub session_id: Uuid,
	pub counter: i64,
	signed: Vec<u8>,
	signature: Vec<u8>,
}

const SIGNATURE_LEN: usize = 16;
const CHECKSUM_LEN: usize = 4;
const MIN_LEN: usize = 1 + 16 + 1 + SIGNATURE_LEN + CHECKSUM_LEN;

impl SignedRefreshToken {
	pub fn encode(session_id: Uuid, counter: i64, key: &[u8]) -> String {
		let mut out = Vec::with_capacity(MIN_LEN + 8);
		out.push(0);
		out.extend_from_slice(session_id.as_bytes());
		let mut n = counter.max(0) as u64;
		loop {
			let byte = (n & 0x7f) as u8;
			n >>= 7;
			if n == 0 {
				out.push(byte);
				break;
			}
			out.push(byte | 0x80);
		}
		let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
		mac.update(&out);
		let sig = mac.finalize().into_bytes();
		out.extend_from_slice(&sig[..SIGNATURE_LEN]);
		let checksum = Sha256::digest(&out);
		out.extend_from_slice(&checksum[..CHECKSUM_LEN]);
		URL_SAFE_NO_PAD.encode(out)
	}

	pub fn parse(token: &str) -> Option<SignedRefreshToken> {
		let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
		if bytes.len() < MIN_LEN || bytes[0] != 0 {
			return None;
		}
		let body = &bytes[..bytes.len() - CHECKSUM_LEN];
		let checksum = Sha256::digest(body);
		if !constant_eq(
			&checksum[..CHECKSUM_LEN],
			&bytes[bytes.len() - CHECKSUM_LEN..],
		) {
			return None;
		}
		let session_id = Uuid::from_slice(&body[1..17]).ok()?;
		let mut counter: u64 = 0;
		let mut shift = 0;
		let mut i = 17;
		loop {
			let b = *body.get(i)?;
			counter |= u64::from(b & 0x7f).checked_shl(shift)?;
			i += 1;
			if b & 0x80 == 0 {
				break;
			}
			shift += 7;
			if shift > 63 {
				return None;
			}
		}
		let rest = &body[i..];
		if rest.len() != SIGNATURE_LEN {
			return None;
		}
		Some(SignedRefreshToken {
			session_id,
			counter: counter.min(i64::MAX as u64) as i64,
			signed: body[..i].to_vec(),
			signature: rest.to_vec(),
		})
	}

	pub fn check(&self, key: &[u8]) -> bool {
		let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
		mac.update(&self.signed);
		let sig = mac.finalize().into_bytes();
		constant_eq(&sig[..SIGNATURE_LEN], &self.signature)
	}
}

/// A session's refresh-token signing key, as stored (unpadded base64url of 32 random bytes).
pub fn new_hmac_key() -> String {
	URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn decode_hmac_key(stored: &str) -> Option<Vec<u8>> {
	URL_SAFE_NO_PAD.decode(stored).ok()
}

pub fn b64_std_nopad(bytes: &[u8]) -> String {
	STANDARD_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn otps_have_their_length() {
		for _ in 0..50 {
			let o = otp(6);
			assert_eq!(o.len(), 6);
			assert!(o.chars().all(|c| c.is_ascii_digit()));
		}
	}

	#[test]
	fn signed_tokens_round_trip_and_reject_tampering() {
		let key = random_bytes::<32>();
		let id = Uuid::new_v4();
		for counter in [0i64, 1, 127, 128, 300, 1 << 40] {
			let t = SignedRefreshToken::encode(id, counter, &key);
			let p = SignedRefreshToken::parse(&t).unwrap();
			assert_eq!(p.session_id, id);
			assert_eq!(p.counter, counter);
			assert!(p.check(&key));
			assert!(!p.check(&random_bytes::<32>()));
		}
		let t = SignedRefreshToken::encode(id, 5, &key);
		let mut b = URL_SAFE_NO_PAD.decode(&t).unwrap();
		b[3] ^= 1;
		assert!(SignedRefreshToken::parse(&URL_SAFE_NO_PAD.encode(b)).is_none());
	}

	#[test]
	fn token_hash_is_keyed_and_56_hex() {
		let secret = "a-project-secret-of-at-least-32-chars";
		let h = token_hash(secret, "a@b.c", "123456");
		assert_eq!(h.len(), 56);
		assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
		assert_eq!(h, token_hash(secret, "a@b.c", "123456"));
		// Not computable from the address and code alone.
		assert_ne!(h, hex::encode(Sha224::digest(b"a@b.c123456")));
		assert_ne!(
			h,
			token_hash("another-project-secret-32-chars-long", "a@b.c", "123456")
		);
		// The address and the code cannot be shifted into each other.
		assert_ne!(h, token_hash(secret, "a@b.c1", "23456"));
	}

	#[test]
	fn passwords_verify() {
		let h = hash_password("hunter22");
		assert!(verify_password(&h, "hunter22"));
		assert!(!verify_password(&h, "hunter23"));
		assert!(!verify_password("", "x"));
		assert_eq!(bcrypt_cost(&h), Some(10));
	}
}
