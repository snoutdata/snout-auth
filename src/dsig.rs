//! Verifying an enveloped XML signature on one element, as SAML uses them.
//!
//! What is verified is exactly the element handed in: its signature must be one of its own
//! children, must carry a single reference, and that reference must name the element's own `ID`.
//! The caller then reads that same element, so the classic wrapping attacks (a signed element
//! moved elsewhere, a second element with the same ID) have nothing to work with: whatever was
//! not signed is never what is read.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use roxmltree::{Document, Node};
use sha2::Digest as _;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::xml::{self, C14n, NS_DS};

const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// The element carries no signature of its own.
	NotPresent,
	/// It carries one and it does not verify; the reason is for the log.
	Invalid(String),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::NotPresent => f.write_str("signature element not present"),
			Error::Invalid(s) => f.write_str(s),
		}
	}
}

fn bad(s: impl Into<String>) -> Error {
	Error::Invalid(s.into())
}

fn b64(s: &str) -> Result<Vec<u8>, Error> {
	let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
	STANDARD
		.decode(clean)
		.map_err(|_| bad("value is not base64"))
}

/// Verify the signature `el` carries against `trusted` (DER certificates), at `now`.
pub fn verify(
	doc: &Document,
	el: Node,
	trusted: &[Vec<u8>],
	now: OffsetDateTime,
) -> Result<(), Error> {
	let mut sigs = xml::children(el, NS_DS, "Signature");
	let sig = sigs.next().ok_or(Error::NotPresent)?;
	if sigs.next().is_some() {
		return Err(bad("more than one Signature"));
	}
	let count = |name: &str| xml::children(sig, NS_DS, name).count();
	if count("SignedInfo") != 1 || count("SignatureValue") != 1 || count("KeyInfo") > 1 {
		return Err(bad("Invalid Signature"));
	}
	let signed_info =
		xml::child(sig, NS_DS, "SignedInfo").ok_or_else(|| bad("Missing SignedInfo"))?;
	let c14n_uri = xml::child(signed_info, NS_DS, "CanonicalizationMethod")
		.and_then(|m| xml::attr(m, "Algorithm"))
		.ok_or_else(|| bad("missing CanonicalizationMethod on Signature"))?;
	let c14n_prefixes = xml::child(signed_info, NS_DS, "CanonicalizationMethod")
		.map(inclusive_prefixes)
		.unwrap_or_default();
	let si_method = C14n::from_uri(c14n_uri, c14n_prefixes).ok_or_else(|| {
		bad(format!(
			"invalid CanonicalizationMethod on Signature: {c14n_uri}"
		))
	})?;
	let sig_method = xml::child(signed_info, NS_DS, "SignatureMethod")
		.and_then(|m| xml::attr(m, "Algorithm"))
		.ok_or_else(|| bad("missing SignatureMethod"))?;

	// One reference, to this element.
	let refs: Vec<Node> = xml::children(signed_info, NS_DS, "Reference").collect();
	if refs.len() != 1 {
		return Err(bad("a SAML signature carries exactly one Reference"));
	}
	let reference = refs[0];
	let id = xml::attr(el, "ID")
		.filter(|s| !s.is_empty())
		.ok_or_else(|| bad("the signed element has no ID"))?;
	if xml::attr(reference, "URI") != Some(&format!("#{id}")) {
		return Err(bad("Missing reference"));
	}

	// The digest of the element, as its transforms say.
	let mut method = C14n::Inclusive { comments: false };
	let mut enveloped = false;
	if let Some(ts) = xml::child(reference, NS_DS, "Transforms") {
		for t in xml::children(ts, NS_DS, "Transform") {
			let alg = xml::attr(t, "Algorithm").unwrap_or("");
			if alg == ENVELOPED {
				enveloped = true;
			} else if let Some(m) = C14n::from_uri(alg, inclusive_prefixes(t)) {
				method = m;
			} else {
				return Err(bad(format!("Unknown Transform Algorithm: {alg}")));
			}
		}
	}
	if !enveloped {
		return Err(bad(
			"the signature does not use the enveloped-signature transform",
		));
	}
	let digest_alg = xml::child(reference, NS_DS, "DigestMethod")
		.and_then(|m| xml::attr(m, "Algorithm"))
		.unwrap_or("");
	let expected = b64(&xml::text(
		xml::child(reference, NS_DS, "DigestValue").ok_or_else(|| bad("missing DigestValue"))?,
	))?;
	let canonical = xml::canonicalize(doc, el, &method, Some(sig.id()));
	let actual = digest(digest_alg, canonical.as_bytes())
		.ok_or_else(|| bad(format!("Unknown digest algorithm: {digest_alg}")))?;
	if actual.len() < 20 || actual.ct_eq(&expected).unwrap_u8() != 1 {
		return Err(bad("Signature could not be verified"));
	}

	// The signature over SignedInfo, by a trusted certificate.
	let value = b64(&xml::text(
		xml::child(sig, NS_DS, "SignatureValue").ok_or_else(|| bad("missing SignatureValue"))?,
	))?;
	let signed = xml::canonicalize(doc, signed_info, &si_method, None);
	let presented = xml::child(sig, NS_DS, "KeyInfo")
		.and_then(|k| xml::child(k, NS_DS, "X509Data"))
		.and_then(|d| xml::child(d, NS_DS, "X509Certificate"))
		.map(|c| b64(&xml::text(c)))
		.transpose()?;
	let candidates: Vec<&Vec<u8>> = match &presented {
		Some(der) => {
			let t = trusted
				.iter()
				.find(|t| *t == der)
				.ok_or_else(|| bad("Could not verify certificate against trusted certs"))?;
			vec![t]
		}
		None => trusted.iter().collect(),
	};
	if candidates.is_empty() {
		return Err(bad(
			"cannot find any signing certificate in the IDP SSO descriptor",
		));
	}
	let mut last = bad("Signature could not be verified");
	for der in candidates {
		match check(der, sig_method, signed.as_bytes(), &value, now) {
			Ok(()) => return Ok(()),
			Err(e) => last = e,
		}
	}
	Err(last)
}

fn inclusive_prefixes(n: Node) -> Vec<String> {
	n.children()
		.find(|c| {
			xml::is(
				*c,
				"http://www.w3.org/2001/10/xml-exc-c14n#",
				"InclusiveNamespaces",
			)
		})
		.and_then(|c| xml::attr(c, "PrefixList"))
		.map(|s| s.split_whitespace().map(str::to_string).collect())
		.unwrap_or_default()
}

fn digest(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
	Some(match alg {
		"http://www.w3.org/2000/09/xmldsig#sha1" => sha1::Sha1::digest(data).to_vec(),
		"http://www.w3.org/2001/04/xmlenc#sha256" => sha2::Sha256::digest(data).to_vec(),
		"http://www.w3.org/2001/04/xmldsig-more#sha384" => sha2::Sha384::digest(data).to_vec(),
		"http://www.w3.org/2001/04/xmlenc#sha512" => sha2::Sha512::digest(data).to_vec(),
		_ => return None,
	})
}

/// Whether `sig` over `data` verifies with the key in certificate `der`, valid at `now`.
fn check(
	der: &[u8],
	method: &str,
	data: &[u8],
	sig: &[u8],
	now: OffsetDateTime,
) -> Result<(), Error> {
	let cert = Certificate::from_der(der).map_err(|e| bad(format!("certificate: {e}")))?;
	let v = &cert.tbs_certificate.validity;
	let t = now.unix_timestamp();
	let secs = |x: &x509_cert::time::Time| x.to_unix_duration().as_secs() as i64;
	if t < secs(&v.not_before) || t > secs(&v.not_after) {
		return Err(bad("Cert is not valid at this time"));
	}
	let spki = &cert.tbs_certificate.subject_public_key_info;
	let key = spki.subject_public_key.raw_bytes();
	let rsa = spki.algorithm.oid.to_string() == "1.2.840.113549.1.1.1";
	let curve = spki
		.algorithm
		.parameters
		.as_ref()
		.and_then(|p| p.to_der().ok())
		.unwrap_or_default();
	const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
	const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
	let alg: &dyn VerificationAlgorithm = match (method, rsa, curve.as_slice()) {
		("http://www.w3.org/2000/09/xmldsig#rsa-sha1", true, _) => {
			&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
		}
		("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", true, _) => {
			&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
		}
		("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", true, _) => {
			&signature::RSA_PKCS1_2048_8192_SHA384
		}
		("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", true, _) => {
			&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
		}
		("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", false, P256) => {
			&signature::ECDSA_P256_SHA256_FIXED
		}
		("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", false, P384) => {
			&signature::ECDSA_P384_SHA384_FIXED
		}
		_ => return Err(bad(format!("Unknown signature method: {method}"))),
	};
	UnparsedPublicKey::new(alg, key)
		.verify(data, sig)
		.map_err(|_| bad("crypto/rsa: verification error"))
}
