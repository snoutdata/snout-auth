//! SAML 2.0, the service-provider side: our key and certificate, our metadata, the
//! authentication request a sign-in starts with, an identity provider's metadata, and the checks
//! a response must pass before anything in it is believed.
//!
//! The certificate is the one the reference server derives from the same key (the same fields,
//! the same encoding, a deterministic signature), so an identity provider that was given our
//! metadata before a switch keeps trusting it after.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use roxmltree::Node;
use time::{Duration, OffsetDateTime};

use crate::dsig;
use crate::xml::{self, NS_DS, NS_MD, NS_SAML, NS_SAMLP, NS_XENC};

pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
pub const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
pub const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// How we sign an authentication request (the reference server uses RSA-SHA1).
pub const SIG_ALG: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// How old a response or assertion may be, and how much clock difference is forgiven.
const MAX_ISSUE_DELAY: Duration = Duration::seconds(90);
const MAX_CLOCK_SKEW: Duration = Duration::seconds(180);

/// `t + d`, pinned to the representable range: every instant here comes from a document an
/// anonymous caller wrote, and an overflow must refuse it, not panic.
fn shift(t: OffsetDateTime, d: Duration) -> OffsetDateTime {
	t.checked_add(d).unwrap_or(if d.is_negative() {
		time::PrimitiveDateTime::MIN.assume_utc()
	} else {
		time::PrimitiveDateTime::MAX.assume_utc()
	})
}

// ------------------------------------------------------------------------------------------
// Our side.

/// The service provider: our key, our certificate(s), and where our endpoints are.
pub struct ServiceProvider {
	key: RsaKeyPair,
	pub cert: Vec<u8>,
	pub next_cert: Option<Vec<u8>>,
	/// Our entity ID, which is also where our metadata is.
	pub entity_id: String,
	pub acs: String,
	pub slo: String,
}

impl ServiceProvider {
	/// From the configured key (base64 of a PKCS#1 DER RSA key), the SAML external URL (else the
	/// API's) for our endpoints, and the API external URL whose host names the certificate.
	pub fn new(
		key_b64: &str,
		next_b64: Option<&str>,
		saml_url: &str,
		api_url: &str,
	) -> Result<ServiceProvider, String> {
		let key = load_key(key_b64, "")?;
		let host = host_of(api_url);
		let cert = certificate(&key, &host)?;
		let next_cert = match next_b64.filter(|s| !s.is_empty()) {
			Some(n) => Some(certificate(&load_key(n, "next ")?, &host)?),
			None => None,
		};
		let mut base = saml_url.split(['?', '#']).next().unwrap_or("").to_string();
		if !base.ends_with('/') {
			base.push('/');
		}
		base.push_str("sso/");
		Ok(ServiceProvider {
			key,
			cert,
			next_cert,
			entity_id: format!("{base}saml/metadata"),
			acs: format!("{base}saml/acs"),
			slo: format!("{base}saml/slo"),
		})
	}

	/// Our metadata document. `valid_until` is the entity's (five years for a download).
	pub fn metadata(&self, now: OffsetDateTime, download: bool) -> String {
		let role_until = now + Duration::hours(48);
		let entity_until = if download {
			OffsetDateTime::now_utc() + Duration::days(365 * 5 + leap_days(now))
		} else {
			role_until
		};
		let cache = if self.next_cert.is_some() {
			" cacheDuration=\"PT1H\""
		} else {
			""
		};
		let kd = |cert: &[u8]| {
			format!(
				"<KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"{NS_DS}\"><X509Data xmlns=\"{NS_DS}\"><X509Certificate xmlns=\"{NS_DS}\">{}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>",
				STANDARD.encode(cert)
			)
		};
		let mut keys = kd(&self.cert);
		if let Some(n) = &self.next_cert {
			keys.push_str(&kd(n));
		}
		let e = xml::escape;
		format!(
			"<EntityDescriptor xmlns=\"{NS_MD}\" validUntil=\"{}\"{cache} entityID=\"{}\"><SPSSODescriptor xmlns=\"{NS_MD}\" validUntil=\"{}\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAssertionsSigned=\"true\">{keys}<SingleLogoutService Binding=\"{POST}\" Location=\"{}\" ResponseLocation=\"{}\"></SingleLogoutService><NameIDFormat>{EMAIL}</NameIDFormat><NameIDFormat>{PERSISTENT}</NameIDFormat><AssertionConsumerService Binding=\"{POST}\" Location=\"{}\" index=\"1\"></AssertionConsumerService><AssertionConsumerService Binding=\"{ARTIFACT}\" Location=\"{}\" index=\"2\"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>",
			millis(entity_until),
			e(&self.entity_id),
			nanos(role_until),
			e(&self.slo),
			e(&self.slo),
			e(&self.acs),
			e(&self.acs),
		)
	}

	/// An authentication request to `destination` (the IdP's HTTP-Redirect endpoint), asking for
	/// `name_id_format`: its ID, and the URL to send the browser to with `relay_state`.
	pub fn authn_request(
		&self,
		destination: &str,
		name_id_format: &str,
		relay_state: &str,
		now: OffsetDateTime,
	) -> Result<(String, String), String> {
		let id = format!("id-{}", hex::encode(rand::random::<[u8; 20]>()));
		let e = xml::escape_min;
		let request = format!(
			"<samlp:AuthnRequest xmlns:saml=\"{NS_SAML}\" xmlns:samlp=\"{NS_SAMLP}\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{}\" AssertionConsumerServiceURL=\"{}\" ProtocolBinding=\"{POST}\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">{}</saml:Issuer><samlp:NameIDPolicy Format=\"{}\" AllowCreate=\"true\"/></samlp:AuthnRequest>",
			instant(now),
			e(destination),
			e(&self.acs),
			e(&self.entity_id),
			e(name_id_format),
		);
		let deflated = miniz_oxide::deflate::compress_to_vec(request.as_bytes(), 9);
		let esc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
		let (base, fragment) = destination
			.split_once('#')
			.map(|(b, f)| (b, Some(f)))
			.unwrap_or((destination, None));
		let (base, existing) = base.split_once('?').unwrap_or((base, ""));
		let mut query = String::from(existing);
		if !query.is_empty() {
			query.push('&');
		}
		query.push_str("SAMLRequest=");
		query.push_str(&esc(&STANDARD.encode(deflated)));
		if !relay_state.is_empty() {
			query.push_str("&RelayState=");
			query.push_str(relay_state);
		}
		query.push_str("&SigAlg=");
		query.push_str(&esc(SIG_ALG));
		let mut sig = vec![0u8; self.key.public().modulus_len()];
		self.key
			.sign(
				&RSA_PKCS1_SHA256,
				&SystemRandom::new(),
				query.as_bytes(),
				&mut sig,
			)
			.map_err(|_| "signing the request failed".to_string())?;
		query.push_str("&Signature=");
		query.push_str(&esc(&STANDARD.encode(sig)));
		let mut url = format!("{base}?{query}");
		if let Some(f) = fragment {
			url.push('#');
			url.push_str(f);
		}
		Ok((id, url))
	}
}

fn load_key(b64: &str, which: &str) -> Result<RsaKeyPair, String> {
	let der = STANDARD
		.decode(b64.trim())
		.map_err(|_| format!("SAML {which}private key not in standard Base64 format"))?;
	let key = RsaKeyPair::from_der(&der).map_err(|e| {
		if e.to_string() == "TooSmall" {
			format!("SAML {which}private key must be at least RSA 2048")
		} else {
			format!("SAML {which}private key not in PKCS#1 format")
		}
	})?;
	let parts = ring::rsa::PublicKeyComponents::<Vec<u8>>::from(key.public());
	let e = parts
		.e
		.iter()
		.skip_while(|b| **b == 0)
		.copied()
		.collect::<Vec<u8>>();
	if e != [0x01, 0x00, 0x01] {
		return Err(format!(
			"SAML {which}private key should use the 65537 (0x10001) RSA public exponent"
		));
	}
	Ok(key)
}

/// The host part of a URL as written (no port, no user info), which names our certificate.
fn host_of(url: &str) -> String {
	let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
	let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
	let hostport = authority
		.rsplit_once('@')
		.map(|(_, h)| h)
		.unwrap_or(authority);
	// A port is split off only where one is actually written; `[::1]` alone keeps its brackets.
	if let Some(inner) = hostport.strip_prefix('[') {
		if let Some((h, port)) = inner.split_once("]:")
			&& !port.is_empty()
		{
			return h.to_string();
		}
		return hostport.to_string();
	}
	match hostport.rsplit_once(':') {
		Some((h, _)) if !h.contains(':') => h.to_string(),
		_ => hostport.to_string(),
	}
}

// DER, just enough to write our certificate.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
	let mut out = vec![tag];
	let n = content.len();
	if n < 0x80 {
		out.push(n as u8);
	} else {
		let bytes: Vec<u8> = n
			.to_be_bytes()
			.iter()
			.skip_while(|b| **b == 0)
			.copied()
			.collect();
		out.push(0x80 | bytes.len() as u8);
		out.extend(bytes);
	}
	out.extend_from_slice(content);
	out
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
	tlv(0x30, &parts.concat())
}

/// PrintableString when every character allows it, else UTF8String.
fn directory_string(s: &str) -> Vec<u8> {
	let printable = s
		.bytes()
		.all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
	tlv(if printable { 0x13 } else { 0x0c }, s.as_bytes())
}

/// Our self-signed certificate: serial 0, valid from the epoch for two hundred years, for
/// digital signatures, naming `_samlsp.<host>`.
fn certificate(key: &RsaKeyPair, host: &str) -> Result<Vec<u8>, String> {
	const SHA256_RSA: &[u8] = &[
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
	];
	const RSA: &[u8] = &[
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
	];
	let cn = format!("SAML 2.0 Certificate for {host}");
	let name = seq(&[&tlv(
		0x31,
		&seq(&[&[0x06, 0x03, 0x55, 0x04, 0x03], &directory_string(&cn)]),
	)]);
	let validity = seq(&[&tlv(0x17, b"700101000000Z"), &tlv(0x18, b"21700101000000Z")]);
	let mut bits = vec![0u8];
	bits.extend_from_slice(key.public().as_ref());
	let spki = seq(&[RSA, &tlv(0x03, &bits)]);
	let key_usage = seq(&[
		&[0x06, 0x03, 0x55, 0x1d, 0x0f],
		&[0x01, 0x01, 0xff],
		&tlv(0x04, &[0x03, 0x02, 0x07, 0x80]),
	]);
	let san = seq(&[
		&[0x06, 0x03, 0x55, 0x1d, 0x11],
		&tlv(
			0x04,
			&seq(&[&tlv(0x82, format!("_samlsp.{host}").as_bytes())]),
		),
	]);
	let extensions = tlv(0xa3, &seq(&[&key_usage, &san]));
	let tbs = seq(&[
		&[0xa0, 0x03, 0x02, 0x01, 0x02],
		&[0x02, 0x01, 0x00],
		SHA256_RSA,
		&name,
		&validity,
		&name,
		&spki,
		&extensions,
	]);
	let mut sig = vec![0u8; key.public().modulus_len()];
	key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), &tbs, &mut sig)
		.map_err(|_| "signing the SAML certificate failed".to_string())?;
	let mut sig_bits = vec![0u8];
	sig_bits.extend(sig);
	Ok(seq(&[&tbs, SHA256_RSA, &tlv(0x03, &sig_bits)]))
}

fn leap_days(now: OffsetDateTime) -> i64 {
	// Five calendar years from now, as the reference server's AddDate(5, 0, 0) counts them.
	let later = now
		.replace_year(now.year() + 5)
		.unwrap_or(now + Duration::days(365 * 5));
	(later - now).whole_days() - 365 * 5
}

// ------------------------------------------------------------------------------------------
// Times, as SAML writes them.

/// Milliseconds, rounded, trailing zeros dropped (`2006-01-02T15:04:05.999Z`).
fn millis(t: OffsetDateTime) -> String {
	let rounded = t + Duration::nanoseconds(500_000);
	let t = rounded
		.replace_nanosecond(rounded.nanosecond() / 1_000_000 * 1_000_000)
		.unwrap_or(rounded);
	frac(t, 3)
}
/// Milliseconds, truncated, as a request's IssueInstant is written.
fn instant(t: OffsetDateTime) -> String {
	frac(t, 3)
}
/// Nanoseconds, trailing zeros dropped.
fn nanos(t: OffsetDateTime) -> String {
	frac(t, 9)
}
fn frac(t: OffsetDateTime, digits: usize) -> String {
	let t = t.to_offset(time::UtcOffset::UTC);
	let base = format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
		t.year(),
		t.month() as u8,
		t.day(),
		t.hour(),
		t.minute(),
		t.second()
	);
	let n = format!("{:09}", t.nanosecond());
	let f = n[..digits].trim_end_matches('0');
	if f.is_empty() {
		format!("{base}Z")
	} else {
		format!("{base}.{f}Z")
	}
}

/// A SAML time: RFC 3339 with any fraction, or the same with no zone (taken as UTC).
pub fn parse_time(s: &str) -> Option<OffsetDateTime> {
	use time::format_description::well_known::Rfc3339;
	if let Ok(t) = OffsetDateTime::parse(s, &Rfc3339) {
		return Some(t);
	}
	OffsetDateTime::parse(&format!("{s}Z"), &Rfc3339).ok()
}

/// An XML Schema duration (`PnYnMnDTnHnMnS`, any part optional, seconds may be fractional, a
/// leading minus allowed). Years are 365 days and months 30, as SAML metadata means them.
pub fn parse_duration(s: &str) -> Option<Duration> {
	let (neg, rest) = match s.strip_prefix('-') {
		Some(r) => (true, r),
		None => (false, s),
	};
	let rest = rest.strip_prefix('P')?;
	let (date, time_part) = match rest.split_once('T') {
		Some((d, t)) => (d, Some(t)),
		None => (rest, None),
	};
	let mut total = 0f64;
	let mut any = false;
	let mut take = |part: &str, units: &[(char, f64)], allow_fraction: bool| -> Option<()> {
		let mut num = String::new();
		let mut last = 0usize;
		for c in part.chars() {
			if c.is_ascii_digit() || (c == '.' && allow_fraction) {
				num.push(c);
				continue;
			}
			let i = units.iter().position(|(u, _)| *u == c)?;
			if i < last || num.is_empty() || (num.contains('.') && c != 'S') {
				return None;
			}
			last = i + 1;
			total += num.parse::<f64>().ok()? * units[i].1;
			num.clear();
			any = true;
		}
		if num.is_empty() { Some(()) } else { None }
	};
	take(
		date,
		&[
			('Y', 365.0 * 86400.0),
			('M', 30.0 * 86400.0),
			('D', 86400.0),
		],
		false,
	)?;
	if let Some(t) = time_part {
		if t.is_empty() {
			return None;
		}
		take(t, &[('H', 3600.0), ('M', 60.0), ('S', 1.0)], true)?;
	}
	if !any {
		return None;
	}
	let d = Duration::checked_seconds_f64(total)?;
	Some(if neg { -d } else { d })
}

// ------------------------------------------------------------------------------------------
// An identity provider's metadata.

pub struct IdpMetadata {
	pub entity_id: String,
	pub valid_until: Option<OffsetDateTime>,
	pub cache_duration: Option<Duration>,
	/// How many IDPSSODescriptors the entity has (exactly one is accepted).
	pub idp_descriptors: usize,
	/// The HTTP-Redirect single sign-on endpoint.
	pub sso_redirect: Option<String>,
	/// Signing certificates, as written (base64, perhaps wrapped).
	pub certs: Vec<String>,
}

impl IdpMetadata {
	/// The signing certificates, decoded.
	pub fn signing_certs(&self) -> Result<Vec<Vec<u8>>, String> {
		if self.certs.is_empty() {
			return Err("cannot find any signing certificate in the IDP SSO descriptor".into());
		}
		self.certs
			.iter()
			.map(|c| {
				let clean: String = c.chars().filter(|c| !c.is_whitespace()).collect();
				let der = STANDARD
					.decode(clean)
					.map_err(|e| format!("cannot parse certificate: {e}"))?;
				use x509_cert::der::Decode;
				x509_cert::Certificate::from_der(&der)
					.map_err(|e| format!("cannot parse certificate: {e}"))?;
				Ok(der)
			})
			.collect()
	}

	/// Whether metadata fetched from a URL is due to be fetched again.
	pub fn is_stale(&self, updated_at: OffsetDateTime, now: OffsetDateTime) -> bool {
		let expired = self.valid_until.is_some_and(|v| now > v);
		let cache_over = self
			.cache_duration
			.is_some_and(|d| d != Duration::ZERO && now > shift(updated_at, d));
		let force = self.valid_until.is_none()
			&& self.cache_duration.is_none_or(|d| d == Duration::ZERO)
			&& now > shift(updated_at, Duration::hours(24));
		expired || cache_over || force
	}
}

/// Parse an identity provider's metadata: an EntityDescriptor, or an EntitiesDescriptor whose
/// first entity with an IDPSSODescriptor is taken.
pub fn parse_metadata(text: &str) -> Result<IdpMetadata, String> {
	let doc = xml::parse(text)?;
	let root = doc.root_element();
	let entity = if xml::is(root, NS_MD, "EntityDescriptor") {
		root
	} else if xml::is(root, NS_MD, "EntitiesDescriptor") {
		xml::children(root, NS_MD, "EntityDescriptor")
			.find(|e| xml::child(*e, NS_MD, "IDPSSODescriptor").is_some())
			.ok_or("no entity found with IDPSSODescriptor")?
	} else {
		return Err(format!(
			"expected element type <EntityDescriptor> but have <{}>",
			root.tag_name().name()
		));
	};
	let valid_until = match xml::attr(entity, "validUntil").filter(|s| !s.is_empty()) {
		Some(s) => Some(parse_time(s).ok_or_else(|| format!("invalid validUntil ({s})"))?),
		None => None,
	};
	let cache_duration = match xml::attr(entity, "cacheDuration").filter(|s| !s.is_empty()) {
		Some(s) => Some(parse_duration(s).ok_or_else(|| format!("invalid duration ({s})"))?),
		None => None,
	};
	let descriptors: Vec<Node> = xml::children(entity, NS_MD, "IDPSSODescriptor").collect();
	let mut certs = vec![];
	let mut sso_redirect = None;
	for d in &descriptors {
		for kd in xml::children(*d, NS_MD, "KeyDescriptor") {
			if !matches!(xml::attr(kd, "use").unwrap_or(""), "" | "signing") {
				continue;
			}
			let data =
				xml::child(kd, NS_DS, "KeyInfo").and_then(|k| xml::child(k, NS_DS, "X509Data"));
			for c in data
				.into_iter()
				.flat_map(|d| xml::children(d, NS_DS, "X509Certificate"))
			{
				certs.push(xml::text(c));
			}
		}
		for s in xml::children(*d, NS_MD, "SingleSignOnService") {
			let binding = xml::attr(s, "Binding").unwrap_or("");
			let location = xml::attr(s, "Location").unwrap_or("");
			if matches!(binding, POST | REDIRECT | ARTIFACT) {
				let ok = url::Url::parse(location)
					.map(|u| matches!(u.scheme(), "http" | "https"))
					.unwrap_or(false);
				if !ok {
					return Err(format!("invalid url {location:?} for binding {binding:?}"));
				}
			}
			if binding == REDIRECT && sso_redirect.is_none() {
				sso_redirect = Some(location.to_string());
			}
		}
	}
	Ok(IdpMetadata {
		entity_id: xml::attr(entity, "entityID").unwrap_or("").to_string(),
		valid_until,
		cache_duration,
		idp_descriptors: descriptors.len(),
		sso_redirect,
		certs,
	})
}

// ------------------------------------------------------------------------------------------
// A response.

/// The issuer a response names, read before anything is checked (to find which IdP sent it).
/// `None` when it is not a SAML response at all.
pub fn peek_issuer(text: &str) -> Option<String> {
	let doc = xml::parse(text).ok()?;
	let root = doc.root_element();
	if !xml::is(root, NS_SAMLP, "Response") {
		return None;
	}
	Some(
		xml::child(root, NS_SAML, "Issuer")
			.map(xml::text)
			.unwrap_or_default(),
	)
}

pub struct Attribute {
	pub name: String,
	pub friendly_name: String,
	pub values: Vec<String>,
}

/// What a verified assertion says.
pub struct Assertion {
	pub name_id: Option<(String, String)>,
	pub attributes: Vec<Attribute>,
	pub session_not_on_or_after: Option<OffsetDateTime>,
}

impl Assertion {
	/// The values of every attribute called `name` (or with that friendly name), any case.
	pub fn attribute(&self, name: &str) -> Vec<&str> {
		self.attributes
			.iter()
			.filter(|a| {
				a.name.eq_ignore_ascii_case(name) || a.friendly_name.eq_ignore_ascii_case(name)
			})
			.flat_map(|a| a.values.iter().map(String::as_str))
			.collect()
	}

	/// The user's stable identifier: the `subject-id` attribute, else a NameID that is not transient.
	pub fn user_id(&self) -> String {
		if let Some(v) = self
			.attribute("urn:oasis:names:tc:SAML:attribute:subject-id")
			.first()
		{
			return v.to_string();
		}
		match &self.name_id {
			Some((format, value)) if !value.is_empty() => {
				if format == EMAIL {
					value.trim().to_lowercase()
				} else if format == TRANSIENT {
					String::new()
				} else {
					value.clone()
				}
			}
			_ => String::new(),
		}
	}

	pub fn email(&self) -> String {
		for name in [
			"urn:oid:0.9.2342.19200300.100.1.3",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"http://schemas.xmlsoap.org/claims/EmailAddress",
			"mail",
			"Mail",
			"email",
		] {
			if let Some(v) = self.attribute(name).into_iter().find(|v| !v.is_empty()) {
				return v.to_string();
			}
		}
		match &self.name_id {
			Some((format, value)) if format == EMAIL => value.clone(),
			_ => String::new(),
		}
	}
}

/// Whether an address an identity provider asserted is in one of the domains registered for that
/// provider (`sso_domains`), and so is one it may speak for. A signed assertion proves which
/// provider sent it, not that the provider owns the address in it: without this, any provider
/// registered for any domain could sign a user in under somebody else's address. The domain is
/// compared without ASCII case and must match a registered one exactly (a subdomain is registered
/// on its own). An address with no `@`, more than one, or an empty side is refused, as is every
/// address when the provider has no domains at all.
pub fn email_in_domains<'a>(email: &str, domains: impl IntoIterator<Item = &'a str>) -> bool {
	let mut parts = email.trim().split('@');
	let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
		return false;
	};
	if local.is_empty() || domain.is_empty() {
		return false;
	}
	domains
		.into_iter()
		.any(|d| !d.trim().is_empty() && d.trim().eq_ignore_ascii_case(domain))
}

/// What a response is checked against.
pub struct Expect<'a> {
	pub idp_entity: &'a str,
	pub certs: &'a [Vec<u8>],
	pub acs: &'a str,
	pub audience: &'a str,
	/// The requests this may answer; ignored for an IdP-initiated sign-in.
	pub request_ids: &'a [String],
	pub idp_initiated: bool,
	pub now: OffsetDateTime,
}

/// Check a response and return its first valid assertion. The error is for the log.
pub fn validate(text: &str, x: &Expect) -> Result<Assertion, String> {
	let doc = xml::parse(text).map_err(|e| format!("invalid xml: {e}"))?;
	let resp = doc.root_element();
	if !xml::is(resp, NS_SAMLP, "Response") {
		return Err("not a SAML Response".into());
	}
	let resp_sig = dsig::verify(&doc, resp, x.certs, x.now);
	let signed = !matches!(resp_sig, Err(dsig::Error::NotPresent));
	let destination = xml::attr(resp, "Destination").unwrap_or("");
	if (signed || !destination.is_empty()) && destination != x.acs {
		return Err(format!(
			"`Destination` does not match AcsURL (expected {:?}, actual {destination:?})",
			x.acs
		));
	}
	if !x.idp_initiated {
		let irt = xml::attr(resp, "InResponseTo").unwrap_or("");
		if !x.request_ids.iter().any(|r| r == irt) {
			return Err(format!(
				"`InResponseTo` does not match any of the possible request IDs (expected {:?})",
				x.request_ids
			));
		}
	}
	let issued = xml::attr(resp, "IssueInstant")
		.and_then(parse_time)
		.ok_or("response IssueInstant missing")?;
	if shift(issued, MAX_ISSUE_DELAY) < x.now {
		return Err(format!(
			"response IssueInstant expired at {}",
			shift(issued, MAX_ISSUE_DELAY)
		));
	}
	if let Some(i) = xml::child(resp, NS_SAML, "Issuer")
		&& xml::text(i) != x.idp_entity
	{
		return Err(format!(
			"response Issuer does not match the IDP metadata (expected {:?})",
			x.idp_entity
		));
	}
	let status = xml::child(resp, NS_SAMLP, "Status")
		.and_then(|s| xml::child(s, NS_SAMLP, "StatusCode"))
		.and_then(|c| xml::attr(c, "Value"))
		.unwrap_or("");
	if status != SUCCESS {
		return Err(status.to_string());
	}
	let need_assertion_signature = match resp_sig {
		Ok(()) => false,
		Err(dsig::Error::NotPresent) => true,
		Err(e) => return Err(format!("cannot validate signature on Response: {e}")),
	};

	let mut first_error = None;
	for c in resp.children().filter(|c| c.is_element()) {
		let r = if xml::is(c, NS_SAML, "EncryptedAssertion") {
			let _ = NS_XENC;
			Err("encrypted assertions are not accepted".to_string())
		} else if xml::is(c, NS_SAML, "Assertion") {
			assertion(&doc, c, x, need_assertion_signature)
		} else {
			continue;
		};
		match r {
			Ok(a) => return Ok(a),
			Err(e) => {
				first_error.get_or_insert(e);
			}
		}
	}
	Err(first_error.unwrap_or_else(|| "expected at least one valid Assertion, none found".into()))
}

fn assertion(
	doc: &roxmltree::Document,
	a: Node,
	x: &Expect,
	need_signature: bool,
) -> Result<Assertion, String> {
	if need_signature {
		dsig::verify(doc, a, x.certs, x.now)
			.map_err(|e| format!("cannot validate signature on Assertion: {e}"))?;
	}
	let issued = xml::attr(a, "IssueInstant")
		.and_then(parse_time)
		.ok_or("assertion IssueInstant missing")?;
	if shift(issued, MAX_ISSUE_DELAY) < x.now {
		return Err(format!("expired on {}", shift(issued, MAX_ISSUE_DELAY)));
	}
	if xml::child(a, NS_SAML, "Issuer")
		.map(xml::text)
		.unwrap_or_default()
		!= x.idp_entity
	{
		return Err(format!("issuer is not {:?}", x.idp_entity));
	}
	let subject = xml::child(a, NS_SAML, "Subject");
	for sc in subject
		.into_iter()
		.flat_map(|s| xml::children(s, NS_SAML, "SubjectConfirmation"))
	{
		let data = xml::child(sc, NS_SAML, "SubjectConfirmationData");
		let get = |k: &str| data.and_then(|d| xml::attr(d, k)).unwrap_or("");
		if !x.idp_initiated && !x.request_ids.iter().any(|r| r == get("InResponseTo")) {
			return Err(format!(
				"assertion SubjectConfirmation one of the possible request IDs ({:?})",
				x.request_ids
			));
		}
		if get("Recipient") != x.acs {
			return Err(format!(
				"assertion SubjectConfirmation Recipient is not {}",
				x.acs
			));
		}
		match parse_time(get("NotOnOrAfter")) {
			Some(t) if shift(t, MAX_CLOCK_SKEW) >= x.now => {}
			_ => return Err("assertion SubjectConfirmationData is expired".into()),
		}
	}
	let conditions = xml::child(a, NS_SAML, "Conditions").ok_or("assertion has no Conditions")?;
	if let Some(nb) = xml::attr(conditions, "NotBefore").and_then(parse_time)
		&& shift(nb, -MAX_CLOCK_SKEW) > x.now
	{
		return Err("assertion Conditions is not yet valid".into());
	}
	match xml::attr(conditions, "NotOnOrAfter").and_then(parse_time) {
		Some(t) if shift(t, MAX_CLOCK_SKEW) >= x.now => {}
		_ => return Err("assertion Conditions is expired".into()),
	}
	let restrictions: Vec<Node> =
		xml::children(conditions, NS_SAML, "AudienceRestriction").collect();
	if !restrictions.is_empty()
		&& !restrictions
			.iter()
			.any(|r| xml::children(*r, NS_SAML, "Audience").any(|au| xml::text(au) == x.audience))
	{
		return Err(format!(
			"assertion Conditions AudienceRestriction does not contain {:?}",
			x.audience
		));
	}

	let name_id = subject
		.and_then(|s| xml::child(s, NS_SAML, "NameID"))
		.map(|n| {
			(
				xml::attr(n, "Format").unwrap_or("").to_string(),
				xml::text(n),
			)
		});
	let mut attributes = vec![];
	for st in xml::children(a, NS_SAML, "AttributeStatement") {
		for at in xml::children(st, NS_SAML, "Attribute") {
			attributes.push(Attribute {
				name: xml::attr(at, "Name").unwrap_or("").to_string(),
				friendly_name: xml::attr(at, "FriendlyName").unwrap_or("").to_string(),
				values: xml::children(at, NS_SAML, "AttributeValue")
					.map(xml::text)
					.collect(),
			});
		}
	}
	let session_not_on_or_after = xml::children(a, NS_SAML, "AuthnStatement")
		.find_map(|s| xml::attr(s, "SessionNotOnOrAfter").and_then(parse_time));
	Ok(Assertion {
		name_id,
		attributes,
		session_not_on_or_after,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn durations_in_full() {
		assert_eq!(parse_duration("PT24H"), Some(Duration::hours(24)));
		assert_eq!(
			parse_duration("P0555555555555555555555555555555555555D"),
			None
		);
		assert_eq!(parse_duration("PT1e400S"), None);
		assert_eq!(parse_duration("P1D"), Some(Duration::days(1)));
		assert_eq!(
			parse_duration("P1Y2M3DT4H5M6.5S"),
			Some(Duration::seconds_f64(
				365.0 * 86400.0 + 60.0 * 86400.0 + 3.0 * 86400.0 + 4.0 * 3600.0 + 5.0 * 60.0 + 6.5
			))
		);
		assert_eq!(parse_duration("-PT1M"), Some(Duration::minutes(-1)));
		assert_eq!(parse_duration("PT0.5S"), Some(Duration::milliseconds(500)));
		assert_eq!(parse_duration("P"), None);
		assert_eq!(parse_duration("PT"), None);
		assert_eq!(parse_duration("P1H"), None);
		assert_eq!(parse_duration("PT1M1H"), None);
		assert_eq!(parse_duration("1D"), None);
	}

	#[test]
	fn times() {
		let t = parse_time("2026-09-29T18:43:20.938050131Z").unwrap();
		assert_eq!(nanos(t), "2026-09-29T18:43:20.938050131Z");
		assert_eq!(millis(t), "2026-09-29T18:43:20.938Z");
		assert_eq!(
			millis(parse_time("2026-09-29T18:43:20.9995Z").unwrap()),
			"2026-09-29T18:43:21Z"
		);
		assert_eq!(
			instant(parse_time("2026-09-29T18:43:20.9995Z").unwrap()),
			"2026-09-29T18:43:20.999Z"
		);
		assert!(parse_time("2026-09-29T18:43:20").is_some());
	}

	#[test]
	fn instants_at_the_edge_of_time_are_refused_not_a_panic() {
		let now = OffsetDateTime::now_utc();
		let x = Expect {
			idp_entity: "i",
			certs: &[],
			acs: "a",
			audience: "e",
			request_ids: &[],
			idp_initiated: true,
			now,
		};
		for t in ["9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z"] {
			let r = format!(
				"<samlp:Response xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" IssueInstant=\"{t}\"><samlp:Status><samlp:StatusCode Value=\"{SUCCESS}\"/></samlp:Status><saml:Assertion IssueInstant=\"{t}\"><saml:Issuer>i</saml:Issuer><saml:Conditions NotBefore=\"{t}\" NotOnOrAfter=\"{t}\"/></saml:Assertion></samlp:Response>"
			);
			assert!(validate(&r, &x).is_err());
		}
		let m = IdpMetadata {
			entity_id: "i".into(),
			valid_until: None,
			cache_duration: Some(Duration::MAX),
			idp_descriptors: 1,
			sso_redirect: None,
			certs: vec![],
		};
		assert!(!m.is_stale(now, now));
	}

	#[test]
	fn an_asserted_address_must_be_in_the_providers_domains() {
		let domains = ["corp.test", "New.Test"];
		let ok = |e: &str| email_in_domains(e, domains.iter().copied());
		assert!(ok("sam@corp.test"));
		assert!(ok("Terry@Corp.Test"));
		assert!(ok("  rita@new.test "));
		assert!(ok("rita@NEW.TEST"));
		// Another domain, a subdomain, a lookalike: refused.
		assert!(!ok("victim@gmail.com"));
		assert!(!ok("sam@eu.corp.test"));
		assert!(!ok("sam@corp.test.evil.test"));
		assert!(!ok("sam@evilcorp.test"));
		// Not one address: refused rather than guessed at.
		assert!(!ok("victim@gmail.com@corp.test"));
		assert!(!ok("\"a@b\"@corp.test"));
		assert!(!ok("corp.test"));
		assert!(!ok("@corp.test"));
		assert!(!ok("sam@"));
		assert!(!ok(""));
		// A provider with no domains speaks for no address.
		assert!(!email_in_domains("sam@corp.test", []));
		assert!(!email_in_domains("sam@corp.test", [""]));
	}

	#[test]
	fn hosts() {
		assert_eq!(host_of("http://api.test/auth/v1"), "api.test");
		assert_eq!(host_of("https://u:p@api.test:8443/x"), "api.test");
		assert_eq!(host_of("http://[::1]:9999/"), "::1");
		assert_eq!(host_of("http://[::1]/"), "[::1]");
	}
}
