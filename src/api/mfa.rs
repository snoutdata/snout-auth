//! `/factors`: a second factor (TOTP), enrolled, challenged, verified and removed.
//!
//! A verified factor makes the user's highest level `aal2`; verifying a challenge raises the
//! session to it and ends the user's other `aal1` sessions.

use axum::extract::Path;
use axum::http::HeaderMap;
use axum::response::Response;
use data_encoding::BASE32_NOPAD;
use deadpool_postgres::GenericClient;
use hmac::{Hmac, Mac};
use serde_json::{Map, json};
use sha1::Sha1;
use time::OffsetDateTime;
use uuid::Uuid;

use super::token::{audit, set, with_headers};
use super::{App, Caller, Req, Shared};
use crate::error::{ApiError, ApiResult, db};
use crate::models::{factor, session, token as tok, user};

/// How long a factor's last verification counts as fresh enough to add or remove a factor.
const FRESH: std::time::Duration = std::time::Duration::from_secs(300);
/// How long an unverified factor with no challenge is kept.
const UNVERIFIED_FACTOR_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

fn totp_code(secret: &[u8], counter: u64) -> String {
	let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac key");
	mac.update(&counter.to_be_bytes());
	let h = mac.finalize().into_bytes();
	let offset = (h[19] & 0x0f) as usize;
	let bin = (u32::from(h[offset] & 0x7f) << 24)
		| (u32::from(h[offset + 1]) << 16)
		| (u32::from(h[offset + 2]) << 8)
		| u32::from(h[offset + 3]);
	format!("{:06}", bin % 1_000_000)
}

/// A six-digit code for this secret, in the current 30-second window or the one either side.
pub fn totp_valid(secret_b32: &str, code: &str, at: OffsetDateTime) -> bool {
	let Ok(secret) = BASE32_NOPAD.decode(
		secret_b32
			.trim_end_matches('=')
			.to_ascii_uppercase()
			.as_bytes(),
	) else {
		return false;
	};
	if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
		return false;
	}
	let step = (at.unix_timestamp() / 30) as u64;
	[step.saturating_sub(1), step, step + 1]
		.iter()
		.any(|s| crate::crypto::constant_eq(totp_code(&secret, *s).as_bytes(), code.as_bytes()))
}

fn qr_svg(uri: &str) -> String {
	match qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::H) {
		Ok(code) => code
			.render::<qrcode::render::svg::Color<'_>>()
			.module_dimensions(3, 3)
			.quiet_zone(false)
			.build(),
		Err(_) => String::new(),
	}
}

fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
	let path_enc = |s: &str| {
		percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
	};
	let query = url::form_urlencoded::Serializer::new(String::new())
		.append_pair("algorithm", "SHA1")
		.append_pair("digits", "6")
		.append_pair("issuer", issuer)
		.append_pair("period", "30")
		.append_pair("secret", secret)
		.finish();
	format!(
		"otpauth://totp/{}:{}?{query}",
		path_enc(issuer),
		path_enc(account)
	)
}

/// Whether this session proved a factor within the last few minutes.
fn recently_verified(s: &session::Session) -> bool {
	let now = OffsetDateTime::now_utc();
	s.amr.iter().any(|c| {
		matches!(c.method.as_str(), "totp" | "mfa/phone" | "mfa/webauthn")
			&& now - c.updated_at < FRESH
	})
}

async fn factor_of(app: &App, caller: &Caller, id: &str) -> ApiResult<factor::Factor> {
	let fid = Uuid::parse_str(id)
		.map_err(|_| ApiError::not_found("validation_failed", "factor_id must be an UUID"))?;
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	match factor::by_id(&conn, fid)
		.await
		.map_err(db("Database error loading factor"))?
	{
		Some(f) if f.user_id == caller.user.id => Ok(f),
		_ => Err(ApiError::not_found(
			"mfa_factor_not_found",
			"Factor not found",
		)),
	}
}

pub async fn enroll(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let cfg = &app.config;
		let caller = super::authenticate(&app, &req).await?;
		let Some(sess) = caller.session.as_ref() else {
			return Err(ApiError::internal("A valid session and a registered user are required to enroll a factor"));
		};
		let p = req.params()?;
		let kind = p.str("factor_type")?;
		let name = p.str("friendly_name")?;
		match kind.as_str() {
			"totp" if !cfg.mfa_totp_enroll => return Err(ApiError::unprocessable("mfa_totp_enroll_not_enabled", "MFA enroll is disabled for TOTP")),
			"totp" => {}
			"phone" => return Err(ApiError::unprocessable("mfa_phone_enroll_not_enabled", "MFA enroll is disabled for Phone")),
			"webauthn" => return Err(ApiError::unprocessable("mfa_web_authn_enroll_not_enabled", "MFA enroll is disabled for WebAuthn")),
			_ => return Err(ApiError::bad_request("validation_failed", "factor_type needs to be totp, phone, or webauthn")),
		}
		let issuer = match p.str("issuer")? {
			s if !s.is_empty() => s,
			_ => url::Url::parse(&cfg.site_url).ok().and_then(|u| u.host_str().map(|h| match u.port() { Some(port) => format!("{h}:{port}"), None => h.to_string() })).ok_or_else(|| ApiError::internal("site url is improperly formatted"))?,
		};
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		conn.execute(
			&format!(
				"delete from mfa_factors where status != 'verified' and not exists (select * from mfa_challenges where mfa_factors.id = mfa_challenges.factor_id) \
				 and created_at + interval '{} seconds' < current_timestamp",
				UNVERIFIED_FACTOR_LIFETIME.as_secs()
			),
			&[],
		)
		.await
		.map_err(db("Database error"))?;
		let factors = factor::for_user(&conn, caller.user.id).await.map_err(db("Database error"))?;
		let mut verified = 0;
		for f in &factors {
			if f.friendly_name == name {
				return Err(ApiError::unprocessable("mfa_factor_name_conflict", format!("A factor with the friendly name {name:?} for this user already exists")));
			}
			if f.is_verified() {
				verified += 1;
			}
		}
		if factors.len() >= cfg.mfa_max_factors || verified >= cfg.mfa_max_verified_factors {
			return Err(ApiError::unprocessable("too_many_enrolled_mfa_factors", "Maximum number of verified factors reached, unenroll to continue"));
		}
		if verified > 0 && !sess.is_aal2() {
			return Err(ApiError::forbidden("insufficient_aal", "AAL2 required to enroll a new factor"));
		}
		if verified > 0 && !recently_verified(sess) {
			return Err(ApiError::forbidden("insufficient_aal", "Verify an existing factor again before adding another"));
		}
		let secret = BASE32_NOPAD.encode(&crate::crypto::random_bytes::<20>());
		let uri = otpauth_uri(&issuer, &caller.user.email, &secret);
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		let f = factor::insert(&tx, caller.user.id, &name, "totp", &secret).await.map_err(db("Database error creating factor"))?;
		let mut t = Map::new();
		t.insert("factor_id".into(), json!(f.id));
		audit(&tx, &caller.user, "factor_in_progress", &req, Some(t)).await?;
		tx.commit().await.map_err(db("Database error"))?;
		Ok(crate::json::ok(&json!({
			"id": f.id,
			"type": "totp",
			"friendly_name": f.friendly_name,
			"totp": { "qr_code": qr_svg(&uri), "secret": secret, "uri": uri },
		})))
	}
	.await;
	req.respond(r)
}

pub async fn challenge(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::limit(&app, &req, &app.limits.factor_challenge)?;
		let caller = super::authenticate(&app, &req).await?;
		let f = factor_of(&app, &caller, &id).await?;
		if f.factor_type != "totp" {
			return Err(ApiError::unprocessable(
				"mfa_phone_verify_not_enabled",
				"MFA verification is disabled for Phone",
			));
		}
		if !app.config.mfa_totp_verify {
			return Err(ApiError::unprocessable(
				"mfa_totp_verify_not_enabled",
				"MFA verification is disabled for TOTP",
			));
		}
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		let ch = factor::insert_challenge(&tx, f.id, &req.ip())
			.await
			.map_err(db("Database error creating challenge"))?;
		let mut f = f;
		factor::set_last_challenged(&tx, &mut f, ch.created_at)
			.await
			.map_err(db("Database error creating challenge"))?;
		let mut t = Map::new();
		t.insert("factor_id".into(), json!(f.id));
		t.insert("factor_status".into(), json!(f.status));
		audit(&tx, &caller.user, "challenge_created", &req, Some(t)).await?;
		tx.commit().await.map_err(db("Database error"))?;
		let expires = ch.created_at + app.config.mfa_challenge_expiry;
		Ok(crate::json::ok(
			&json!({ "id": ch.id, "type": f.factor_type, "expires_at": expires.unix_timestamp() }),
		))
	}
	.await;
	req.respond(r)
}

pub async fn verify(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = verify_factor(&app, &req, &id).await;
	req.respond(r)
}

async fn verify_factor(app: &App, req: &Req, id: &str) -> ApiResult<Response> {
	super::limit(app, req, &app.limits.factor_verify)?;
	let caller = super::authenticate(app, req).await?;
	let f = factor_of(app, &caller, id).await?;
	let p = req.params()?;
	let code = p.str("code")?;
	let challenge_id = p.str("challenge_id")?;
	if code.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Code needs to be non-empty",
		));
	}
	if f.factor_type != "totp" {
		return Err(ApiError::unprocessable(
			"mfa_phone_verify_not_enabled",
			"MFA verification is disabled for Phone",
		));
	}
	if !app.config.mfa_totp_verify {
		return Err(ApiError::unprocessable(
			"mfa_totp_verify_not_enabled",
			"MFA verification is disabled for TOTP",
		));
	}
	let Some(sess) = caller.session.clone() else {
		return Err(ApiError::internal("Cannot read SessionId claim as UUID"));
	};
	let challenge_id = Uuid::parse_str(&challenge_id).map_err(|_| {
		ApiError::bad_request(
			"bad_json",
			"Could not parse request body as JSON: invalid challenge_id",
		)
	})?;
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let Some(ch) = factor::challenge_by_id(&conn, f.id, challenge_id)
		.await
		.map_err(db("Database error finding Challenge"))?
	else {
		return Err(ApiError::unprocessable(
			"mfa_factor_not_found",
			"MFA factor with the provided challenge ID not found",
		));
	};
	if ch.verified_at.is_some() || ch.ip_address != req.ip() {
		return Err(ApiError::unprocessable(
			"mfa_ip_address_mismatch",
			"Challenge and verify IP addresses mismatch.",
		));
	}
	if OffsetDateTime::now_utc() > ch.created_at + app.config.mfa_challenge_expiry {
		factor::delete_challenge(&conn, ch.id)
			.await
			.map_err(db("Database error deleting challenge"))?;
		return Err(ApiError::unprocessable(
			"mfa_challenge_expired",
			format!(
				"MFA challenge {} has expired, verify against another challenge or create a new challenge.",
				ch.id
			),
		));
	}
	if !totp_valid(&f.secret, &code, OffsetDateTime::now_utc()) {
		return Err(ApiError::unprocessable(
			"mfa_verification_failed",
			"Invalid TOTP code entered",
		));
	}

	let tx = conn.transaction().await.map_err(db("Database error"))?;
	let mut t = Map::new();
	t.insert("factor_id".into(), json!(f.id));
	t.insert("challenge_id".into(), json!(ch.id));
	t.insert("factor_type".into(), json!(f.factor_type));
	audit(&tx, &caller.user, "verification_attempted", req, Some(t)).await?;
	if !factor::verify_challenge(&tx, ch.id)
		.await
		.map_err(db("Database error"))?
	{
		// Verified by another request between our read and now: as if it came second.
		return Err(ApiError::unprocessable(
			"mfa_ip_address_mismatch",
			"Challenge and verify IP addresses mismatch.",
		));
	}
	let mut f = f;
	if !f.is_verified() {
		factor::set_status(&tx, &mut f, "verified")
			.await
			.map_err(db("Database error"))?;
	}
	let mut u = user::by_id(&tx, caller.user.id)
		.await
		.map_err(db("Database error"))?
		.ok_or_else(|| ApiError::internal("user not found"))?;
	let mut headers = HeaderMap::new();
	let body = raise_session(
		app,
		&tx,
		req,
		&mut headers,
		&mut u,
		&sess,
		"totp",
		Some(f.id),
	)
	.await?;
	// Two verifications at once for one user must not become a 500: the loser's deletes find
	// nothing, which is fine.
	session::delete_below_aal(&tx, u.id, "aal2")
		.await
		.map_err(|e| ApiError::internal("Failed to update sessions.").with_internal(e))?;
	factor::delete_unverified(&tx, u.id, "totp")
		.await
		.map_err(|e| ApiError::internal("Error removing unverified factors.").with_internal(e))?;
	tx.commit().await.map_err(|e| {
		if e.code()
			.is_some_and(|c| c.code() == "40001" || c.code() == "40P01" || c.code() == "23503")
		{
			ApiError::conflict("Another verification for this user is in progress; try again")
		} else {
			ApiError::internal("Database error").with_internal(e)
		}
	})?;
	Ok(with_headers(crate::json::ok(&body), headers))
}

/// Record the new authentication method on the current session, rotate its refresh token, and
/// issue an access token carrying the session's new level.
#[allow(clippy::too_many_arguments)]
async fn raise_session<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	headers: &mut HeaderMap,
	u: &mut user::User,
	sess: &session::Session,
	method: &str,
	factor_id: Option<Uuid>,
) -> ApiResult<serde_json::Value> {
	session::add_claim(tx, sess.id, method)
		.await
		.map_err(db("Database error"))?;
	let locked = session::by_id_for_update(tx, sess.id)
		.await
		.map_err(db("Database error"))?
		.ok_or_else(|| {
			ApiError::conflict("The session is being changed by another request; try again")
		})?;
	let issued = match (
		locked
			.refresh_token_hmac_key
			.as_deref()
			.and_then(crate::crypto::decode_hmac_key),
		locked.refresh_token_counter,
	) {
		(Some(key), Some(counter)) => {
			let next = counter + 2;
			session::set_counter(tx, locked.id, next)
				.await
				.map_err(db("Failed to update session"))?;
			crate::crypto::SignedRefreshToken::encode(locked.id, next, &key)
		}
		_ => {
			let Some(mut current) = session::first_active_token(tx, locked.id)
				.await
				.map_err(db("Database error"))?
			else {
				return Err(ApiError::internal("Refresh token not found"));
			};
			audit(tx, u, "token_revoked", req, None).await?;
			session::revoke(tx, &mut current)
				.await
				.map_err(db("Database error"))?;
			let new = session::insert_token(tx, u.id, locked.id, Some(&current.token))
				.await
				.map_err(db("Database error"))?;
			user::update(tx, u, &["last_sign_in_at"])
				.await
				.map_err(db("Database error"))?;
			new.token
		}
	};
	let (aal, _) = locked.aal_and_amr(u);
	session::set_aal(tx, locked.id, aal, factor_id)
		.await
		.map_err(db("Database error"))?;
	let (access, exp) = super::token::access_token(app, tx, u, locked.id).await?;
	set(headers, "sb-auth-session-id", &locked.id.to_string());
	Ok(super::token::token_response(&access, exp, &issued, u))
}

pub async fn unenroll(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		let caller = super::authenticate(&app, &req).await?;
		let f = factor_of(&app, &caller, &id).await?;
		let Some(sess) = caller.session.as_ref() else {
			return Err(ApiError::internal(
				"A valid session and factor are required to unenroll a factor",
			));
		};
		if f.is_verified() && !sess.is_aal2() {
			return Err(ApiError::unprocessable(
				"insufficient_aal",
				"AAL2 required to unenroll verified factor",
			));
		}
		if f.is_verified() && !recently_verified(sess) {
			return Err(ApiError::unprocessable(
				"insufficient_aal",
				"Verify a factor again before removing one",
			));
		}
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		factor::delete(&tx, f.id)
			.await
			.map_err(db("Database error deleting factor"))?;
		let mut t = Map::new();
		t.insert("factor_id".into(), json!(f.id));
		t.insert("factor_status".into(), json!(f.status));
		t.insert("session_id".into(), json!(sess.id));
		audit(&tx, &caller.user, "factor_unenrolled", &req, Some(t)).await?;
		downgrade_sessions(&tx, caller.user.id, f.id).await?;
		tx.commit().await.map_err(db("Database error"))?;
		Ok(crate::json::ok(&json!({ "id": f.id })))
	}
	.await;
	req.respond(r)
}

/// Sessions that were raised by this factor lose the claim it gave them and go back to `aal1`.
pub async fn downgrade_sessions<C: GenericClient>(
	tx: &C,
	user_id: Uuid,
	factor_id: Uuid,
) -> ApiResult<()> {
	let sessions: Vec<Uuid> = tx
		.query(
			"select id from sessions where factor_id = $1",
			&[&factor_id],
		)
		.await
		.map_err(db("Database error downgrading sessions"))?
		.iter()
		.map(|r| r.get(0))
		.collect();
	for s in sessions {
		tx.execute(
			"delete from mfa_amr_claims where session_id = $1 and authentication_method = 'totp'",
			&[&s],
		)
		.await
		.map_err(db("Database error downgrading sessions"))?;
	}
	tx.execute(
		"update sessions set aal = 'aal1', factor_id = null where user_id = $1 and factor_id = $2",
		&[&user_id, &factor_id],
	)
	.await
	.map_err(db("Database error downgrading sessions"))?;
	let _ = tok::CONFIRMATION;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rfc6238_vector() {
		// RFC 6238, SHA-1, T = 59s: 94287082 (8 digits), so the six-digit code is 287082.
		let secret = b"12345678901234567890";
		assert_eq!(totp_code(secret, 59 / 30), "287082");
		let b32 = BASE32_NOPAD.encode(secret);
		assert!(totp_valid(
			&b32,
			"287082",
			OffsetDateTime::from_unix_timestamp(59).unwrap()
		));
		assert!(!totp_valid(
			&b32,
			"287083",
			OffsetDateTime::from_unix_timestamp(59).unwrap()
		));
	}
}
