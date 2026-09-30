//! `GET /verify` (a link from an email) and `POST /verify` (a code typed in): confirming a
//! sign-up, an invite, a recovery or magic link, or an email change.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use deadpool_postgres::GenericClient;
use serde_json::{Map, json};
use time::OffsetDateTime;

use super::token::{Grant, audit, issue_session, traits, with_headers};
use super::{App, Req, Shared};
use crate::crypto;
use crate::error::{ApiError, ApiResult, db};
use crate::models::{
	identity, token as tok,
	user::{self, User},
};
use crate::pkce;

const SINGLE_CONFIRMATION: &str =
	"Confirmation link accepted. Please proceed to confirm link sent to the other email";

struct Params {
	kind: String,
	token: String,
	token_hash: String,
	email: String,
	redirect_to: String,
}

pub fn otp_valid(
	actual: &str,
	expected: &str,
	sent_at: OffsetDateTime,
	exp: std::time::Duration,
) -> bool {
	if expected.is_empty() {
		return false;
	}
	OffsetDateTime::now_utc() <= sent_at + exp
		&& (actual == expected || format!("{}{actual}", pkce::PREFIX) == expected)
}

fn expired(sent_at: Option<OffsetDateTime>, exp: std::time::Duration) -> bool {
	sent_at.is_none_or(|at| OffsetDateTime::now_utc() > at + exp)
}

// ------------------------------------------------------------------------------------------
// Finding the user a token belongs to.

async fn by_token_hash<C: GenericClient>(app: &App, tx: &C, p: &mut Params) -> ApiResult<User> {
	let types: &[&str] = match p.kind.as_str() {
		"email" => &[tok::CONFIRMATION, tok::RECOVERY],
		"signup" | "invite" => &[tok::CONFIRMATION],
		"recovery" | "magiclink" => &[tok::RECOVERY],
		"email_change" => &[tok::EMAIL_CHANGE_CURRENT, tok::EMAIL_CHANGE_NEW],
		_ => {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Invalid email verification type",
			));
		}
	};
	let invalid = || ApiError::forbidden("otp_expired", "Email link is invalid or has expired");
	let id = tok::find_user_id(tx, &p.token_hash, types)
		.await
		.map_err(db("Database error finding user from email link"))?
		.ok_or_else(invalid)?;
	let u = user::by_id_for_update(tx, id)
		.await
		.map_err(db("Database error finding user from email link"))?
		.ok_or_else(invalid)?;
	// Another request may have spent this link while this one waited for the row.
	if tok::find_user_id(tx, &p.token_hash, types)
		.await
		.map_err(db("Database error finding user from email link"))?
		!= Some(u.id)
	{
		return Err(invalid());
	}
	if u.is_banned() {
		return Err(ApiError::forbidden("user_banned", "User is banned"));
	}
	let exp = app.config.otp_exp;
	let is_expired = match p.kind.as_str() {
		"email" => {
			let mut sent = u.confirmation_sent_at;
			p.kind = "signup".into();
			if u.recovery_token == p.token_hash {
				sent = u.recovery_sent_at;
				p.kind = "magiclink".into();
			}
			expired(sent, exp)
		}
		"signup" | "invite" => expired(u.confirmation_sent_at, exp),
		"recovery" | "magiclink" => expired(u.recovery_sent_at, exp),
		_ => expired(u.email_change_sent_at, exp),
	};
	if is_expired {
		return Err(invalid().with_internal("email link has expired"));
	}
	Ok(u)
}

async fn by_email_and_code<C: GenericClient>(
	app: &App,
	tx: &C,
	p: &mut Params,
	aud: &str,
) -> ApiResult<Guess> {
	let invalid = || ApiError::forbidden("otp_expired", "Token has expired or is invalid");
	let found = if p.kind == "email_change" {
		let mut found = None;
		for (ty, prefixed) in [
			(tok::EMAIL_CHANGE_CURRENT, false),
			(tok::EMAIL_CHANGE_CURRENT, true),
			(tok::EMAIL_CHANGE_NEW, false),
			(tok::EMAIL_CHANGE_NEW, true),
		] {
			if ty == tok::EMAIL_CHANGE_CURRENT && !app.config.secure_email_change {
				continue;
			}
			let h = if prefixed {
				format!("{}{}", pkce::PREFIX, p.token_hash)
			} else {
				p.token_hash.clone()
			};
			if let Some(id) = tok::find_user_id(tx, &h, &[ty])
				.await
				.map_err(db("Database error finding user"))?
			{
				let u = user::by_id(tx, id)
					.await
					.map_err(db("Database error finding user"))?;
				found = u.filter(|u| u.aud == aud);
				if found.is_some() {
					break;
				}
			}
		}
		found
	} else {
		user::by_email(tx, &p.email, aud)
			.await
			.map_err(db("Database error finding user"))?
	};
	let Some(u) = found else {
		return Err(invalid());
	};
	// The row, locked and read again: a second request with the same code waits here and then
	// finds it spent, as it would had it come later.
	let u = user::by_id_for_update(tx, u.id)
		.await
		.map_err(db("Database error finding user"))?
		.ok_or_else(invalid)?;
	if u.is_banned() {
		return Err(ApiError::forbidden("user_banned", "User is banned"));
	}
	let exp = app.config.otp_exp;
	let valid_for = |expected: &str, sent: Option<OffsetDateTime>| {
		sent.is_some_and(|s| otp_valid(&p.token_hash, expected, s, exp))
	};
	let valid = match p.kind.as_str() {
		"email" => {
			if valid_for(&u.confirmation_token, u.confirmation_sent_at) {
				p.kind = "signup".into();
				true
			} else if valid_for(&u.recovery_token, u.recovery_sent_at) {
				p.kind = "magiclink".into();
				true
			} else {
				false
			}
		}
		"signup" | "invite" => valid_for(&u.confirmation_token, u.confirmation_sent_at),
		"recovery" | "magiclink" => valid_for(&u.recovery_token, u.recovery_sent_at),
		"email_change" => {
			valid_for(&u.email_change_token_current, u.email_change_sent_at)
				|| valid_for(&u.email_change_token_new, u.email_change_sent_at)
		}
		_ => false,
	};
	if !valid {
		let sent = [
			u.confirmation_sent_at,
			u.recovery_sent_at,
			u.email_change_sent_at,
		]
		.into_iter()
		.flatten()
		.map(|t| t.unix_timestamp_nanos())
		.max()
		.unwrap_or(0);
		if app.otp_guesses.wrong(u.id, sent) >= crate::ratelimit::OTP_GUESSES {
			// The fifth wrong guess spends the codes this kind of verification accepts: the user
			// asks for a new one, and until then every guess, right or wrong, gets the answer an
			// expired code gets. No new error for an application to learn (upstream #2819).
			spend(tx, u, &p.kind).await?;
			return Ok(Guess::Spent);
		}
		return Err(invalid().with_internal("token has expired or is invalid"));
	}
	app.otp_guesses.forget(u.id);
	Ok(Guess::Right(Box::new(u)))
}

/// What a guess at an emailed code came to: the user whose code it was, or that code spent by one
/// wrong guess too many (a write the caller commits before it refuses).
enum Guess {
	Right(Box<User>),
	Spent,
}

/// Clear the codes `kind` accepts, in the user row and in `one_time_tokens`.
async fn spend<C: GenericClient>(tx: &C, mut u: User, kind: &str) -> ApiResult<()> {
	let (columns, types): (&[&str], &[&str]) = match kind {
		"email" => (
			&["confirmation_token", "recovery_token"],
			&[tok::CONFIRMATION, tok::RECOVERY],
		),
		"signup" | "invite" => (&["confirmation_token"], &[tok::CONFIRMATION]),
		"recovery" | "magiclink" => (&["recovery_token"], &[tok::RECOVERY]),
		"email_change" => (
			&["email_change_token_current", "email_change_token_new"],
			&[tok::EMAIL_CHANGE_CURRENT, tok::EMAIL_CHANGE_NEW],
		),
		_ => return Ok(()),
	};
	for c in columns {
		match *c {
			"confirmation_token" => u.confirmation_token.clear(),
			"recovery_token" => u.recovery_token.clear(),
			"email_change_token_current" => u.email_change_token_current.clear(),
			_ => u.email_change_token_new.clear(),
		}
	}
	user::update(tx, &mut u, columns)
		.await
		.map_err(db("Database error updating user"))?;
	tok::delete_types(tx, u.id, types)
		.await
		.map_err(db("Database error updating user"))?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// What each kind of token does.

async fn signup_verify<C: GenericClient>(tx: &C, req: &Req, u: &mut User) -> ApiResult<()> {
	if !u.has_password() && u.invited_at.is_some() {
		// An invited user who never chose a password gets one nobody knows, so that the
		// password grant cannot be used on the account until they set their own.
		let random = crypto::secure_alphanumeric(64);
		u.encrypted_password = Some(
			tokio::task::spawn_blocking(move || crypto::hash_password(&random))
				.await
				.unwrap_or_default(),
		);
		super::user_api::set_password(tx, u, None)
			.await
			.map_err(|e| ApiError::internal("Error storing password").with_internal(e.message))?;
	}
	audit(
		tx,
		u,
		"user_signedup",
		req,
		Some(traits(&[("provider", "email")])),
	)
	.await?;
	super::signup::confirm(tx, u)
		.await
		.map_err(|e| ApiError::internal("Error confirming user").with_internal(e.message))?;
	let email = u.email.clone();
	for ident in u.identities.iter_mut() {
		if ident.email.is_empty() || email.is_empty() || ident.email != email {
			continue;
		}
		let mut upd = Map::new();
		upd.insert("email_verified".into(), json!(true));
		identity::update_data(tx, ident, &upd)
			.await
			.map_err(db("Error setting email_verified to true on identity"))?;
	}
	Ok(())
}

async fn recover_verify<C: GenericClient>(tx: &C, req: &Req, u: &mut User) -> ApiResult<()> {
	let r: ApiResult<()> = async {
		u.recovery_token.clear();
		user::update(tx, u, &["recovery_token"])
			.await
			.map_err(db("Database error updating user"))?;
		tok::clear_all(tx, u.id)
			.await
			.map_err(db("Database error updating user"))?;
		if !u.is_confirmed() {
			audit(
				tx,
				u,
				"user_signedup",
				req,
				Some(traits(&[("provider", "email")])),
			)
			.await?;
			super::signup::confirm(tx, u).await?;
		} else {
			audit(tx, u, "login", req, None).await?;
		}
		Ok(())
	}
	.await;
	r.map_err(|e| ApiError::internal("Database error updating user").with_internal(e.message))
}

/// An email change: with secure change on, the first of the two links only records itself and
/// `false` is returned; the second (or the only one) moves the address.
async fn email_change_verify<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	p: &Params,
	u: &mut User,
) -> ApiResult<bool> {
	let cfg = &app.config;
	if !cfg.autoconfirm
		&& cfg.secure_email_change
		&& u.email_change_confirm_status == 0
		&& !u.email.is_empty()
	{
		u.email_change_confirm_status = 1;
		let current = tok::find_user_id(tx, &p.token_hash, &[tok::EMAIL_CHANGE_CURRENT])
			.await
			.map_err(db("Database error"))?;
		let new = tok::find_user_id(tx, &p.token_hash, &[tok::EMAIL_CHANGE_NEW])
			.await
			.map_err(db("Database error"))?;
		let matches = |stored: &str| p.token == stored || p.token_hash == stored;
		if matches(&u.email_change_token_current) || current.is_some() {
			u.email_change_token_current.clear();
			tx.execute(
				"delete from one_time_tokens where token_type = 'email_change_token_current' and user_id = $1",
				&[&u.id],
			)
			.await
			.map_err(db("Database error"))?;
		} else if matches(&u.email_change_token_new) || new.is_some() {
			u.email_change_token_new.clear();
			tx.execute(
				"delete from one_time_tokens where token_type = 'email_change_token_new' and user_id = $1",
				&[&u.id],
			)
			.await
			.map_err(db("Database error"))?;
		}
		user::update(
			tx,
			u,
			&[
				"email_change_confirm_status",
				"email_change_token_current",
				"email_change_token_new",
			],
		)
		.await
		.map_err(db("Database error"))?;
		return Ok(false);
	}
	audit(tx, u, "user_modified", req, None).await?;
	let new_email = u.email_change.clone();
	match identity::by_provider(tx, &u.id.to_string(), "email")
		.await
		.map_err(db("Database error"))?
	{
		None => {
			let mut data = Map::new();
			data.insert("sub".into(), json!(u.id.to_string()));
			data.insert("email".into(), json!(new_email));
			data.insert("email_verified".into(), json!(true));
			data.insert("phone_verified".into(), json!(false));
			identity::insert(tx, u.id, "email", data)
				.await
				.map_err(db("Error creating identity"))?;
		}
		Some(mut ident) => {
			let mut upd = Map::new();
			upd.insert("email".into(), json!(new_email));
			upd.insert("email_verified".into(), json!(true));
			identity::update_data(tx, &mut ident, &upd)
				.await
				.map_err(db("Database error"))?;
		}
	}
	if u.is_anonymous {
		u.is_anonymous = false;
		user::update(tx, u, &["is_anonymous"])
			.await
			.map_err(db("Database error"))?;
	}
	u.identities = identity::for_user(tx, u.id)
		.await
		.map_err(|e| ApiError::internal("Error refetching identities").with_internal(e))?;
	u.email = new_email.clone();
	u.email_change.clear();
	u.email_change_token_current.clear();
	u.email_change_token_new.clear();
	u.email_change_confirm_status = 0;
	user::update(
		tx,
		u,
		&[
			"email",
			"email_change",
			"email_change_token_current",
			"email_change_token_new",
			"email_change_confirm_status",
		],
	)
	.await
	.map_err(|e| ApiError::internal("Error confirm email").with_internal(e))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(db("Error confirm email"))?;
	if !u.is_confirmed() {
		super::signup::confirm(tx, u).await?;
	}
	Ok(true)
}

async fn apply<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	p: &Params,
	u: &mut User,
) -> ApiResult<bool> {
	match p.kind.as_str() {
		"signup" | "invite" => signup_verify(tx, req, u).await.map(|_| true),
		"recovery" | "magiclink" => recover_verify(tx, req, u).await.map(|_| true),
		"email_change" => email_change_verify(app, tx, req, p, u).await,
		_ => Err(ApiError::bad_request(
			"validation_failed",
			"Unsupported verification type",
		)),
	}
}

// ------------------------------------------------------------------------------------------
// The two entry points.

pub async fn verify_get(axum::extract::State(app): Shared, req: Req) -> Response {
	match verify_link(&app, &req).await {
		Ok(r) => r,
		Err(e) => e.render(&req.headers),
	}
}

async fn verify_link(app: &App, req: &Req) -> ApiResult<Response> {
	super::limit(app, req, &app.limits.verify)?;
	let mut p = Params {
		kind: req.form_value("type"),
		token: req.form_value("token"),
		token_hash: String::new(),
		email: String::new(),
		redirect_to: req.referrer(&app.config),
	};
	if p.kind.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Verify requires a verification type",
		));
	}
	if p.token.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Verify requires a token or a token hash",
		));
	}
	p.token_hash = p.token.clone();
	let pkce_flow = p.token.starts_with(pkce::PREFIX);
	let method = if pkce_flow {
		Some(match p.kind.as_str() {
			"signup" => "email/signup",
			"invite" => "invite",
			"recovery" => "recovery",
			"magiclink" => "magiclink",
			"email_change" => "email_change",
			other => {
				return Err(ApiError::internal(format!(
					"unsupported authentication method {other:?}"
				)));
			}
		})
	} else {
		None
	};

	let mut headers = HeaderMap::new();
	let outcome: ApiResult<(Option<serde_json::Value>, Option<String>, bool)> = async {
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		let mut u = by_token_hash(app, &tx, &mut p).await?;
		if !matches!(p.kind.as_str(), "signup" | "invite" | "recovery" | "magiclink" | "email_change") {
			return Err(ApiError::bad_request("validation_failed", "Unsupported verification type"));
		}
		let completed = apply(app, &tx, req, &p, &mut u).await?;
		if !completed {
			tx.commit().await.map_err(db("Database error"))?;
			return Ok((None, None, true));
		}
		super::signup::set_providers(&tx, &mut u).await?;
		user::reload(&tx, &mut u).await.map_err(db("Database error"))?;
		let result = match method {
			None => (Some(issue_session(app, &tx, req, &mut headers, &mut u, "otp", Grant::default()).await?), None, false),
			Some(m) => {
				let flow = tok::flow_by_user(&tx, u.id, m).await.map_err(db("Database error"))?;
				let code = match flow {
					Some(mut f) if f.is_pkce() => {
						tok::issue_auth_code(&tx, &mut f).await.map_err(db("Database error"))?;
						f.auth_code.clone().unwrap_or_default()
					}
					Some(_) => {
						return Err(ApiError::bad_request(
							"flow_state_not_found",
							"No associated flow state found. 422: Flow state does not have an auth code (not a PKCE flow).",
						));
					}
					None => return Err(ApiError::bad_request("flow_state_not_found", "No associated flow state found. 422: No valid flow state found for user.")),
				};
				(None, Some(code), false)
			}
		};
		tx.commit().await.map_err(db("Database error"))?;
		Ok(result)
	}
	.await;

	let location = match outcome {
		Ok((_, _, true)) => with_message(&p.redirect_to, SINGLE_CONFIRMATION, pkce_flow),
		Ok((Some(body), _, _)) => {
			super::token::as_fragment(&p.redirect_to, &body, &[("type", &p.kind)])
		}
		Ok((None, Some(code), _)) => with_query(&p.redirect_to, &[("code", &code)]),
		Ok(_) => p.redirect_to.clone(),
		Err(e) if e.status.as_u16() < 500 || matches!(*e.kind, crate::error::ErrorKind::Http) => {
			error_redirect(&p.redirect_to, &e, pkce_flow)
		}
		Err(e) => return Err(e),
	};
	Ok(with_headers(see_other(req, &location), headers))
}

pub async fn verify_post(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = verify_code(&app, &req).await;
	req.respond(r)
}

async fn verify_code(app: &App, req: &Req) -> ApiResult<Response> {
	super::limit(app, req, &app.limits.verify)?;
	let body = req.params()?;
	let mut p = Params {
		kind: body.str("type")?,
		token: body.str("token")?,
		token_hash: body.str("token_hash")?,
		email: body.str("email")?,
		redirect_to: body.str("redirect_to")?,
	};
	let phone = body.str("phone")?;
	if p.kind.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Verify requires a verification type",
		));
	}
	if p.token.is_empty() == p.token_hash.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Verify requires either a token or a token hash",
		));
	}
	if !p.token.is_empty() {
		if !phone.is_empty() && p.email.is_empty() {
			return Err(ApiError::bad_request(
				"phone_provider_disabled",
				"Phone logins are disabled",
			));
		} else if phone.is_empty() && !p.email.is_empty() {
			p.email = super::mail::validate_email(&p.email).map_err(|e| {
				ApiError::unprocessable("validation_failed", "Invalid email format")
					.with_internal(e.message)
			})?;
			p.token_hash = crypto::token_hash(&p.email, &p.token);
		} else {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Only an email address or phone number should be provided on verify",
			));
		}
	} else if !p.email.is_empty() || !phone.is_empty() || !p.redirect_to.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Only the token_hash and type should be provided",
		));
	}
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn.transaction().await.map_err(db("Database error"))?;
	let using_hash = !p.token_hash.is_empty() && p.token.is_empty() && p.email.is_empty();
	let mut u = if using_hash {
		by_token_hash(app, &tx, &mut p).await?
	} else {
		match by_email_and_code(app, &tx, &mut p, &aud).await? {
			Guess::Right(u) => *u,
			Guess::Spent => {
				tx.commit().await.map_err(db("Database error"))?;
				return Err(ApiError::forbidden(
					"otp_expired",
					"Token has expired or is invalid",
				));
			}
		}
	};
	if matches!(p.kind.as_str(), "sms" | "phone_change") {
		return Err(ApiError::bad_request(
			"phone_provider_disabled",
			"Phone logins are disabled",
		));
	}
	let completed = apply(app, &tx, req, &p, &mut u).await?;
	if !completed {
		tx.commit().await.map_err(db("Database error"))?;
		return Ok(crate::json::ok(
			&json!({ "msg": SINGLE_CONFIRMATION, "code": "200" }),
		));
	}
	super::signup::set_providers(&tx, &mut u).await?;
	user::reload(&tx, &mut u)
		.await
		.map_err(db("Database error"))?;
	let mut headers = HeaderMap::new();
	let body = issue_session(app, &tx, req, &mut headers, &mut u, "otp", Grant::default()).await?;
	tx.commit().await.map_err(db("Database error"))?;
	Ok(with_headers(crate::json::ok(&body), headers))
}

// ------------------------------------------------------------------------------------------
// Redirect answers.

/// A URL string in three parts, as written: everything before the query, the query, the fragment.
/// The URL is never re-serialised, so nothing the application wrote (a missing trailing slash,
/// a custom scheme) is changed on the way back to it.
fn split(s: &str) -> (&str, Option<&str>, Option<&str>) {
	let (before_frag, frag) = match s.split_once('#') {
		Some((a, f)) => (a, Some(f)),
		None => (s, None),
	};
	match before_frag.split_once('?') {
		Some((base, q)) => (base, Some(q), frag),
		None => (before_frag, None, frag),
	}
}

fn pairs(q: Option<&str>) -> Vec<(String, String)> {
	q.map(|q| {
		url::form_urlencoded::parse(q.as_bytes())
			.map(|(k, v)| (k.into_owned(), v.into_owned()))
			.collect()
	})
	.unwrap_or_default()
}

fn encode_sorted(pairs: &mut [(String, String)]) -> String {
	pairs.sort_by(|a, b| a.0.cmp(&b.0));
	let mut ser = url::form_urlencoded::Serializer::new(String::new());
	for (k, v) in pairs.iter() {
		ser.append_pair(k, v);
	}
	ser.finish()
}

fn assemble(base: &str, query: &str, fragment: Option<&str>) -> String {
	let mut out = base.to_string();
	if !query.is_empty() {
		out.push('?');
		out.push_str(query);
	}
	if let Some(f) = fragment {
		out.push('#');
		out.push_str(f);
	}
	out
}

/// The redirect with these query parameters set (replacing any of the same name).
pub fn with_query(to: &str, set: &[(&str, &str)]) -> String {
	let (base, q, frag) = split(to);
	let mut ps: Vec<(String, String)> = pairs(q)
		.into_iter()
		.filter(|(k, _)| !set.iter().any(|(s, _)| s == k))
		.collect();
	for (k, v) in set {
		ps.push((k.to_string(), v.to_string()));
	}
	assemble(base, &encode_sorted(&mut ps), frag)
}

fn with_message(to: &str, message: &str, pkce_flow: bool) -> String {
	let (base, q, _) = split(to);
	let mut ps = pairs(q);
	if pkce_flow {
		ps.retain(|(k, _)| k != "message");
		ps.push(("message".into(), message.into()));
	}
	let mut h = vec![
		("message".to_string(), message.to_string()),
		("sb".to_string(), String::new()),
	];
	assemble(base, &encode_sorted(&mut ps), Some(&encode_sorted(&mut h)))
}

/// The application's redirect carrying the error: in the fragment always, in the query too for
/// a PKCE flow (a server can read a query; only the browser sees a fragment).
pub fn error_redirect(to: &str, e: &ApiError, pkce_flow: bool) -> String {
	let (base, q, _) = split(to);
	let oauth = match e.status.as_u16() {
		400 => Some("invalid_request"),
		401 => Some("unauthorized_client"),
		403 => Some("access_denied"),
		500 => Some("server_error"),
		503 => Some("temporarily_unavailable"),
		_ => None,
	};
	let mut hq: Vec<(String, String)> = vec![
		("error_code".into(), e.code.clone()),
		("error_description".into(), e.message.clone()),
		("sb".into(), String::new()),
	];
	let mut ps = pairs(q);
	let original_query = q.unwrap_or("").to_string();
	if let Some(o) = oauth {
		hq.push(("error".into(), o.into()));
	}
	let query = if pkce_flow {
		ps.retain(|(k, _)| !matches!(k.as_str(), "error" | "error_code" | "error_description"));
		if let Some(o) = oauth {
			ps.push(("error".into(), o.into()));
		}
		ps.push(("error_code".into(), e.code.clone()));
		ps.push(("error_description".into(), e.message.clone()));
		encode_sorted(&mut ps)
	} else {
		original_query
	};
	assemble(base, &query, Some(&encode_sorted(&mut hq)))
}

/// `303 See Other`, with the short HTML body browsers show while they follow it.
pub fn see_other(req: &Req, location: &str) -> Response {
	go_redirect(req, location, StatusCode::SEE_OTHER)
}

pub fn go_redirect(req: &Req, location: &str, status: StatusCode) -> Response {
	let mut r = super::redirect(location, status);
	if req.method == axum::http::Method::GET || req.method == axum::http::Method::HEAD {
		r.headers_mut().insert(
			axum::http::header::CONTENT_TYPE,
			axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
		);
	}
	if req.method == axum::http::Method::GET {
		let text = status.canonical_reason().unwrap_or("");
		*r.body_mut() = axum::body::Body::from(format!(
			"<a href=\"{}\">{text}</a>.\n\n",
			crate::template::html_escape(location)
		));
	}
	r
}
