//! `POST /otp`, `POST /magiclink`, `POST /recover` and `POST /resend`: the mails that sign a
//! user in, reset a password, or confirm an address, sent on request.
//!
//! None of them may say whether an address has an account: each answers the same `{}` for an
//! address with an account and one without, and a mail server refusing the address is logged,
//! not reported.

use axum::response::Response;
use serde_json::{Map, json};

use super::token::{audit, traits};
use super::{App, Req, Shared};
use crate::error::{ApiError, ApiResult, db};
use crate::models::{identity, token as tok, user};
use crate::{crypto, pkce};

fn empty() -> Response {
	crate::json::ok(&json!({}))
}

/// A mail the server could not deliver to an address is not something to tell the caller about.
fn quiet_delivery(r: ApiResult<()>) -> ApiResult<()> {
	match r {
		Err(e) if e.code == "email_address_invalid" => {
			tracing::info!(message = %e.message, "the mail server refused an address; answered as if sent");
			Ok(())
		}
		other => other,
	}
}

pub async fn otp(axum::extract::State(app): Shared, req: Req) -> Response {
	let mut r = otp_once(&app, &req).await;
	if super::signup::is_race(&r) {
		r = otp_once(&app, &req).await;
	}
	req.respond(r)
}

async fn otp_once(app: &App, req: &Req) -> ApiResult<Response> {
	async {
		super::limit(app, req, &app.limits.otp)?;
		let p = req.params()?;
		let email = p.str("email")?;
		let phone = p.str("phone")?;
		let channel = p.str("channel")?;
		let create_user = p.bool("create_user")?.unwrap_or(true);
		if !email.is_empty() && !phone.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Only an email address or phone number should be provided",
			));
		}
		if !email.is_empty() && !channel.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Channel should only be specified with Phone OTP",
			));
		}
		pkce::validate_params(&p.str("code_challenge_method")?, &p.str("code_challenge")?)?;
		if !create_user && !email.is_empty() {
			let email = super::mail::validate_email(&email)?;
			let claims = super::optional_claims(app, req);
			let aud = super::request_aud(app, req, claims.as_ref());
			let conn = app.pool.get().await.map_err(super::pool_error)?;
			if user::by_email(&conn, &email, &aud)
				.await
				.map_err(db("Database error finding user"))?
				.is_none()
			{
				// No account and no sign-up: nothing is sent, and the answer is the one a sent
				// mail gets, so it does not say that the address is unknown.
				return Ok(empty());
			}
		}
		if !email.is_empty() {
			return magic(app, req, create_user).await;
		}
		if !phone.is_empty() {
			return Err(ApiError::bad_request(
				"phone_provider_disabled",
				"Unsupported phone provider",
			));
		}
		Err(ApiError::bad_request(
			"validation_failed",
			"One of email or phone must be set",
		))
	}
	.await
}

pub async fn magic_link(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::limit(&app, &req, &app.limits.magic_link)?;
		magic(&app, &req, true).await
	}
	.await;
	req.respond(r)
}

async fn magic(app: &App, req: &Req, may_create: bool) -> ApiResult<Response> {
	let cfg = &app.config;
	if !cfg.email_enabled {
		return Err(ApiError::unprocessable(
			"email_provider_disabled",
			"Email logins are disabled",
		));
	}
	let p = req.params().map_err(|e| {
		ApiError::bad_request(
			"bad_json",
			e.message.replace(
				"Could not parse request body as JSON",
				"Could not read verification params",
			),
		)
	})?;
	let email = p.str("email")?;
	if email.is_empty() {
		return Err(ApiError::unprocessable(
			"validation_failed",
			"Password recovery requires an email",
		));
	}
	let email = super::mail::validate_email(&email)?;
	let challenge = p.str("code_challenge")?;
	let method = p.str("code_challenge_method")?;
	pkce::validate_params(&method, &challenge)?;
	let data = p.map("data")?.unwrap_or_default();
	let pkce_flow = !challenge.is_empty();
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let existing = user::by_email(&conn, &email, &aud)
		.await
		.map_err(db("Database error finding user"))?;
	let is_new = existing.as_ref().is_none_or(|u| !u.is_confirmed());
	if is_new {
		if !may_create && existing.is_none() {
			return Ok(empty());
		}
		if cfg.disable_signup {
			return Err(ApiError::unprocessable(
				"signup_disabled",
				"Signups not allowed for this instance",
			));
		}
		if !super::signup::domain_allowed(cfg, &email) {
			return Err(ApiError::forbidden(
				"signup_disabled",
				"Signups from this email domain are not allowed",
			));
		}
		passwordless_signup(app, req, &mut conn, &email, &aud, data, &challenge, &method).await?;
		if cfg.autoconfirm {
			// Confirmed at once: now send the sign-in link itself.
			let u = user::by_email(&conn, &email, &aud)
				.await
				.map_err(db("Database error finding user"))?;
			if let Some(mut u) = u {
				return send_link(app, req, &mut conn, &mut u, pkce_flow, &challenge, &method)
					.await;
			}
		}
		return Ok(empty());
	}
	let mut u = existing.expect("found above");
	send_link(app, req, &mut conn, &mut u, pkce_flow, &challenge, &method).await
}

async fn send_link(
	app: &App,
	req: &Req,
	conn: &mut deadpool_postgres::Object,
	u: &mut user::User,
	pkce_flow: bool,
	challenge: &str,
	method: &str,
) -> ApiResult<Response> {
	let tx = conn.transaction().await.map_err(db("Database error"))?;
	if pkce_flow {
		tok::insert_flow(
			&tx,
			&tok::NewFlow {
				provider_type: "magiclink",
				authentication_method: "magiclink",
				code_challenge: challenge,
				code_challenge_method: method,
				user_id: Some(u.id),
				invite_token: None,
				referrer: None,
				provider_access_token: None,
				provider_refresh_token: None,
			},
		)
		.await
		.map_err(db("Database error creating flow state"))?;
	}
	audit(&tx, u, "user_recovery_requested", req, None).await?;
	quiet_delivery(super::mail::send_magic_link(app, &tx, req, u, pkce_flow).await)?;
	tx.commit().await.map_err(db("Database error"))?;
	Ok(empty())
}

/// A sign-up with no password: the account gets one nobody knows, and the confirmation mail is
/// the sign-in link. The password policy does not apply to a password nobody chose.
#[allow(clippy::too_many_arguments)]
async fn passwordless_signup(
	app: &App,
	req: &Req,
	conn: &mut deadpool_postgres::Object,
	email: &str,
	aud: &str,
	data: Map<String, serde_json::Value>,
	challenge: &str,
	method: &str,
) -> ApiResult<()> {
	let cfg = &app.config;
	let random = crypto::secure_alphanumeric(33);
	let hash = tokio::task::spawn_blocking(move || crypto::hash_password(&random))
		.await
		.unwrap_or_default();
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error saving new user"))?;
	let mut u = match super::signup::duplicate_email(&tx, email, aud, None).await? {
		Some(u) => u,
		None => {
			let mut nu = user::new_user(email, "", Some(hash), aud, Some(data.clone()));
			let mut app_meta = Map::new();
			app_meta.insert("provider".into(), json!("email"));
			app_meta.insert("providers".into(), json!(["email"]));
			nu.app_metadata = Some(app_meta);
			super::signup::create_user(&tx, &mut nu, &cfg.jwt_default_group).await?;
			nu
		}
	};
	if identity::by_provider(&tx, &u.id.to_string(), "email")
		.await
		.map_err(db("Database error finding identity"))?
		.is_none()
	{
		let mut idata = identity::email_identity_data(u.id, &u.email);
		for (k, v) in &data {
			idata.entry(k.clone()).or_insert_with(|| v.clone());
		}
		let ident = identity::insert(&tx, u.id, "email", idata)
			.await
			.map_err(db("Error creating identity"))?;
		super::signup::remove_unconfirmed_identities(&tx, &mut u, &ident).await?;
		u.identities = vec![ident];
	}
	let pkce_flow = !challenge.is_empty();
	if cfg.autoconfirm {
		audit(
			&tx,
			&u,
			"user_signedup",
			req,
			Some(traits(&[("provider", "email")])),
		)
		.await?;
		super::signup::confirm(&tx, &mut u).await?;
	} else {
		audit(
			&tx,
			&u,
			"user_confirmation_requested",
			req,
			Some(traits(&[("provider", "email")])),
		)
		.await?;
		if pkce_flow {
			tok::insert_flow(
				&tx,
				&tok::NewFlow {
					provider_type: "email",
					authentication_method: "email/signup",
					code_challenge: challenge,
					code_challenge_method: method,
					user_id: Some(u.id),
					invite_token: None,
					referrer: None,
					provider_access_token: None,
					provider_refresh_token: None,
				},
			)
			.await
			.map_err(db("Database error creating flow state"))?;
		}
		quiet_delivery(super::mail::send_confirmation(app, &tx, req, &mut u, pkce_flow).await)?;
	}
	tx.commit()
		.await
		.map_err(db("Database error saving new user"))?;
	Ok(())
}

pub async fn recover(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::limit(&app, &req, &app.limits.recover)?;
		if !app.config.email_enabled {
			return Err(ApiError::bad_request(
				"email_provider_disabled",
				"Email logins are disabled",
			));
		}
		let p = req.params()?;
		let email = p.str("email")?;
		let challenge = p.str("code_challenge")?;
		let method = p.str("code_challenge_method")?;
		if email.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Password recovery requires an email",
			));
		}
		let email = super::mail::validate_email(&email)?;
		pkce::validate_params(&method, &challenge)?;
		let claims = super::optional_claims(&app, &req);
		let aud = super::request_aud(&app, &req, claims.as_ref());
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let Some(mut u) = user::by_email(&conn, &email, &aud)
			.await
			.map_err(|e| ApiError::internal("Unable to process request").with_internal(e))?
		else {
			return Ok(empty());
		};
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		if !challenge.is_empty() {
			tok::insert_flow(
				&tx,
				&tok::NewFlow {
					provider_type: "recovery",
					authentication_method: "recovery",
					code_challenge: &challenge,
					code_challenge_method: &method,
					user_id: Some(u.id),
					invite_token: None,
					referrer: None,
					provider_access_token: None,
					provider_refresh_token: None,
				},
			)
			.await
			.map_err(db("Database error creating flow state"))?;
		}
		audit(&tx, &u, "user_recovery_requested", &req, None).await?;
		quiet_delivery(
			super::mail::send_recovery(&app, &tx, &req, &mut u, !challenge.is_empty()).await,
		)?;
		tx.commit().await.map_err(db("Database error"))?;
		Ok(empty())
	}
	.await;
	req.respond(r)
}

pub async fn resend(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::limit(&app, &req, &app.limits.resend)?;
		let p = req.params()?;
		let kind = p.str("type")?;
		let email = p.str("email")?;
		let phone = p.str("phone")?;
		let challenge = p.str("code_challenge")?;
		let method = p.str("code_challenge_method")?;
		match kind.as_str() {
			"signup" | "email_change" => pkce::validate_params(&method, &challenge)?,
			"sms" | "phone_change" => {}
			_ => {
				return Err(ApiError::bad_request(
					"validation_failed",
					"Missing one of these types: signup, email_change, sms, phone_change",
				));
			}
		}
		if email.is_empty() && kind == "signup" {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Type provided requires an email address",
			));
		}
		if phone.is_empty() && kind == "sms" {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Type provided requires a phone number",
			));
		}
		if !email.is_empty() && !phone.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Only an email address or phone number should be provided.",
			));
		}
		if !phone.is_empty() {
			return Err(ApiError::bad_request(
				"phone_provider_disabled",
				"Phone logins are disabled",
			));
		}
		if email.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Missing email address or phone number",
			));
		}
		if !app.config.email_enabled {
			return Err(ApiError::bad_request(
				"email_provider_disabled",
				"Email logins are disabled",
			));
		}
		let email = super::mail::validate_email(&email)?;
		let claims = super::optional_claims(&app, &req);
		let aud = super::request_aud(&app, &req, claims.as_ref());
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let Some(mut u) = user::by_email(&conn, &email, &aud)
			.await
			.map_err(|e| ApiError::internal("Unable to process request").with_internal(e))?
		else {
			return Ok(empty());
		};
		if (kind == "signup" && u.is_confirmed())
			|| (kind == "email_change" && u.email_change.is_empty())
			|| kind == "sms"
			|| kind == "phone_change"
		{
			return Ok(empty());
		}
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		let pkce_flow = !challenge.is_empty();
		if kind == "signup" {
			audit(&tx, &u, "user_confirmation_requested", &req, None).await?;
			if pkce_flow {
				tok::insert_flow(
					&tx,
					&tok::NewFlow {
						provider_type: "email",
						authentication_method: "email/signup",
						code_challenge: &challenge,
						code_challenge_method: &method,
						user_id: Some(u.id),
						invite_token: None,
						referrer: None,
						provider_access_token: None,
						provider_refresh_token: None,
					},
				)
				.await
				.map_err(db("Database error creating flow state"))?;
			}
			quiet_delivery(
				super::mail::send_confirmation(&app, &tx, &req, &mut u, pkce_flow).await,
			)?;
		} else {
			if pkce_flow {
				tok::insert_flow(
					&tx,
					&tok::NewFlow {
						provider_type: "email_change",
						authentication_method: "email_change",
						code_challenge: &challenge,
						code_challenge_method: &method,
						user_id: Some(u.id),
						invite_token: None,
						referrer: None,
						provider_access_token: None,
						provider_refresh_token: None,
					},
				)
				.await
				.map_err(db("Database error creating flow state"))?;
			}
			let new_email = u.email_change.clone();
			super::mail::send_email_change(&app, &tx, &req, &mut u, &new_email, pkce_flow).await?;
		}
		tx.commit().await.map_err(db("Database error"))?;
		Ok(empty())
	}
	.await;
	req.respond(r)
}
