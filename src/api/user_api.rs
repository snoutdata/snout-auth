//! `GET /user`, `PUT /user`, `POST /logout` and `GET /reauthenticate`: the signed-in user's own
//! account.

use axum::response::Response;
use serde_json::{Map, Value, json};

use super::token::audit;
use super::{App, Req, Shared};
use crate::crypto;
use crate::error::{ApiError, ApiResult, db};
use crate::models::{identity, session, token as tok, user};

pub async fn get_user(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let caller = super::authenticate(&app, &req).await?;
		let aud = super::request_aud(&app, &req, Some(&caller.claims));
		let from_claims = crate::jwt::audiences(&caller.claims);
		if from_claims.first().is_none_or(|a| *a != aud) {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Token audience doesn't match request audience",
			));
		}
		Ok(crate::json::ok(&caller.user.to_json()))
	}
	.await;
	req.respond(r)
}

pub async fn logout(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let scope = match req.query("scope") {
			"" | "global" => "global",
			"local" => "local",
			"others" => "others",
			other => {
				return Err(ApiError::bad_request(
					"validation_failed",
					format!("Unsupported logout scope {other:?}"),
				));
			}
		};
		let caller = super::authenticate(&app, &req).await?;
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Error logging out user"))?;
		audit(&tx, &caller.user, "logout", &req, None).await?;
		match (&caller.session, scope) {
			(Some(s), "local") => session::delete(&tx, s.id).await,
			(Some(s), "others") => session::delete_others(&tx, s.id, caller.user.id).await,
			_ => session::delete_all_for_user(&tx, caller.user.id).await,
		}
		.map_err(db("Error logging out user"))?;
		tx.commit().await.map_err(db("Error logging out user"))?;
		Ok(super::no_content())
	}
	.await;
	req.respond(r)
}

pub async fn reauthenticate(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let caller = super::authenticate(&app, &req).await?;
		let mut u = caller.user;
		if u.email.is_empty() && u.phone.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Reauthentication requires the user to have an email or a phone number",
			));
		}
		if !u.email.is_empty() && !u.is_confirmed() {
			return Err(ApiError::unprocessable(
				"email_not_confirmed",
				"Please verify your email first.",
			));
		}
		if u.email.is_empty() {
			return Err(ApiError::unprocessable(
				"phone_provider_disabled",
				"Phone logins are disabled",
			));
		}
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Error sending reauthentication email"))?;
		audit(&tx, &u, "user_reauthenticate_requested", &req, None).await?;
		super::mail::send_reauthentication(&app, &tx, &mut u).await?;
		tx.commit()
			.await
			.map_err(db("Error sending reauthentication email"))?;
		Ok(crate::json::ok(&json!({})))
	}
	.await;
	req.respond(r)
}

/// Whether `nonce` is the code the last reauthentication mail carried, still in time.
pub async fn verify_reauthentication<C: deadpool_postgres::GenericClient>(
	app: &App,
	tx: &C,
	u: &mut user::User,
	nonce: &str,
) -> ApiResult<()> {
	let invalid = || {
		ApiError::unprocessable(
			"reauthentication_not_valid",
			"Nonce has expired or is invalid",
		)
	};
	let Some(sent) = u.reauthentication_sent_at else {
		return Err(invalid());
	};
	if u.reauthentication_token.is_empty() || u.email.is_empty() {
		return Err(invalid());
	}
	let hash = crypto::token_hash(&u.email, nonce);
	if !super::verify::otp_valid(&hash, &u.reauthentication_token, sent, app.config.otp_exp) {
		return Err(invalid());
	}
	u.reauthentication_token.clear();
	user::update(tx, u, &["reauthentication_token"])
		.await
		.map_err(db("Error during reauthentication"))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(db("Error during reauthentication"))?;
	Ok(())
}

pub async fn update_user(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = update(&app, &req).await;
	req.respond(r)
}

async fn update(app: &App, req: &Req) -> ApiResult<Response> {
	let cfg = &app.config;
	let caller = super::authenticate(app, req).await?;
	super::limit(app, req, &app.limits.user)?;
	let aud = super::request_aud(app, req, Some(&caller.claims));
	let p = req.params()?;
	let mut email = p.str("email")?;
	let password: Option<String> = match p.value("password") {
		None => None,
		Some(Value::String(s)) => Some(s.clone()),
		Some(_) => {
			return Err(ApiError::bad_request(
				"bad_json",
				"Could not parse request body as JSON: password must be a string",
			));
		}
	};
	let current_password = p.str("current_password")?;
	let nonce = p.str("nonce")?;
	let data = p.map("data")?;
	let app_data = p.map("app_metadata")?;
	let phone = p.str("phone")?;
	let challenge = p.str("code_challenge")?;
	let challenge_method = p.str("code_challenge_method")?;

	if !email.is_empty() {
		email = super::mail::validate_email(&email)?;
	}
	if !phone.is_empty() {
		return Err(ApiError::bad_request(
			"phone_provider_disabled",
			"Phone logins are disabled",
		));
	}
	if let Some(pw) = &password {
		super::signup::check_password(cfg, pw)?;
	}
	let mut u = caller.user;
	let sess = caller.session;
	if app_data.is_some() {
		return Err(ApiError::forbidden(
			"not_admin",
			"Updating app_metadata requires admin privileges",
		));
	}
	let changing_secret = password.as_deref().is_some_and(|p| !p.is_empty())
		|| (!email.is_empty() && email != u.email);
	if u.has_mfa() && !sess.as_ref().is_some_and(session::Session::is_aal2) && changing_secret {
		return Err(ApiError::unauthorized(
			"insufficient_aal",
			"AAL2 session is required to update email or password when MFA is enabled.",
		));
	}
	if u.is_anonymous && password.as_deref().is_some_and(|p| !p.is_empty()) && email.is_empty() {
		return Err(ApiError::unprocessable(
			"validation_failed",
			"Updating password of an anonymous user without an email or phone is not allowed",
		));
	}
	if u.is_sso_user && (changing_secret || !nonce.is_empty()) {
		return Err(ApiError::unprocessable(
			"user_sso_managed",
			"Updating email, phone, password of a SSO account only possible via SSO",
		));
	}

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	if !email.is_empty()
		&& email != u.email
		&& super::signup::duplicate_email(&conn, &email, &aud, Some(u.id))
			.await?
			.is_some()
	{
		return Err(ApiError::unprocessable(
			"email_exists",
			"A user with this email address has already been registered",
		));
	}
	let adding_first_password =
		password.as_deref().is_some_and(|p| !p.is_empty()) && !u.has_password();
	let tx = conn
		.transaction()
		.await
		.map_err(db("Error updating user"))?;

	if let Some(pw) = &password {
		if cfg.update_password_require_reauthentication {
			let fresh = sess.as_ref().is_some_and(|s| {
				time::OffsetDateTime::now_utc()
					< s.created_at + std::time::Duration::from_secs(24 * 3600)
			});
			if !fresh {
				if nonce.is_empty() {
					return Err(ApiError::bad_request(
						"reauthentication_needed",
						"Password update requires reauthentication",
					));
				}
				verify_reauthentication(app, &tx, &mut u, &nonce).await?;
			}
		}
		if !pw.is_empty() && u.has_password() {
			let is_recovery = sess.as_ref().is_some_and(|s| {
				s.amr
					.iter()
					.any(|c| matches!(c.method.as_str(), "otp" | "magiclink" | "recovery"))
			});
			let hash = u.encrypted_password.clone().unwrap_or_default();
			if cfg.update_password_require_current_password && !is_recovery {
				if current_password.is_empty() {
					return Err(ApiError::bad_request(
						"current_password_required",
						"Current password required when setting new password.",
					));
				}
				let (h, c) = (hash.clone(), current_password.clone());
				if !tokio::task::spawn_blocking(move || crypto::verify_password(&h, &c))
					.await
					.unwrap_or(false)
				{
					return Err(ApiError::bad_request(
						"current_password_mismatch",
						"Current password required when setting new password.",
					));
				}
			}
			let (h, n) = (hash, pw.clone());
			if tokio::task::spawn_blocking(move || crypto::verify_password(&h, &n))
				.await
				.unwrap_or(false)
			{
				return Err(ApiError::unprocessable(
					"same_password",
					"New password should be different from the old password.",
				));
			}
		}
		u.encrypted_password = if pw.is_empty() {
			None
		} else {
			let n = pw.clone();
			Some(
				tokio::task::spawn_blocking(move || crypto::hash_password(&n))
					.await
					.unwrap_or_default(),
			)
		};
		set_password(&tx, &mut u, sess.as_ref().map(|s| s.id)).await?;
		audit(&tx, &u, "user_updated_password", req, None).await?;
		if adding_first_password {
			ensure_email_identity(&tx, &mut u).await?;
		}
	}
	if let Some(d) = &data {
		u.merge_user_metadata(d);
		user::update(&tx, &mut u, &["raw_user_meta_data"])
			.await
			.map_err(db("Error updating user"))?;
	}
	if !email.is_empty() && email != u.email && u.is_anonymous && cfg.autoconfirm {
		// A guest adding an address where sign-ups need no confirmation: the address is theirs
		// at once, as a sign-up's would be, and they stop being a guest.
		u.email_change = email.clone();
		super::verify::complete_email_change(&tx, req, &mut u).await?;
	} else if !email.is_empty() && email != u.email {
		let pkce_flow = !challenge.is_empty();
		if pkce_flow {
			crate::pkce::validate_params(&challenge_method, &challenge)?;
			tok::insert_flow(
				&tx,
				&tok::NewFlow {
					provider_type: "email_change",
					authentication_method: "email_change",
					code_challenge: &challenge,
					code_challenge_method: &challenge_method,
					user_id: Some(u.id),
					invite_token: None,
					referrer: None,
					provider_access_token: None,
					provider_refresh_token: None,
				},
			)
			.await
			.map_err(db("Error updating user"))?;
		}
		super::mail::send_email_change(app, &tx, req, &mut u, &email, pkce_flow).await?;
	}
	audit(&tx, &u, "user_modified", req, None).await?;
	tx.commit().await.map_err(db("Error updating user"))?;
	user::load_relations(&conn, &mut u)
		.await
		.map_err(db("Error updating user"))?;
	Ok(crate::json::ok(&u.to_json()))
}

/// Store the new password hash (already on `u`), void every outstanding link and code, and end
/// every other session: whoever held the old password is signed out.
pub async fn set_password<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
	keep_session: Option<uuid::Uuid>,
) -> ApiResult<()> {
	u.confirmation_token.clear();
	u.confirmation_sent_at = None;
	u.recovery_token.clear();
	u.recovery_sent_at = None;
	u.email_change_token_current.clear();
	u.email_change_token_new.clear();
	u.email_change_sent_at = None;
	u.phone_change_token.clear();
	u.phone_change_sent_at = None;
	u.reauthentication_token.clear();
	u.reauthentication_sent_at = None;
	user::update(
		tx,
		u,
		&[
			"encrypted_password",
			"confirmation_token",
			"confirmation_sent_at",
			"recovery_token",
			"recovery_sent_at",
			"email_change_token_current",
			"email_change_token_new",
			"email_change_sent_at",
			"phone_change_token",
			"phone_change_sent_at",
			"reauthentication_token",
			"reauthentication_sent_at",
		],
	)
	.await
	.map_err(db("Error during password storage"))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(db("Error during password storage"))?;
	match keep_session {
		Some(s) => session::delete_others(tx, s, u.id).await,
		None => session::delete_all_for_user(tx, u.id).await,
	}
	.map_err(db("Error during password storage"))?;
	Ok(())
}

/// A user who signed up through a provider and now sets a password can sign in with it: the
/// confirmed address gets an email identity, and `providers` lists it.
async fn ensure_email_identity<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
) -> ApiResult<()> {
	if u.is_sso_user || u.is_anonymous || u.email.is_empty() || !u.is_confirmed() {
		return Ok(());
	}
	if u.identities.iter().any(|i| i.provider == "email") {
		return Ok(());
	}
	let mut data = Map::new();
	data.insert("sub".into(), json!(u.id.to_string()));
	data.insert("email".into(), json!(u.email));
	data.insert("email_verified".into(), json!(true));
	data.insert("phone_verified".into(), json!(false));
	let ident = identity::insert(tx, u.id, "email", data)
		.await
		.map_err(db("Error creating identity"))?;
	u.identities.push(ident);
	super::signup::set_providers(tx, u).await
}
