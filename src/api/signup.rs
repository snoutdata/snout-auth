//! `POST /signup`: a new account with an email address and a password, or, with neither an
//! address nor a phone number, a guest (an anonymous user) when the project allows them.

use axum::http::HeaderMap;
use axum::response::Response;
use serde_json::{Map, Value, json};

use super::token::{Grant, audit, issue_session, traits, with_headers};
use super::{App, Req, Shared};
use crate::config::Config;
use crate::error::{ApiError, ApiResult, db};
use crate::models::{identity, token as tok, user};
use crate::{crypto, pkce};

pub const MAX_PASSWORD: usize = 72;

/// The password policy: a length, and optionally one character from each required set.
pub fn check_password(cfg: &Config, password: &str) -> ApiResult<()> {
	if password.len() > MAX_PASSWORD {
		return Err(ApiError::bad_request(
			"validation_failed",
			format!("Password cannot be longer than {MAX_PASSWORD} characters"),
		));
	}
	let mut reasons = Vec::new();
	let mut messages = Vec::new();
	if password.chars().count() < cfg.password_min_length {
		reasons.push("length".to_string());
		messages.push(format!(
			"Password should be at least {} characters.",
			cfg.password_min_length
		));
	}
	if cfg
		.password_required_characters
		.iter()
		.any(|set| !set.is_empty() && !password.chars().any(|c| set.contains(c)))
	{
		reasons.push("characters".to_string());
		messages.push(format!(
			"Password should contain at least one character of each: {}.",
			cfg.password_required_characters.join(", ")
		));
	}
	if reasons.is_empty() {
		Ok(())
	} else {
		Err(ApiError::weak_password(messages.join(" "), reasons))
	}
}

/// Whether the domain of this address may sign up, when sign-ups are limited to some domains.
pub fn domain_allowed(cfg: &Config, email: &str) -> bool {
	if cfg.allowed_signup_domains.is_empty() {
		return true;
	}
	let domain = email
		.rsplit_once('@')
		.map(|(_, d)| d.to_ascii_lowercase())
		.unwrap_or_default();
	cfg.allowed_signup_domains.contains(&domain)
}

pub async fn signup(axum::extract::State(app): Shared, req: Req) -> Response {
	let mut r = handle(&app, &req).await;
	if is_race(&r) {
		r = handle(&app, &req).await;
	}
	req.respond(r)
}

/// The code of a sign-up that lost a race to create the same user.
pub const RACE: &str = "email_exists_race";

pub fn is_race<T>(r: &ApiResult<T>) -> bool {
	matches!(r, Err(e) if e.code == RACE)
}

async fn handle(app: &App, req: &Req) -> ApiResult<Response> {
	let cfg = &app.config;
	let p = req.params()?;
	let mut email = p.str("email")?;
	let phone = p.str("phone")?;
	let data = p.map("data")?.unwrap_or_default();
	// No address and no phone number is a guest, decided before anything else is checked: with
	// guests off, such a request is refused as a disabled provider, as upstream refuses it, and
	// not as a sign-up that forgot its email.
	if email.is_empty() && phone.is_empty() {
		return anonymous(app, req, data).await;
	}
	if cfg.disable_signup {
		return Err(ApiError::unprocessable(
			"signup_disabled",
			"Signups not allowed for this instance",
		));
	}
	let password = p.str("password")?;
	let challenge = p.str("code_challenge")?;
	let challenge_method = p.str("code_challenge_method")?;

	if password.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Signup requires a valid password",
		));
	}
	check_password(cfg, &password)?;
	if !email.is_empty() && !phone.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Only an email address or phone number should be provided on signup.",
		));
	}
	if !phone.is_empty() && !challenge.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"PKCE not supported for phone signups",
		));
	}
	pkce::validate_params(&challenge_method, &challenge)?;
	let pkce_flow = !challenge.is_empty();

	// No email here means a phone number (no address and no phone was a guest, above).
	if email.is_empty() {
		return Err(ApiError::bad_request(
			"phone_provider_disabled",
			"Phone signups are disabled",
		));
	}
	if !cfg.email_enabled {
		return Err(ApiError::bad_request(
			"email_provider_disabled",
			"Email signups are disabled",
		));
	}
	email = super::mail::validate_email(&email)?;
	if !domain_allowed(cfg, &email) {
		return Err(ApiError::forbidden(
			"signup_disabled",
			"Signups from this email domain are not allowed",
		));
	}
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error saving new user"))?;
	let existing = duplicate_email(&tx, &email, &aud, None).await?;

	// With autoconfirm on, signing up again for an existing unconfirmed row confirms it and
	// answers with a session, so only a caller with that row's own password may; everybody else
	// gets the answer a registered address gets.
	let claims_row = match &existing {
		Some(u) if cfg.autoconfirm && !u.is_confirmed() => {
			let hash = u.encrypted_password.clone().unwrap_or_default();
			let pw = password.clone();
			tokio::task::spawn_blocking(move || crypto::verify_password(&hash, &pw))
				.await
				.unwrap_or(false)
		}
		_ => true,
	};

	let mut u = match existing {
		Some(u) if u.is_confirmed() || !claims_row => {
			// Already registered. Recorded, and answered as a new sign-up is, so the answer does
			// not say which addresses have accounts.
			audit(
				&tx,
				&u,
				"user_repeated_signup",
				req,
				Some(traits(&[("provider", "email")])),
			)
			.await?;
			tx.commit().await.map_err(db("Database error"))?;
			if cfg.autoconfirm {
				return Err(ApiError::unprocessable(
					"user_already_exists",
					"User already registered",
				));
			}
			return Ok(crate::json::ok(&obfuscated(&u, &email, &aud, &data)));
		}
		Some(u) => u,
		None => {
			let pw = password.clone();
			let hash = tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
				.await
				.unwrap_or_default();
			let mut nu = user::new_user(&email, "", Some(hash), &aud, Some(data.clone()));
			let mut app_meta = Map::new();
			app_meta.insert("provider".into(), json!("email"));
			app_meta.insert("providers".into(), json!(["email"]));
			nu.app_metadata = Some(app_meta);
			create_user(&tx, &mut nu, &cfg.jwt_default_group).await?;
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
		remove_unconfirmed_identities(&tx, &mut u, &ident).await?;
		u.identities = vec![ident];
	}

	if !u.is_confirmed() {
		if cfg.autoconfirm {
			audit(
				&tx,
				&u,
				"user_signedup",
				req,
				Some(traits(&[("provider", "email")])),
			)
			.await?;
			confirm(&tx, &mut u).await?;
			// The answer says the new identity's address is verified, which it now is; the stored
			// row keeps what was written at creation, as the reference server's does.
			for i in u.identities.iter_mut().filter(|i| i.provider == "email") {
				i.identity_data.insert("email_verified".into(), json!(true));
			}
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
				.map_err(db("Database error creating flow state"))?;
			}
			super::mail::send_confirmation(app, &tx, req, &mut u, pkce_flow).await?;
		}
	}

	if u.is_confirmed() {
		audit(
			&tx,
			&u,
			"login",
			req,
			Some(traits(&[("provider", "email")])),
		)
		.await?;
		let mut headers = HeaderMap::new();
		let body = issue_session(
			app,
			&tx,
			req,
			&mut headers,
			&mut u,
			"password",
			Grant::default(),
		)
		.await?;
		tx.commit()
			.await
			.map_err(db("Database error saving new user"))?;
		return Ok(with_headers(crate::json::ok(&body), headers));
	}
	tx.commit()
		.await
		.map_err(db("Database error saving new user"))?;
	if u.invited_at.is_some() {
		u.user_metadata = Some(Map::new());
		u.identities.clear();
	}
	Ok(crate::json::ok(&u.to_json()))
}

/// A guest: a user with no email, no phone and no password, signed in at once. The session is a
/// real one (`auth.uid()` works in a policy) and its token says `is_anonymous: true`. The guest
/// becomes a full account by adding an address with `PUT /user`, keeping the same id.
async fn anonymous(app: &App, req: &Req, data: Map<String, Value>) -> ApiResult<Response> {
	let cfg = &app.config;
	if !cfg.anonymous_users_enabled {
		return Err(ApiError::unprocessable(
			"anonymous_provider_disabled",
			"Anonymous sign-ins are disabled",
		));
	}
	super::limit(app, req, &app.limits.anonymous)?;
	if cfg.disable_signup {
		return Err(ApiError::unprocessable(
			"signup_disabled",
			"Signups not allowed for this instance",
		));
	}
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error creating anonymous user"))?;
	// No identity and no provider in `app_metadata`, and nothing on the audit log, as upstream:
	// a guest is visible by `is_anonymous` and by the `anonymous` method in its token's `amr`.
	let mut u = user::new_user("", "", None, &aud, Some(data));
	u.is_anonymous = true;
	create_user(&tx, &mut u, &cfg.jwt_default_group).await?;
	let mut headers = HeaderMap::new();
	let body = issue_session(
		app,
		&tx,
		req,
		&mut headers,
		&mut u,
		ANONYMOUS,
		Grant::default(),
	)
	.await?;
	tx.commit()
		.await
		.map_err(db("Database error creating anonymous user"))?;
	Ok(with_headers(crate::json::ok(&body), headers))
}

/// The `amr` method of a guest's session.
pub const ANONYMOUS: &str = "anonymous";

/// What a repeated sign-up returns: a user that looks new and holds nothing real.
fn obfuscated(u: &user::User, email: &str, aud: &str, data: &Map<String, Value>) -> Value {
	let mut fake = u.clone();
	let now = crate::json::now();
	fake.id = uuid::Uuid::new_v4();
	fake.role.clear();
	fake.email_change.clear();
	fake.created_at = now;
	fake.updated_at = now;
	fake.confirmation_sent_at = Some(now);
	fake.last_sign_in_at = None;
	fake.confirmed_at = None;
	fake.email_change_sent_at = None;
	fake.email_confirmed_at = None;
	fake.phone_confirmed_at = None;
	fake.identities.clear();
	fake.factors.clear();
	fake.user_metadata = Some(data.clone());
	fake.aud = aud.to_string();
	let mut app_meta = Map::new();
	app_meta.insert("provider".into(), json!("email"));
	app_meta.insert("providers".into(), json!(["email"]));
	fake.app_metadata = Some(app_meta);
	fake.email = email.to_string();
	fake.phone.clear();
	fake.to_json()
}

/// Insert the user, then give them the default role, and read the row back.
pub async fn create_user<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
	role: &str,
) -> ApiResult<()> {
	user::insert(tx, u).await.map_err(|e| {
		// Another request made this user between our look and our insert: the caller retries
		// once (is_race) and then takes the path a second, later request would.
		if e.as_db_error().and_then(|d| d.constraint()) == Some("users_email_partial_key") {
			ApiError::new(
				409,
				RACE,
				"A user with this email address has already been registered",
			)
		} else {
			db("Database error saving new user")(e)
		}
	})?;
	u.role = role.trim().to_string();
	user::update(tx, u, &["role"])
		.await
		.map_err(db("Database error updating user"))?;
	user::reload(tx, u)
		.await
		.map_err(db("Database error loading user after sign-up"))?;
	Ok(())
}

/// Confirm the user's email now.
pub async fn confirm<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
) -> ApiResult<()> {
	u.confirmation_token.clear();
	u.email_confirmed_at = Some(crate::json::now());
	user::update(tx, u, &["confirmation_token", "email_confirmed_at"])
		.await
		.map_err(db("Database error updating user"))?;
	let mut upd = Map::new();
	upd.insert("email_verified".into(), json!(true));
	u.merge_user_metadata(&upd);
	user::update(tx, u, &["raw_user_meta_data"])
		.await
		.map_err(db("Database error updating user"))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(db("Database error updating user"))?;
	user::reload(tx, u)
		.await
		.map_err(db("Database error updating user"))?;
	Ok(())
}

/// A user not yet confirmed keeps only the identity just used: whoever registered the address
/// before without confirming it does not get to keep a way in.
pub async fn remove_unconfirmed_identities<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
	keep: &identity::Identity,
) -> ApiResult<()> {
	if keep.provider != "email" && keep.provider != "phone" {
		u.encrypted_password = None;
		user::update(tx, u, &["encrypted_password"])
			.await
			.map_err(db("Database error updating user"))?;
	}
	u.user_metadata = Some(keep.identity_data.clone());
	user::update(tx, u, &["raw_user_meta_data"])
		.await
		.map_err(db("Database error updating user"))?;
	for other in u.identities.iter().filter(|i| i.id != keep.id) {
		tx.execute("delete from identities where id = $1", &[&other.id])
			.await
			.map_err(db("Database error updating user"))?;
	}
	set_providers(tx, u).await
}

/// `app_metadata.providers` from the user's identities, and `provider` the first of them.
pub async fn set_providers<C: deadpool_postgres::GenericClient>(
	tx: &C,
	u: &mut user::User,
) -> ApiResult<()> {
	let providers = identity::providers(tx, u.id)
		.await
		.map_err(db("Database error updating user"))?;
	let mut upd = Map::new();
	if let Some(first) = providers.first() {
		upd.insert("provider".into(), json!(first));
	}
	upd.insert("providers".into(), json!(providers));
	u.merge_app_metadata(&upd);
	user::update(tx, u, &["raw_app_meta_data"])
		.await
		.map_err(db("Database error updating user"))?;
	Ok(())
}

/// The user who already has this address (through an identity or their own row), other than `me`.
pub async fn duplicate_email<C: deadpool_postgres::GenericClient>(
	tx: &C,
	email: &str,
	aud: &str,
	me: Option<uuid::Uuid>,
) -> ApiResult<Option<user::User>> {
	let ids = identity::by_email(tx, email)
		.await
		.map_err(db("unable to find identity by email for duplicates"))?;
	let mut seen = Vec::new();
	for i in ids {
		if i.provider.starts_with("sso:") || seen.contains(&i.user_id) || Some(i.user_id) == me {
			continue;
		}
		seen.push(i.user_id);
		if let Some(u) = user::by_id(tx, i.user_id)
			.await
			.map_err(db("unable to find user from email identity for duplicates"))?
			&& u.aud == aud
		{
			return Ok(Some(u));
		}
	}
	let u = user::by_email(tx, email, aud)
		.await
		.map_err(db("unable to find user email address for duplicates"))?;
	Ok(u.filter(|u| Some(u.id) != me))
}
