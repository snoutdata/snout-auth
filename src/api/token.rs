//! `POST /token`: exchanging a password, a refresh token, a PKCE code or a provider's ID token
//! for a session. And the one place sessions and access tokens are issued.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{App, Req, Shared};
use crate::crypto::{self, SignedRefreshToken};
use crate::error::{ApiError, ApiResult, db};
use crate::models::{session, token as tok, user};

pub async fn token(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = grant(&app, &req).await;
	req.respond(r)
}

async fn grant(app: &App, req: &Req) -> ApiResult<Response> {
	let grant_type = req.form_value("grant_type");
	match grant_type.as_str() {
		"password" | "refresh_token" | "id_token" | "pkce" => {}
		_ => {
			return Err(ApiError::bad_request(
				"invalid_credentials",
				"unsupported_grant_type",
			));
		}
	}
	super::limit(app, req, &app.limits.token)?;
	match grant_type.as_str() {
		"password" => password(app, req).await,
		"refresh_token" => refresh(app, req).await,
		"pkce" => pkce(app, req).await,
		_ => super::external::id_token_grant(app, req).await,
	}
}

pub const INVALID_LOGIN: &str = "Invalid login credentials";

async fn password(app: &App, req: &Req) -> ApiResult<Response> {
	let p = req.params()?;
	let email = p.str("email")?;
	let phone = p.str("phone")?;
	let password = p.str("password")?;
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());
	let cfg = &app.config;
	if !email.is_empty() && !phone.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Only an email address or phone number should be provided on login.",
		));
	}
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let (found, provider) = if !email.is_empty() {
		if !cfg.email_enabled {
			return Err(ApiError::unprocessable(
				"email_provider_disabled",
				"Email logins are disabled",
			));
		}
		(
			user::by_email(&conn, &email, &aud)
				.await
				.map_err(db("Database error querying schema"))?,
			"email",
		)
	} else if !phone.is_empty() {
		return Err(ApiError::unprocessable(
			"phone_provider_disabled",
			"Phone logins are disabled",
		));
	} else {
		return Err(ApiError::bad_request(
			"validation_failed",
			"missing email or phone",
		));
	};
	let Some(mut u) = found else {
		// The same work a real comparison costs, so the answer's timing does not say whether the
		// address has an account.
		crypto::verify_nothing(&password);
		return Err(ApiError::bad_request("invalid_credentials", INVALID_LOGIN));
	};
	if !u.has_password() {
		crypto::verify_nothing(&password);
		return Err(ApiError::bad_request("invalid_credentials", INVALID_LOGIN));
	}
	if u.is_banned() {
		return Err(ApiError::bad_request("user_banned", "User is banned"));
	}
	let hash = u.encrypted_password.clone().unwrap_or_default();
	let pw = password.clone();
	let valid = tokio::task::spawn_blocking(move || crypto::verify_password(&hash, &pw))
		.await
		.unwrap_or(false);
	let mut weak = None;
	if valid {
		if let Err(e) = super::signup::check_password(cfg, &password)
			&& let crate::error::ErrorKind::WeakPassword { reasons } = &*e.kind
		{
			weak = Some(json!({ "message": e.message, "reasons": reasons }));
		}
		// A hash at a cost other than ours is replaced now that the password is known.
		let cost = crypto::bcrypt_cost(u.encrypted_password.as_deref().unwrap_or(""));
		if cost.is_some_and(|c| c > 10 || c == 4) {
			let pw = password.clone();
			u.encrypted_password = Some(
				tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
					.await
					.unwrap_or_default(),
			);
			user::update(&conn, &mut u, &["encrypted_password"])
				.await
				.map_err(db("Database error updating user"))?;
		}
	}
	if !valid {
		return Err(ApiError::bad_request("invalid_credentials", INVALID_LOGIN));
	}
	if !u.is_confirmed() {
		return Err(ApiError::bad_request(
			"email_not_confirmed",
			"Email not confirmed",
		));
	}
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error granting user"))?;
	audit(
		&tx,
		&u,
		"login",
		req,
		Some(traits(&[("provider", provider)])),
	)
	.await?;
	let mut headers = HeaderMap::new();
	let mut resp = issue_session(
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
		.map_err(db("Database error granting user"))?;
	// Always present on a password sign-in: null when the password meets the policy.
	resp.as_object_mut()
		.expect("object")
		.insert("weak_password".into(), weak.unwrap_or(Value::Null));
	Ok(with_headers(crate::json::ok(&resp), headers))
}

async fn pkce(app: &App, req: &Req) -> ApiResult<Response> {
	let p = req.params()?;
	let code = p.str("auth_code")?;
	let verifier = p.str("code_verifier")?;
	if code.is_empty() || verifier.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"invalid request: both auth code and code verifier should be non-empty",
		));
	}
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error granting user"))?;
	// Taken, not read: two exchanges of the same code cannot both succeed.
	let Some(flow) = tok::take_flow_by_auth_code(&tx, &code)
		.await
		.map_err(db("Database error finding flow state"))?
	else {
		return Err(ApiError::not_found(
			"flow_state_not_found",
			"invalid flow state, no valid flow state found",
		));
	};
	let Some(user_id) = flow.user_id else {
		return Err(ApiError::not_found(
			"flow_state_not_found",
			"invalid flow state, no valid flow state found",
		));
	};
	if flow.is_expired(app.config.flow_state_expiry) {
		return Err(ApiError::unprocessable(
			"flow_state_expired",
			"invalid flow state, flow state has expired",
		));
	}
	let mut u = user::by_id(&tx, user_id)
		.await
		.map_err(db("Database error finding user"))?
		.ok_or_else(|| ApiError::internal("user not found"))?;
	if let Err(why) = flow.verify_pkce(&verifier) {
		return Err(ApiError::bad_request("bad_code_verifier", why));
	}
	let method = if flow.authentication_method.ends_with("signup") {
		"email/signup".to_string()
	} else {
		flow.authentication_method.clone()
	};
	audit(
		&tx,
		&u,
		"login",
		req,
		Some(traits(&[("provider_type", &flow.provider_type)])),
	)
	.await?;
	let mut headers = HeaderMap::new();
	let mut resp = issue_session(
		app,
		&tx,
		req,
		&mut headers,
		&mut u,
		&method,
		Grant::default(),
	)
	.await?;
	tx.commit()
		.await
		.map_err(db("Database error granting user"))?;
	let o = resp.as_object_mut().expect("object");
	if !flow.provider_access_token.is_empty() {
		o.insert("provider_token".into(), json!(flow.provider_access_token));
	}
	if !flow.provider_refresh_token.is_empty() {
		o.insert(
			"provider_refresh_token".into(),
			json!(flow.provider_refresh_token),
		);
	}
	Ok(with_headers(crate::json::ok(&resp), headers))
}

// ------------------------------------------------------------------------------------------
// Refresh.

enum Presented {
	/// A twelve-character token, stored as a row.
	Stored(session::RefreshToken),
	/// A signed token carrying its session and a counter.
	Signed(SignedRefreshToken),
}

/// The user, the token and its session, when the token is one of ours. `lock` takes the session
/// (and a stored token's row) for this transaction, or reports not-found when another has them.
async fn find_by_refresh<C: GenericClient>(
	conn: &C,
	token: &str,
	lock: bool,
) -> ApiResult<Option<(user::User, Presented, Option<session::Session>)>> {
	if token.len() < 12 {
		return Ok(None);
	}
	if token.len() == 12 {
		let Some(rt) = session::token_by_value(conn, token, lock)
			.await
			.map_err(db("error finding refresh token"))?
		else {
			return Ok(None);
		};
		// The user and the session both hang off the token and not off each other: one round trip.
		let sid = rt.session_id.filter(|s| !s.is_nil());
		let (u, sess) = tokio::try_join!(
			async {
				user::by_id(conn, rt.user_id)
					.await
					.map_err(db("error finding user"))
			},
			async {
				match sid {
					Some(sid) if lock => session::by_id_for_update(conn, sid)
						.await
						.map_err(db("error finding session")),
					Some(sid) => session::by_id(conn, sid)
						.await
						.map_err(db("error finding session")),
					None => Ok(None),
				}
			},
		)?;
		let Some(u) = u else {
			return Ok(None);
		};
		if sid.is_some() && sess.is_none() && lock {
			return Ok(None);
		}
		return Ok(Some((u, Presented::Stored(rt), sess)));
	}
	let Some(signed) = SignedRefreshToken::parse(token) else {
		return Ok(None);
	};
	let sess = if lock {
		session::by_id_for_update(conn, signed.session_id)
			.await
			.map_err(db("error finding session"))?
	} else {
		session::by_id(conn, signed.session_id)
			.await
			.map_err(db("error finding session"))?
	};
	let Some(sess) = sess else {
		return Ok(None);
	};
	let (Some(key), Some(_)) = (
		sess.refresh_token_hmac_key
			.as_deref()
			.and_then(crypto::decode_hmac_key),
		sess.refresh_token_counter,
	) else {
		return Ok(None);
	};
	if !signed.check(&key) {
		return Ok(None);
	}
	let Some(u) = user::by_id(conn, sess.user_id)
		.await
		.map_err(db("error finding user"))?
	else {
		return Ok(None);
	};
	Ok(Some((u, Presented::Signed(signed), Some(sess))))
}

fn refresh_error(code: &str, message: &str) -> ApiError {
	ApiError::bad_request(code, message)
}

async fn refresh(app: &App, req: &Req) -> ApiResult<Response> {
	let p = req.params()?;
	let token = p.str("refresh_token")?;
	let well_formed = match token.len() {
		0..12 => false,
		12 => token
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
		_ => SignedRefreshToken::parse(&token).is_some(),
	};
	if !well_formed {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Refresh token is not valid",
		));
	}
	let cfg = &app.config;
	let started = std::time::Instant::now();
	let start_time = OffsetDateTime::now_utc();
	let mut headers = HeaderMap::new();
	loop {
		if started.elapsed() > Duration::from_secs(5) {
			return Err(ApiError::conflict(
				"Too many concurrent token refresh requests on the same session or refresh token",
			));
		}
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Database error refreshing"))?;
		// The common case reads once, locked. Nothing locked comes back when the token is unknown,
		// its session is gone, or another refresh holds the rows; the unlocked read below tells
		// those apart and refuses each exactly as it would have been refused before the lock.
		let locked = match find_by_refresh(&tx, &token, true).await? {
			Some((u, presented, Some(sess))) => Some((u, presented, sess)),
			_ => None,
		};
		let Some((mut u, presented, sess)) = locked else {
			drop(tx);
			let Some((u, presented, sess)) = find_by_refresh(&conn, &token, false).await? else {
				return Err(refresh_error(
					"refresh_token_not_found",
					"Invalid Refresh Token: Refresh Token Not Found",
				));
			};
			vet_user(&u, &mut headers)?;
			let Some(sess) = sess else {
				if let Presented::Stored(rt) = &presented {
					session::delete_token(&conn, rt.id)
						.await
						.map_err(db("Error deleting refresh token with missing session"))?;
				}
				return Err(refresh_error(
					"session_not_found",
					"Invalid Refresh Token: No Valid Session Found",
				));
			};
			vet_session(cfg, start_time, &u, &presented, &sess, &mut headers)?;
			// Found, valid, and held by another refresh. Try again shortly.
			drop(conn);
			tokio::time::sleep(Duration::from_millis(10 + rand::random::<u64>() % 20)).await;
			continue;
		};
		vet_user(&u, &mut headers)?;
		vet_session(cfg, start_time, &u, &presented, &sess, &mut headers)?;

		let issued: String;
		// Whether this refresh writes the user row. That row is the one lock a refresh shares with
		// every other refresh of the same person (one per device), so it is written last, beside
		// the session's own row, and held for no more than that write and the commit.
		let mut touch_user = false;
		match presented {
			Presented::Stored(mut rt) => {
				let mut reuse = None;
				if rt.revoked {
					let active = session::active_token(&tx, sess.id)
						.await
						.map_err(db("Database error finding token"))?;
					if active.as_ref().is_some_and(|a| a.parent == rt.token) {
						// The client never stored the answer to its last refresh: give it that one.
						reuse = active.map(|a| a.token);
					} else {
						let reuse_until = rt.updated_at
							+ Duration::from_secs(cfg.refresh_reuse_interval.max(0) as u64);
						if OffsetDateTime::now_utc() > reuse_until {
							if cfg.refresh_rotation {
								session::revoke_family(&tx, &rt)
									.await
									.map_err(db("Database error revoking tokens"))?;
							}
							tx.commit()
								.await
								.map_err(db("Database error revoking tokens"))?;
							tracing::warn!(
								token_id = rt.id,
								"a revoked refresh token was presented after its reuse window"
							);
							return Err(refresh_error(
								"refresh_token_already_used",
								"Invalid Refresh Token: Already Used",
							));
						}
					}
				}
				issued = match reuse {
					Some(t) => {
						audit(&tx, &u, "token_refreshed", req, None).await?;
						t
					}
					None => {
						// The two audit entries, and the token revoked with its successor issued: two
						// statements that depend on nothing but what is already read, sent together.
						let (_, new) = tokio::try_join!(
							audit_pair(&tx, &u, ["token_refreshed", "token_revoked"], req),
							async {
								session::revoke_and_issue(&tx, &mut rt, u.id, sess.id)
									.await
									.map_err(db("Database error granting user"))
							},
						)?;
						touch_user = true;
						set(&mut headers, "sb-auth-refresh-token-reuse", "false");
						new.token
					}
				};
				set(
					&mut headers,
					"sb-auth-refresh-token-prefix",
					&issued[..5.min(issued.len())],
				);
			}
			Presented::Signed(signed) => {
				let key = sess
					.refresh_token_hmac_key
					.as_deref()
					.and_then(crypto::decode_hmac_key)
					.unwrap_or_default();
				let current = sess.refresh_token_counter.unwrap_or(0);
				let behind = current - signed.counter;
				let mut counter = current;
				if behind < 0 {
					return Err(ApiError::bad_request(
						"validation_failed",
						"Invalid Refresh Token: Not Issued By This Server",
					));
				} else if behind == 0 {
					counter += 1;
					set(&mut headers, "sb-auth-refresh-token-reuse", "false");
				} else {
					let not_saved = behind == 1;
					let concurrent = (start_time - sess.last_refreshed(None)).abs()
						< Duration::from_secs(cfg.refresh_reuse_interval.max(0) as u64);
					let mut causes = vec![];
					if concurrent {
						causes.push("concurrent-refresh");
					}
					if not_saved {
						causes.push("fail-to-save");
					}
					if !causes.is_empty() {
						set(
							&mut headers,
							"sb-auth-refresh-token-reuse-cause",
							&causes.join(","),
						);
					}
					if !(not_saved || concurrent) {
						if cfg.refresh_rotation {
							session::delete(&tx, sess.id).await.map_err(db(
								"destroying session after detected refresh token reuse failed",
							))?;
							set(&mut headers, "sb-auth-refresh-token-rotated", "true");
						}
						tx.commit().await.map_err(db("Database error"))?;
						return Err(refresh_error(
							"refresh_token_already_used",
							"Invalid Refresh Token: Already Used",
						));
					}
				}
				issued = SignedRefreshToken::encode(sess.id, counter, &key);
				tokio::try_join!(
					async {
						session::set_counter(&tx, sess.id, counter)
							.await
							.map_err(db("failed saving session"))
					},
					audit(&tx, &u, "token_refreshed", req, None),
				)?;
				set(
					&mut headers,
					"sb-auth-refresh-token-counter",
					&counter.to_string(),
				);
			}
		}
		// The session read under the lock is the one the token is for; its claims have not moved.
		let (access, expires_at) = access_token_for(app, &u, &sess);
		let ua = req.header("user-agent").to_string();
		let ip = req.ip();
		if touch_user {
			session::update_refresh_info_and_user(&tx, sess.id, &ua, &ip, &mut u)
				.await
				.map_err(db("Database error granting user"))?;
		} else {
			session::update_refresh_info(&tx, sess.id, &ua, &ip)
				.await
				.map_err(db("failed to update session information"))?;
		}
		tx.commit().await.map_err(db("Database error refreshing"))?;
		let body = token_response(&access, expires_at, &issued, &u);
		return Ok(with_headers(crate::json::ok(&body), headers));
	}
}

/// A refresh for a banned user is refused, and says whose it was.
fn vet_user(u: &user::User, headers: &mut HeaderMap) -> ApiResult<()> {
	set(headers, "sb-auth-user-id", &u.id.to_string());
	if u.is_banned() {
		return Err(refresh_error(
			"user_banned",
			"Invalid Refresh Token: User Banned",
		));
	}
	Ok(())
}

/// A refresh of a session past its inactivity limit or its lifetime is refused.
fn vet_session(
	cfg: &crate::config::Config,
	start_time: OffsetDateTime,
	u: &user::User,
	presented: &Presented,
	sess: &session::Session,
	headers: &mut HeaderMap,
) -> ApiResult<()> {
	set(headers, "sb-auth-session-id", &sess.id.to_string());
	let token_time = match presented {
		Presented::Stored(rt) => Some(rt.updated_at),
		Presented::Signed(_) => None,
	};
	match sess.validity(cfg, start_time, token_time, u.highest_aal()) {
		session::Validity::Valid => Ok(()),
		session::Validity::TimedOut => Err(refresh_error(
			"session_expired",
			"Invalid Refresh Token: Session Expired (Inactivity)",
		)),
		_ => Err(refresh_error(
			"session_expired",
			"Invalid Refresh Token: Session Expired",
		)),
	}
}

// ------------------------------------------------------------------------------------------
// Issuing.

#[derive(Default, Clone)]
pub struct Grant<'a> {
	pub factor_id: Option<Uuid>,
	pub not_after: Option<OffsetDateTime>,
	pub tag: Option<&'a str>,
}

/// A new session for `u`, authenticated by `method`, with its refresh token and access token.
/// The user's last sign-in is now.
pub async fn issue_session<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	headers: &mut HeaderMap,
	u: &mut user::User,
	method: &str,
	grant: Grant<'_>,
) -> ApiResult<Value> {
	set(headers, "sb-auth-user-id", &u.id.to_string());
	let ua = req.header("user-agent").to_string();
	let ip = req.ip();
	let sid = session::insert(
		tx,
		&session::NewSession {
			user_id: u.id,
			factor_id: grant.factor_id,
			not_after: grant.not_after,
			user_agent: &ua,
			ip: &ip,
			tag: grant.tag,
			hmac_key: None,
		},
	)
	.await
	.map_err(db("Database error granting user"))?;
	let rt = session::insert_token(tx, u.id, sid, None)
		.await
		.map_err(db("Database error granting user"))?;
	u.last_sign_in_at = Some(crate::json::now());
	user::update(tx, u, &["last_sign_in_at"])
		.await
		.map_err(db("Database error granting user"))?;
	set(headers, "sb-auth-session-id", &sid.to_string());
	set(headers, "sb-auth-refresh-token-prefix", &rt.token[..5]);
	session::add_claim(tx, sid, method)
		.await
		.map_err(db("Database error granting user"))?;
	let (access, expires_at) = access_token(app, tx, u, sid).await?;
	Ok(token_response(&access, expires_at, &rt.token, u))
}

/// An access token for `u` in session `session_id`, and when it expires.
pub async fn access_token<C: GenericClient>(
	app: &App,
	tx: &C,
	u: &user::User,
	session_id: Uuid,
) -> ApiResult<(String, i64)> {
	let sess = session::by_id(tx, session_id)
		.await
		.map_err(db("Database error finding session"))?
		.ok_or_else(|| ApiError::internal("Session is required to issue access token"))?;
	Ok(access_token_for(app, u, &sess))
}

/// An access token for `u` in a session already read, and when it expires.
pub fn access_token_for(app: &App, u: &user::User, sess: &session::Session) -> (String, i64) {
	let cfg = &app.config;
	let session_id = sess.id;
	let (aal, amr) = sess.aal_and_amr(u);
	let now = OffsetDateTime::now_utc().unix_timestamp();
	let exp = now + cfg.jwt_exp;
	let claims = crate::jwt::access_claims(
		&cfg.jwt_issuer,
		&u.id.to_string(),
		&u.aud,
		exp,
		now,
		&u.email,
		&u.phone,
		&u.app_metadata_value(),
		&u.user_metadata_value(),
		&u.role,
		aal,
		&amr,
		&session_id.to_string(),
		u.is_anonymous,
	);
	(crate::jwt::sign(&claims, &cfg.jwt_secret), exp)
}

pub fn token_response(access: &str, expires_at: i64, refresh: &str, u: &user::User) -> Value {
	let mut m = Map::new();
	m.insert("access_token".into(), json!(access));
	m.insert("token_type".into(), json!("bearer"));
	m.insert(
		"expires_in".into(),
		json!(expires_at - OffsetDateTime::now_utc().unix_timestamp()),
	);
	m.insert("expires_at".into(), json!(expires_at));
	m.insert("refresh_token".into(), json!(refresh));
	m.insert("user".into(), u.to_json());
	Value::Object(m)
}

/// The same answer as a URL fragment, for a redirect back to the application.
pub fn as_fragment(redirect_to: &str, body: &Value, extra: &[(&str, &str)]) -> String {
	let mut ser = url::form_urlencoded::Serializer::new(String::new());
	let s = |k: &str| {
		body.get(k)
			.map(|v| {
				v.as_str()
					.map(str::to_string)
					.unwrap_or_else(|| v.to_string())
			})
			.unwrap_or_default()
	};
	let mut pairs: Vec<(String, String)> = vec![
		("access_token".into(), s("access_token")),
		("expires_at".into(), s("expires_at")),
		("expires_in".into(), s("expires_in")),
		("refresh_token".into(), s("refresh_token")),
		("sb".into(), String::new()),
		("token_type".into(), s("token_type")),
	];
	for (k, v) in extra {
		pairs.push((k.to_string(), v.to_string()));
	}
	pairs.sort_by(|a, b| a.0.cmp(&b.0));
	for (k, v) in pairs {
		ser.append_pair(&k, &v);
	}
	format!("{redirect_to}#{}", ser.finish())
}

pub fn set(h: &mut HeaderMap, k: &'static str, v: &str) {
	if let Ok(v) = HeaderValue::from_str(v) {
		h.insert(k, v);
	}
}

pub fn with_headers(mut r: Response, h: HeaderMap) -> Response {
	for (k, v) in h.iter() {
		r.headers_mut().insert(k.clone(), v.clone());
	}
	r
}

pub fn traits(pairs: &[(&str, &str)]) -> Map<String, Value> {
	pairs
		.iter()
		.map(|(k, v)| (k.to_string(), json!(v)))
		.collect()
}

/// Who `u` is in an audit entry: the phone or else the email, and the full name when there is one.
fn actor(u: &user::User) -> (String, Option<Value>) {
	let username = if !u.phone.is_empty() {
		u.phone.clone()
	} else {
		u.email.clone()
	};
	let name = u
		.user_metadata
		.as_ref()
		.and_then(|m| m.get("full_name"))
		.cloned();
	(username, name)
}

/// Two audit entries for `u`, in this order, in one statement.
async fn audit_pair<C: GenericClient>(
	db_: &C,
	u: &user::User,
	actions: [&str; 2],
	req: &Req,
) -> ApiResult<()> {
	let (username, name) = actor(u);
	tok::audit_pair(
		db_,
		u.id,
		&username,
		u.is_sso_user,
		name.as_ref(),
		actions,
		&req.ip(),
	)
	.await
	.map_err(db("Database error creating audit log entry"))
}

/// One audit entry for `u`, with the caller's address.
pub async fn audit<C: GenericClient>(
	db_: &C,
	u: &user::User,
	action: &str,
	req: &Req,
	traits: Option<Map<String, Value>>,
) -> ApiResult<()> {
	let (username, name) = actor(u);
	tok::audit(
		db_,
		u.id,
		&username,
		u.is_sso_user,
		name.as_ref(),
		action,
		&req.ip(),
		traits,
	)
	.await
	.map_err(db("Database error creating audit log entry"))
}
