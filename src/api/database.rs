//! Database tokens over HTTP: the issuer libpq 18's `oauth` sign-in talks to (RFC 8628, the
//! device grant), and the two calls a signed-in person approves a sign-in with.
//!
//!   GET  /.well-known/openid-configuration      the issuer's metadata (libpq reads this one)
//!   GET  /.well-known/oauth-authorization-server  the same document (RFC 8414)
//!   GET  /db/jwks                                 the public keys databases check tokens with
//!   POST /db/device                               device authorization (RFC 8628 §3.1)
//!   POST /db/token                                the device_code grant (RFC 8628 §3.4)
//!   POST /db/device/lookup                        what a typed code would approve
//!   POST /db/device/approve                       approve or turn down a typed code
//!
//! Routed only when `AUTH_DATABASE_TOKENS_ENABLED` is true. Off, every one of these paths answers
//! exactly what it answered before they existed.
//!
//! The person never types which project: the database's `pg_hba` line puts `db:<ref>` in its
//! scope, libpq sends that scope to `/db/device`, and the token's audience is that ref. The
//! role is never the client's to choose either: the access function names it.

use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::Response;
use serde_json::json;
use uuid::Uuid;

use super::token::{audit, traits};
use super::{App, Req, Shared};
use crate::config::DatabaseTokens;
use crate::dbtoken::{self, Poll};
use crate::error::{ApiError, ApiResult, db};
use crate::models::device::{self, NewDevice};
use crate::models::{session, user};

fn settings(app: &App) -> &DatabaseTokens {
	app.config
		.database_tokens
		.as_ref()
		.expect("routed only when database tokens are on")
}

/// An OAuth response must never be cached (RFC 6749 §5.1).
fn no_store(mut r: Response) -> Response {
	let h = r.headers_mut();
	h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
	h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
	r
}

pub async fn discovery(State(app): Shared) -> Response {
	let mut r = crate::json::ok(&dbtoken::discovery(&settings(&app).issuer));
	r.headers_mut().insert(
		header::CACHE_CONTROL,
		HeaderValue::from_static("public, max-age=300"),
	);
	r
}

/// The DATABASE keys, apart from `/.well-known/jwks.json` (the session keys) on purpose: whatever
/// trusts one set must never be handed the other.
pub async fn jwks(State(app): Shared) -> Response {
	let mut r = crate::json::ok(&settings(&app).keys.jwks());
	r.headers_mut().insert(
		header::CACHE_CONTROL,
		HeaderValue::from_static("public, max-age=300"),
	);
	r
}

/// The body's form fields (RFC 6749 §3.2: urlencoded, each at most once). Never the query
/// string: a device code in a URL is a device code in an access log.
fn form(req: &Req) -> ApiResult<Vec<(String, String)>> {
	if !req
		.header("content-type")
		.to_ascii_lowercase()
		.starts_with("application/x-www-form-urlencoded")
	{
		return Err(ApiError::oauth(
			"invalid_request",
			"the body must be application/x-www-form-urlencoded",
		));
	}
	let fields: Vec<(String, String)> = url::form_urlencoded::parse(&req.body)
		.map(|(k, v)| (k.into_owned(), v.into_owned()))
		.collect();
	for (i, (k, _)) in fields.iter().enumerate() {
		if fields[..i].iter().any(|(seen, _)| seen == k) {
			return Err(ApiError::oauth(
				"invalid_request",
				format!("{k} is given more than once"),
			));
		}
	}
	Ok(fields)
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
	fields
		.iter()
		.find(|(k, _)| k == name)
		.map(|(_, v)| v.as_str())
		.unwrap_or("")
}

/// The public client asking: named in the body, and one this server was told to accept.
fn client<'a>(s: &DatabaseTokens, fields: &'a [(String, String)]) -> ApiResult<&'a str> {
	let id = field(fields, "client_id");
	if id.is_empty() {
		return Err(ApiError::oauth("invalid_request", "client_id is required"));
	}
	if !s.client_ids.iter().any(|c| c == id) {
		return Err(ApiError::oauth_with_status(
			401,
			"invalid_client",
			"unknown client_id",
		));
	}
	Ok(id)
}

// ------------------------------------------------------------------------------------------
// The device grant.

pub async fn device_authorization(State(app): Shared, req: Req) -> Response {
	let r = start(&app, &req).await;
	no_store(req.respond(r))
}

async fn start(app: &App, req: &Req) -> ApiResult<Response> {
	super::limit(app, req, &app.limits.database_device)?;
	let s = settings(app);
	let fields = form(req)?;
	let client_id = client(s, &fields)?;
	let scope = field(&fields, "scope");
	let project_ref =
		dbtoken::project_from_scope(scope).map_err(|why| ApiError::oauth("invalid_scope", why))?;

	let conn = app.pool.get().await.map_err(super::pool_error)?;
	let now = crate::json::now();
	device::sweep(&conn, now)
		.await
		.map_err(db("Database error starting a database sign-in"))?;
	let expires_at = now + s.device_code_expiry;
	let interval = s.poll_interval.as_secs() as i32;
	// Two codes, each drawn from enough bits that a collision is not a real event; a few draws
	// is what refuses to loop forever if something else is wrong.
	for _ in 0..3 {
		let device_code = dbtoken::new_device_code();
		let user_code = dbtoken::new_user_code();
		let inserted = device::insert(
			&conn,
			&NewDevice {
				device_code_hash: &dbtoken::code_hash(&device_code),
				user_code_hash: &dbtoken::code_hash(&user_code),
				client_id,
				project_ref: &project_ref,
				scope,
				ip_address: &req.ip(),
				user_agent: req.header("user-agent"),
				created_at: now,
				expires_at,
				poll_interval: interval,
			},
		)
		.await
		.map_err(db("Database error starting a database sign-in"))?;
		if inserted {
			tracing::info!(client_id, project_ref, "database sign-in started");
			return Ok(crate::json::ok(&json!({
				"device_code": device_code,
				"user_code": dbtoken::format_user_code(&user_code),
				// A page, never a link with the code in it: the code is typed, so the person at
				// the browser is the person at the terminal.
				"verification_uri": s.verification_uri,
				"expires_in": s.device_code_expiry.as_secs(),
				"interval": interval,
			})));
		}
	}
	Err(ApiError::internal("Could not start a database sign-in"))
}

pub async fn token(State(app): Shared, req: Req) -> Response {
	let r = grant(&app, &req).await;
	no_store(req.respond(r))
}

async fn grant(app: &App, req: &Req) -> ApiResult<Response> {
	super::limit(app, req, &app.limits.database_token)?;
	let s = settings(app);
	let fields = form(req)?;
	match field(&fields, "grant_type") {
		"" => return Err(ApiError::oauth("invalid_request", "grant_type is required")),
		dbtoken::DEVICE_GRANT => {}
		_ => {
			return Err(ApiError::oauth(
				"unsupported_grant_type",
				"only the device_code grant is served here",
			));
		}
	}
	let client_id = client(s, &fields)?;
	let device_code = field(&fields, "device_code");
	if device_code.is_empty() {
		return Err(ApiError::oauth(
			"invalid_request",
			"device_code is required",
		));
	}

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error issuing a database token"))?;
	let Some(d) = device::by_device_code_for_update(&tx, &dbtoken::code_hash(device_code))
		.await
		.map_err(db("Database error issuing a database token"))?
	else {
		return Err(ApiError::oauth("invalid_grant", "unknown device_code"));
	};
	let now = crate::json::now();
	match dbtoken::poll(&d.pending(), client_id, now) {
		Poll::InvalidGrant(why) => Err(ApiError::oauth("invalid_grant", why)),
		Poll::AccessDenied => Err(ApiError::oauth(
			"access_denied",
			"the sign-in was turned down",
		)),
		Poll::Expired => Err(ApiError::oauth(
			"expired_token",
			"the device code expired before it was approved",
		)),
		Poll::SlowDown => {
			device::polled(&tx, d.id, now, d.poll_interval.saturating_add(5))
				.await
				.map_err(db("Database error issuing a database token"))?;
			tx.commit()
				.await
				.map_err(db("Database error issuing a database token"))?;
			Err(ApiError::oauth(
				"slow_down",
				"polling too fast: wait five seconds longer between polls",
			))
		}
		Poll::Pending => {
			device::polled(&tx, d.id, now, d.poll_interval)
				.await
				.map_err(db("Database error issuing a database token"))?;
			tx.commit()
				.await
				.map_err(db("Database error issuing a database token"))?;
			Err(ApiError::oauth(
				"authorization_pending",
				"waiting for the sign-in to be approved",
			))
		}
		Poll::Issue => issue(req, s, tx, d, now).await,
	}
}

/// The code was approved: ask again whether this person may open this project, then issue.
/// Asked again because access is the control plane's to take away, and the approval may be
/// minutes old; the token is what lasts.
async fn issue(
	req: &Req,
	s: &DatabaseTokens,
	tx: deadpool_postgres::Transaction<'_>,
	d: device::Device,
	now: time::OffsetDateTime,
) -> ApiResult<Response> {
	let fail = db("Database error issuing a database token");
	let user_id = d
		.user_id
		.ok_or_else(|| ApiError::internal("an approved code with no approver"))?;
	let Some(u) = user::by_id(&tx, user_id).await.map_err(&fail)? else {
		return Err(ApiError::oauth(
			"access_denied",
			"the sign-in was turned down",
		));
	};
	let role = if u.is_banned() {
		None
	} else {
		device::access_role(&tx, &s.access_function, u.id, &d.project_ref)
			.await
			.map_err(&fail)?
	};
	let Some(role) = role.filter(|r| issuable(r, &d.project_ref)) else {
		device::deny_approved(&tx, d.id, now).await.map_err(&fail)?;
		audit(
			&tx,
			&u,
			"database_token_refused",
			req,
			Some(traits(&[
				("project_ref", &d.project_ref),
				("client_id", &d.client_id),
				(
					"reason",
					if u.is_banned() {
						"banned"
					} else {
						"no_database_access"
					},
				),
			])),
		)
		.await?;
		tx.commit().await.map_err(&fail)?;
		tracing::info!(project_ref = %d.project_ref, user = %u.id, "database token refused: no database access");
		return Err(ApiError::oauth(
			"access_denied",
			"this account has no database access to that project",
		));
	};
	let jti = Uuid::new_v4().to_string();
	let id = u.id.to_string();
	let claims = dbtoken::claims(
		&dbtoken::Grant {
			issuer: &s.issuer,
			user_id: &id,
			email: &u.email,
			project_ref: &d.project_ref,
			db_role: &role,
			client_id: &d.client_id,
			jti: &jti,
		},
		now.unix_timestamp(),
		s.lifetime,
	);
	let token = s
		.keys
		.sign(&claims)
		.map_err(|e| ApiError::internal("Could not sign the database token").with_internal(e))?;
	if !device::consume(&tx, d.id, now).await.map_err(&fail)? {
		return Err(ApiError::oauth(
			"invalid_grant",
			"the device code has already been used",
		));
	}
	audit(
		&tx,
		&u,
		"database_token_issued",
		req,
		Some(traits(&[
			("project_ref", &d.project_ref),
			("db_role", &role),
			("client_id", &d.client_id),
			("jti", &jti),
			("kid", s.keys.signing_kid()),
		])),
	)
	.await?;
	tx.commit().await.map_err(&fail)?;
	tracing::info!(project_ref = %d.project_ref, db_role = %role, user = %u.id, jti, "database token issued");
	Ok(crate::json::ok(&json!({
		"access_token": token,
		"token_type": "Bearer",
		"expires_in": s.lifetime.as_secs(),
		"scope": d.scope,
	})))
}

fn issuable(role: &str, project_ref: &str) -> bool {
	if dbtoken::is_issuable_role(role) {
		return true;
	}
	tracing::error!(
		project_ref,
		role,
		"the access function named a role that cannot go in a token; refused"
	);
	false
}

// ------------------------------------------------------------------------------------------
// The person's side: type the code, see what it opens, approve or turn it down.

/// The signed-in person deciding. A real session (not a service key, not a guest), still valid,
/// and at `aal2` when the account has a second factor: what a database token opens is worth at
/// least what the account's own sign-in demands.
async fn approver(app: &App, req: &Req) -> ApiResult<super::Caller> {
	let caller = super::authenticate(app, req).await?;
	let Some(sess) = &caller.session else {
		return Err(ApiError::forbidden(
			"session_required",
			"Approving a database sign-in needs a signed-in session",
		));
	};
	if sess.validity(
		&app.config,
		time::OffsetDateTime::now_utc(),
		None,
		caller.user.highest_aal(),
	) != session::Validity::Valid
	{
		return Err(ApiError::forbidden(
			"session_expired",
			"Session is no longer valid",
		));
	}
	if caller.user.is_anonymous {
		return Err(ApiError::forbidden(
			"anonymous_not_allowed",
			"A guest account cannot approve a database sign-in",
		));
	}
	if caller.user.has_mfa() && !sess.is_aal2() {
		return Err(ApiError::forbidden(
			"insufficient_aal",
			"Verify your second factor before approving a database sign-in",
		));
	}
	if app.db_code_misses.blocked(caller.user.id) {
		return Err(ApiError::too_many(
			"over_request_rate_limit",
			"Too many wrong codes. Wait a few minutes and try again.",
		));
	}
	Ok(caller)
}

/// The typed code, in its stored form. A code that is not even shaped like one is a miss.
fn typed_code(app: &App, caller: &super::Caller, req: &Req) -> ApiResult<String> {
	let typed = req.params()?.str("user_code")?;
	dbtoken::normalise_user_code(&typed).ok_or_else(|| {
		app.db_code_misses.miss(caller.user.id);
		ApiError::bad_request(
			"validation_failed",
			"A code is twelve letters and digits, as the terminal printed it",
		)
	})
}

fn not_found(app: &App, caller: &super::Caller) -> ApiError {
	app.db_code_misses.miss(caller.user.id);
	ApiError::not_found(
		"device_code_not_found",
		"No sign-in is waiting for that code. Check it against the terminal.",
	)
}

pub async fn lookup(State(app): Shared, req: Req) -> Response {
	let r = look(&app, &req).await;
	req.respond(r)
}

async fn look(app: &App, req: &Req) -> ApiResult<Response> {
	let s = settings(app);
	let caller = approver(app, req).await?;
	let code = typed_code(app, &caller, req)?;
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	let fail = db("Database error reading a database sign-in");
	let Some(d) = device::by_user_code(&conn, &dbtoken::code_hash(&code), false)
		.await
		.map_err(&fail)?
	else {
		return Err(not_found(app, &caller));
	};
	let now = crate::json::now();
	if let Err((status, code, message)) = dbtoken::decidable(
		d.approved_at.is_some(),
		d.denied_at.is_some(),
		d.consumed_at.is_some(),
		d.expires_at,
		now,
	) {
		return Err(ApiError::new(status, code, message));
	}
	let role = device::access_role(&conn, &s.access_function, caller.user.id, &d.project_ref)
		.await
		.map_err(&fail)?
		.filter(|r| dbtoken::is_issuable_role(r));
	Ok(crate::json::ok(&json!({
		"project_ref": d.project_ref,
		"client_id": d.client_id,
		"scope": d.scope,
		// What the requesting machine said about itself, for the person deciding. Not verified.
		"ip_address": d.ip_address,
		"user_agent": d.user_agent,
		"created_at": crate::json::time(d.created_at),
		"expires_at": crate::json::time(d.expires_at),
		"database_access": role.is_some(),
		"db_role": role,
	})))
}

pub async fn approve(State(app): Shared, req: Req) -> Response {
	let r = decide(&app, &req).await;
	req.respond(r)
}

async fn decide(app: &App, req: &Req) -> ApiResult<Response> {
	let s = settings(app);
	let caller = approver(app, req).await?;
	let approve = match req.params()?.str("decision")?.as_str() {
		"approve" => true,
		"deny" => false,
		_ => {
			return Err(ApiError::bad_request(
				"validation_failed",
				"decision must be approve or deny",
			));
		}
	};
	let code = typed_code(app, &caller, req)?;
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let fail = db("Database error deciding a database sign-in");
	let tx = conn.transaction().await.map_err(&fail)?;
	let Some(d) = device::by_user_code(&tx, &dbtoken::code_hash(&code), true)
		.await
		.map_err(&fail)?
	else {
		return Err(not_found(app, &caller));
	};
	let now = crate::json::now();
	if let Err((status, code, message)) = dbtoken::decidable(
		d.approved_at.is_some(),
		d.denied_at.is_some(),
		d.consumed_at.is_some(),
		d.expires_at,
		now,
	) {
		return Err(ApiError::new(status, code, message));
	}
	let base = [
		("project_ref", d.project_ref.as_str()),
		("client_id", d.client_id.as_str()),
	];
	if !approve {
		device::decide(&tx, d.id, caller.user.id, false, now)
			.await
			.map_err(&fail)?;
		audit(
			&tx,
			&caller.user,
			"database_device_denied",
			req,
			Some(traits(&base)),
		)
		.await?;
		tx.commit().await.map_err(&fail)?;
		return Ok(crate::json::ok(&json!({ "status": "denied" })));
	}
	let role = device::access_role(&tx, &s.access_function, caller.user.id, &d.project_ref)
		.await
		.map_err(&fail)?
		.filter(|r| issuable(r, &d.project_ref));
	let Some(role) = role else {
		// Turned down here rather than left pending, so the client stops polling now with
		// `access_denied` instead of waiting out the code.
		device::decide(&tx, d.id, caller.user.id, false, now)
			.await
			.map_err(&fail)?;
		let mut t = traits(&base);
		t.insert("reason".into(), json!("no_database_access"));
		audit(&tx, &caller.user, "database_token_refused", req, Some(t)).await?;
		tx.commit().await.map_err(&fail)?;
		return Err(ApiError::forbidden(
			"no_database_access",
			format!(
				"Your account has no database access to project {}. Ask the project's owner to give you access.",
				d.project_ref
			),
		));
	};
	device::decide(&tx, d.id, caller.user.id, true, now)
		.await
		.map_err(&fail)?;
	let mut t = traits(&base);
	t.insert("db_role".into(), json!(role));
	audit(&tx, &caller.user, "database_device_approved", req, Some(t)).await?;
	tx.commit().await.map_err(&fail)?;
	Ok(crate::json::ok(&json!({
		"status": "approved",
		"project_ref": d.project_ref,
		"client_id": d.client_id,
		"db_role": role,
	})))
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::Value;

	#[test]
	fn the_discovery_document_is_what_libpq_reads() {
		let d = dbtoken::discovery("http://issuer.test/auth/v1");
		for f in [
			"issuer",
			"token_endpoint",
			"device_authorization_endpoint",
			"jwks_uri",
		] {
			assert!(
				d[f].as_str()
					.is_some_and(|v| v.starts_with("http://issuer.test/auth/v1")),
				"{f}"
			);
		}
		assert!(
			d["grant_types_supported"]
				.as_array()
				.unwrap()
				.contains(&Value::from(dbtoken::DEVICE_GRANT))
		);
	}
}
