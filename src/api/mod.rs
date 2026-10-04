//! The HTTP API: routing, what every request carries, and who is asking.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use deadpool_postgres::Pool;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::mailer::Mailer;
use crate::models::{session, user};
use crate::ratelimit::{Limiter, Limits};

pub mod admin;
pub mod external;
pub mod mail;
pub mod mfa;
pub mod otp;
pub mod saml;
pub mod signup;
pub mod sso;
pub mod token;
pub mod user_api;
pub mod verify;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_BODY: usize = 1 << 20;

pub struct App {
	pub config: Arc<Config>,
	pub pool: Pool,
	pub mailer: Mailer,
	pub limits: Limits,
	pub http: reqwest::Client,
	pub saml: Option<saml::ServiceProvider>,
	pub oidc: crate::oidc::Cache,
	pub otp_guesses: crate::ratelimit::OtpGuesses,
}

pub type Shared = State<Arc<App>>;

/// Everything a handler may look at: the method, the path, the query, the headers, the body
/// (read whole, at most 1 MB) and the peer.
pub struct Req {
	pub method: Method,
	pub path: String,
	pub query: Vec<(String, String)>,
	pub headers: HeaderMap,
	pub body: bytes::Bytes,
	pub peer: Option<SocketAddr>,
}

impl<S: Send + Sync> FromRequest<S> for Req {
	type Rejection = Response;

	async fn from_request(req: Request, _: &S) -> Result<Req, Response> {
		let (parts, body) = req.into_parts();
		let peer = parts
			.extensions
			.get::<ConnectInfo<SocketAddr>>()
			.map(|c| c.0);
		let query = parts
			.uri
			.query()
			.map(|q| {
				url::form_urlencoded::parse(q.as_bytes())
					.map(|(k, v)| (k.into_owned(), v.into_owned()))
					.collect()
			})
			.unwrap_or_default();
		let body = match axum::body::to_bytes(body, MAX_BODY).await {
			Ok(b) => b,
			Err(_) => {
				return Err(ApiError::new(
					413,
					"request_entity_too_large",
					format!("Request body too large (max {MAX_BODY} bytes)"),
				)
				.render(&parts.headers));
			}
		};
		Ok(Req {
			method: parts.method,
			path: parts.uri.path().to_string(),
			query,
			headers: parts.headers,
			body,
			peer,
		})
	}
}

impl Req {
	pub fn header(&self, name: &str) -> &str {
		self.headers
			.get(name)
			.and_then(|v| v.to_str().ok())
			.unwrap_or("")
	}

	pub fn query(&self, name: &str) -> &str {
		self.query
			.iter()
			.find(|(k, _)| k == name)
			.map(|(_, v)| v.as_str())
			.unwrap_or("")
	}

	/// A form field from the query or an urlencoded body, the query first.
	pub fn form_value(&self, name: &str) -> String {
		let q = self.query(name);
		if !q.is_empty() {
			return q.to_string();
		}
		if self
			.header("content-type")
			.starts_with("application/x-www-form-urlencoded")
		{
			return url::form_urlencoded::parse(&self.body)
				.find(|(k, _)| k == name)
				.map(|(_, v)| v.into_owned())
				.unwrap_or_default();
		}
		String::new()
	}

	/// The body as a JSON object. An empty or non-object body is the same refusal a malformed one is.
	pub fn params(&self) -> ApiResult<Params> {
		let v: Value = serde_json::from_slice(&self.body).map_err(|e| {
			let why = if self.body.iter().all(u8::is_ascii_whitespace) {
				"unexpected end of JSON input".to_string()
			} else {
				e.to_string()
			};
			ApiError::bad_request(
				"bad_json",
				format!("Could not parse request body as JSON: {why}"),
			)
		})?;
		match v {
			Value::Object(m) => Ok(Params(m)),
			Value::Null => Ok(Params(Map::new())),
			_ => Err(ApiError::bad_request(
				"bad_json",
				"Could not parse request body as JSON: the body is not an object",
			)),
		}
	}

	/// The caller's address: the first valid address in `X-Forwarded-For`, else the socket peer.
	pub fn ip(&self) -> String {
		for part in self.header("x-forwarded-for").split(',') {
			if let Ok(ip) = part.trim().parse::<std::net::IpAddr>() {
				return ip.to_string();
			}
		}
		self.peer.map(|p| p.ip().to_string()).unwrap_or_default()
	}

	/// Where to send the user afterwards: `redirect_to` (header, then query or form) when it is
	/// allowed, else the Referer when it is, else the site URL.
	pub fn referrer(&self, cfg: &Config) -> String {
		let mut candidate = self.header("redirect_to").to_string();
		if candidate.is_empty() {
			candidate = self.form_value("redirect_to");
		}
		if crate::redirect::is_valid(&cfg.site_url, &cfg.allow_list, &candidate) {
			return candidate;
		}
		let referer = self.header("referer");
		if crate::redirect::is_valid(&cfg.site_url, &cfg.allow_list, referer) {
			return referer.to_string();
		}
		cfg.site_url.clone()
	}

	pub fn respond(&self, r: ApiResult<Response>) -> Response {
		match r {
			Ok(r) => r,
			// A sign-up race that was not retried answers as the later request would have.
			Err(e) if e.code == signup::RACE => {
				ApiError::unprocessable("email_exists", e.message).render(&self.headers)
			}
			Err(e) => e.render(&self.headers),
		}
	}
}

/// A request body as the handlers read it: missing and `null` are both "not given", and a value
/// of the wrong type is refused with the field's name.
pub struct Params(pub Map<String, Value>);

impl Params {
	fn find(&self, key: &str) -> Option<&Value> {
		self.0.get(key).or_else(|| {
			self.0
				.iter()
				.find(|(k, _)| k.eq_ignore_ascii_case(key))
				.map(|(_, v)| v)
		})
	}

	fn wrong(key: &str, want: &str, got: &Value) -> ApiError {
		let kind = match got {
			Value::Bool(_) => "bool",
			Value::Number(_) => "number",
			Value::String(_) => "string",
			Value::Array(_) => "array",
			Value::Object(_) => "object",
			Value::Null => "null",
		};
		ApiError::bad_request(
			"bad_json",
			format!(
				"Could not parse request body as JSON: json: cannot unmarshal {kind} into field {key} of type {want}"
			),
		)
	}

	pub fn str(&self, key: &str) -> ApiResult<String> {
		match self.find(key) {
			None | Some(Value::Null) => Ok(String::new()),
			Some(Value::String(s)) => Ok(s.clone()),
			Some(other) => Err(Params::wrong(key, "string", other)),
		}
	}

	pub fn bool(&self, key: &str) -> ApiResult<Option<bool>> {
		match self.find(key) {
			None | Some(Value::Null) => Ok(None),
			Some(Value::Bool(b)) => Ok(Some(*b)),
			Some(other) => Err(Params::wrong(key, "bool", other)),
		}
	}

	pub fn map(&self, key: &str) -> ApiResult<Option<Map<String, Value>>> {
		match self.find(key) {
			None | Some(Value::Null) => Ok(None),
			Some(Value::Object(m)) => Ok(Some(m.clone())),
			Some(other) => Err(Params::wrong(key, "map[string]interface {}", other)),
		}
	}

	pub fn value(&self, key: &str) -> Option<&Value> {
		self.find(key).filter(|v| !v.is_null())
	}

	/// A nested object's string field (`options.redirect_to`).
	pub fn nested_str(&self, obj: &str, key: &str) -> ApiResult<String> {
		match self.map(obj)? {
			None => Ok(String::new()),
			Some(m) => Params(m).str(key),
		}
	}
}

// ------------------------------------------------------------------------------------------
// Who is asking.

/// A caller authenticated by an access token.
pub struct Caller {
	pub claims: Map<String, Value>,
	pub user: user::User,
	pub session: Option<session::Session>,
}

impl Caller {
	pub fn role(&self) -> &str {
		crate::jwt::string_claim(&self.claims, "role")
	}
	pub fn session_id(&self) -> Option<Uuid> {
		self.session.as_ref().map(|s| s.id)
	}
}

pub fn bearer(req: &Req) -> ApiResult<String> {
	let h = req.header("authorization");
	let mut parts = h.splitn(2, ' ');
	match (parts.next(), parts.next()) {
		(Some(scheme), Some(token))
			if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() =>
		{
			Ok(token.trim().to_string())
		}
		_ => Err(ApiError::unauthorized(
			"no_authorization",
			"This endpoint requires a valid Bearer token",
		)),
	}
}

pub fn claims_of(app: &App, token: &str) -> ApiResult<Map<String, Value>> {
	crate::jwt::verify(token, &app.config.jwt_secret).map_err(|e| {
		ApiError::forbidden(
			"bad_jwt",
			format!("invalid JWT: unable to parse or verify signature, {e}"),
		)
	})
}

/// The signed-in user behind the request's token, and their session.
pub async fn authenticate(app: &App, req: &Req) -> ApiResult<Caller> {
	let token = bearer(req)?;
	let claims = claims_of(app, &token)?;
	load_caller(app, claims).await
}

pub async fn load_caller(app: &App, claims: Map<String, Value>) -> ApiResult<Caller> {
	let sub = crate::jwt::string_claim(&claims, "sub");
	if sub.is_empty() {
		return Err(ApiError::forbidden(
			"bad_jwt",
			"invalid claim: missing sub claim",
		));
	}
	let id = Uuid::parse_str(sub)
		.map_err(|_| ApiError::bad_request("bad_jwt", "invalid claim: sub claim must be a UUID"))?;
	let db = app.pool.get().await.map_err(pool_error)?;
	let sid_claim = crate::jwt::string_claim(&claims, "session_id");
	let sid = if !sid_claim.is_empty() && sid_claim != "00000000-0000-0000-0000-000000000000" {
		Some(Uuid::parse_str(sid_claim))
	} else {
		None
	};
	// The user and the session on one connection at once (pipelined: one round trip, not two).
	let session_lookup = async {
		match &sid {
			Some(Ok(s)) => session::by_id(&db, *s).await,
			_ => Ok(None),
		}
	};
	let (user, found_session) = tokio::join!(user::by_id(&db, id), session_lookup);
	// Refused in the order the reference refuses: the user first, then the session claim.
	let user = user
		.map_err(crate::error::db("Database error finding user"))?
		.ok_or_else(|| {
			ApiError::forbidden(
				"user_not_found",
				"User from sub claim in JWT does not exist",
			)
		})?;
	let mut sess = None;
	if let Some(parsed) = sid {
		parsed.map_err(|_| {
			ApiError::forbidden("bad_jwt", "invalid claim: session_id claim must be a UUID")
		})?;
		sess = Some(
			found_session
				.map_err(crate::error::db("Database error finding session"))?
				.ok_or_else(|| {
					ApiError::forbidden(
						"session_not_found",
						"Session from session_id claim in JWT does not exist",
					)
				})?,
		);
	}
	if user.is_banned() {
		return Err(ApiError::forbidden("user_banned", "User is banned"));
	}
	Ok(Caller {
		claims,
		user,
		session: sess,
	})
}

/// The service role (or another admin role): the admin API's only callers.
pub async fn require_admin(app: &App, req: &Req) -> ApiResult<Map<String, Value>> {
	let token = bearer(req)?;
	let claims = claims_of(app, &token)?;
	let sid = crate::jwt::string_claim(&claims, "session_id");
	if !sid.is_empty() && sid != "00000000-0000-0000-0000-000000000000" {
		let caller = load_caller(app, claims.clone()).await?;
		if let Some(s) = &caller.session
			&& s.validity(
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
	}
	let role = crate::jwt::string_claim(&claims, "role");
	if app.config.jwt_admin_roles.iter().any(|r| r == role) {
		Ok(claims)
	} else {
		Err(
			ApiError::forbidden("not_admin", "User not allowed").with_internal(format!(
				"this token needs one of the roles {}",
				app.config.jwt_admin_roles.join(", ")
			)),
		)
	}
}

/// The audience a request acts in: the `X-JWT-AUD` header, else a non-admin caller's own, else
/// the configured one.
pub fn request_aud(app: &App, req: &Req, claims: Option<&Map<String, Value>>) -> String {
	let h = req.header("x-jwt-aud");
	if !h.is_empty() {
		return h.to_string();
	}
	if let Some(c) = claims {
		let role = crate::jwt::string_claim(c, "role");
		if !app.config.jwt_admin_roles.iter().any(|r| r == role)
			&& let Some(a) = crate::jwt::audiences(c).into_iter().find(|a| !a.is_empty())
		{
			return a;
		}
	}
	app.config.jwt_aud.clone()
}

/// The request's claims when it carries a valid token, for the audience only.
pub fn optional_claims(app: &App, req: &Req) -> Option<Map<String, Value>> {
	bearer(req)
		.ok()
		.and_then(|t| crate::jwt::verify(&t, &app.config.jwt_secret).ok())
}

pub fn pool_error(e: deadpool_postgres::PoolError) -> ApiError {
	ApiError::internal("Database connection unavailable").with_internal(e)
}

/// Refuse the request if this client is over the limit. No key, no limit.
pub fn limit(app: &App, req: &Req, limiter: &Limiter) -> ApiResult<()> {
	let Some(name) = &app.config.rate_limit_header else {
		return Ok(());
	};
	let value = req.header(name);
	let key = value.split(',').next().unwrap_or("").trim();
	if key.is_empty() {
		return Ok(());
	}
	if limiter.allow(key) {
		Ok(())
	} else {
		Err(ApiError::too_many(
			"over_request_rate_limit",
			"Request rate limit reached",
		))
	}
}

// ------------------------------------------------------------------------------------------
// Routing.

async fn health(State(_app): Shared) -> Response {
	crate::json::ok(&serde_json::json!({
		"version": VERSION,
		"name": "snout-auth",
		"description": "snout-auth is a user registration and authentication API",
	}))
}

async fn settings(State(app): Shared) -> Response {
	let c = &app.config;
	let mut external = Map::new();
	for p in [
		"anonymous_users",
		"apple",
		"azure",
		"bitbucket",
		"discord",
		"facebook",
		"snapchat",
		"figma",
		"fly",
		"github",
		"gitlab",
		"google",
		"keycloak",
		"kakao",
		"linkedin",
		"linkedin_oidc",
		"notion",
		"spotify",
		"slack",
		"slack_oidc",
		"workos",
		"twitch",
		"twitter",
		"email",
		"phone",
		"zoom",
	] {
		let on = match p {
			"github" => c.github.enabled,
			"google" => c.google.enabled,
			"email" => c.email_enabled,
			"anonymous_users" => c.anonymous_users_enabled,
			_ => false,
		};
		external.insert(p.into(), Value::Bool(on));
	}
	crate::json::ok(&serde_json::json!({
		"external": external,
		"disable_signup": c.disable_signup,
		"mailer_autoconfirm": c.autoconfirm,
		"phone_autoconfirm": false,
		"sms_provider": "",
		"saml_enabled": c.saml_enabled,
		"saml_private_key_next_configured": app.saml.as_ref().is_some_and(|s| s.next_cert.is_some()),
		"passkeys_enabled": false,
	}))
}

async fn jwks() -> Response {
	crate::json::ok(&serde_json::json!({ "keys": [] }))
}

/// An endpoint of a feature this server does not serve, answered as a disabled feature is.
async fn not_enabled(req: Req) -> Response {
	let e = if req.path.starts_with("/oauth") || req.path.starts_with("/.well-known/oauth") {
		ApiError::not_found("oauth_server_disabled", "OAuth server is disabled")
	} else if req.path.starts_with("/passkeys") {
		ApiError::not_found("passkeys_disabled", "Passkeys are disabled")
	} else {
		ApiError::not_found("not_found", "Not Found")
	};
	e.render(&req.headers)
}

pub fn router(app: Arc<App>) -> Router {
	Router::new()
		.route("/health", get(health))
		.route("/settings", get(settings))
		.route("/.well-known/jwks.json", get(jwks))
		.route("/signup", post(signup::signup))
		.route("/token", post(token::token))
		.route("/verify", get(verify::verify_get).post(verify::verify_post))
		.route("/otp", post(otp::otp))
		.route("/magiclink", post(otp::magic_link))
		.route("/recover", post(otp::recover))
		.route("/resend", post(otp::resend))
		.route("/invite", post(admin::invite))
		.route("/logout", post(user_api::logout))
		.route("/reauthenticate", get(user_api::reauthenticate))
		.route("/user", get(user_api::get_user).put(user_api::update_user))
		.route("/factors", post(mfa::enroll))
		.route("/factors/{factor_id}", axum::routing::delete(mfa::unenroll))
		.route("/factors/{factor_id}/challenge", post(mfa::challenge))
		.route("/factors/{factor_id}/verify", post(mfa::verify))
		.route("/authorize", get(external::authorize))
		.route(
			"/callback",
			get(external::callback).post(external::callback),
		)
		.route("/sso", post(sso::start))
		.route("/sso/saml/metadata", get(saml::metadata))
		.route("/sso/saml/acs", post(saml::acs))
		.route(
			"/admin/users",
			get(admin::list_users).post(admin::create_user),
		)
		.route(
			"/admin/users/{user_id}",
			get(admin::get_user)
				.put(admin::update_user)
				.delete(admin::delete_user),
		)
		.route("/admin/users/{user_id}/factors", get(admin::list_factors))
		.route(
			"/admin/users/{user_id}/factors/{factor_id}",
			axum::routing::delete(admin::delete_factor).put(admin::update_factor),
		)
		.route("/admin/generate_link", post(admin::generate_link))
		.route("/admin/audit", get(admin::audit_log))
		.route(
			"/admin/sso/providers",
			get(sso::list_providers).post(sso::create_provider),
		)
		.route(
			"/admin/sso/providers/{idp_id}",
			get(sso::get_provider)
				.put(sso::update_provider)
				.delete(sso::delete_provider),
		)
		.route("/oauth/{*rest}", any(not_enabled))
		.route("/passkeys", any(not_enabled))
		.route("/passkeys/{*rest}", any(not_enabled))
		.fallback(not_enabled)
		.layer(axum::middleware::from_fn_with_state(app.clone(), cors))
		.with_state(app)
}

const ALLOWED_METHODS: &str = "GET, POST, PUT, PATCH, DELETE";

/// Browsers may call from anywhere, with credentials: the origin is echoed, never `*`.
async fn cors(State(app): Shared, req: Request, next: axum::middleware::Next) -> Response {
	let origin = req.headers().get(header::ORIGIN).cloned();
	if req.method() == Method::OPTIONS
		&& req
			.headers()
			.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
	{
		let mut r = StatusCode::NO_CONTENT.into_response();
		let h = r.headers_mut();
		h.insert(
			header::VARY,
			HeaderValue::from_static(
				"Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
			),
		);
		if let Some(o) = origin {
			h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
			h.insert(
				header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
				HeaderValue::from_static("true"),
			);
			h.insert(
				header::ACCESS_CONTROL_ALLOW_METHODS,
				HeaderValue::from_static(ALLOWED_METHODS),
			);
			let mut allowed = vec![
				"Accept".to_string(),
				"Authorization".into(),
				"Content-Type".into(),
				"X-Client-IP".into(),
				"X-Client-Info".into(),
				"X-JWT-AUD".into(),
				"x-use-cookie".into(),
				crate::error::API_VERSION_HEADER.into(),
			];
			allowed.extend(app.config.cors_extra_headers.iter().cloned());
			if let Ok(v) = HeaderValue::from_str(&allowed.join(", ")) {
				h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
			}
		}
		return r;
	}
	let mut r = next.run(req).await;
	let h = r.headers_mut();
	h.append(header::VARY, HeaderValue::from_static("Origin"));
	if let Some(o) = origin {
		h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
		h.insert(
			header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
			HeaderValue::from_static("true"),
		);
		h.insert(
			header::ACCESS_CONTROL_EXPOSE_HEADERS,
			HeaderValue::from_static("X-Total-Count, Link, X-Api-Version"),
		);
	}
	r
}

/// A 204 with no body.
pub fn no_content() -> Response {
	let mut r = Response::new(Body::empty());
	*r.status_mut() = StatusCode::NO_CONTENT;
	r
}

/// A redirect (303 See Other for a POST, 302 Found otherwise).
pub fn redirect(to: &str, status: StatusCode) -> Response {
	let mut r = Response::new(Body::empty());
	*r.status_mut() = status;
	if let Ok(v) = HeaderValue::from_str(to) {
		r.headers_mut().insert(header::LOCATION, v);
	}
	r
}
