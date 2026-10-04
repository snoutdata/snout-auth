//! Signing in through Google or GitHub (`/authorize` then `/callback`), and exchanging a Google
//! ID token for a session (`/token?grant_type=id_token`).

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::token::{Grant, audit, issue_session, traits, with_headers};
use super::verify::{go_redirect, with_query};
use super::{App, Req, Shared};
use crate::config::Provider;
use crate::error::{ApiError, ApiResult, ErrorKind, db};
use crate::models::{identity, token as tok, user};

pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_USERINFO: &str = "https://www.googleapis.com/userinfo/v2/me";

#[derive(Clone, Copy, PartialEq)]
enum Kind {
	Google,
	Github,
}

impl Kind {
	fn name(self) -> &'static str {
		match self {
			Kind::Google => "google",
			Kind::Github => "github",
		}
	}
	fn config(self, app: &App) -> &Provider {
		match self {
			Kind::Google => &app.config.google,
			Kind::Github => &app.config.github,
		}
	}
}

/// The provider named, if it is one this server can use.
fn provider(app: &App, name: &str) -> Result<(Kind, Provider), String> {
	let kind = match name.to_ascii_lowercase().as_str() {
		"google" => Kind::Google,
		"github" => Kind::Github,
		// Providers this server knows of and does not run: not enabled, not unknown.
		"apple" | "azure" | "bitbucket" | "discord" | "facebook" | "figma" | "fly" | "gitlab"
		| "kakao" | "keycloak" | "linkedin" | "linkedin_oidc" | "notion" | "snapchat"
		| "spotify" | "slack" | "slack_oidc" | "twitch" | "twitter" | "x" | "workos" | "zoom" => {
			return Err("provider is not enabled".into());
		}
		_ => return Err(format!("Provider {name} could not be found")),
	};
	let p = kind.config(app).clone();
	if !p.enabled {
		return Err("provider is not enabled".into());
	}
	if p.client_id.is_empty() {
		return Err("missing OAuth client ID".into());
	}
	if p.secret.is_empty() {
		return Err("missing OAuth secret".into());
	}
	if p.redirect_uri.is_empty() {
		return Err("missing redirect URI".into());
	}
	Ok((kind, p))
}

fn github_hosts(p: &Provider) -> (String, String) {
	let choose = |default: &str| match p.url.as_deref() {
		None | Some("") => format!("https://{default}"),
		Some(u) => u.trim_end_matches('/').to_string(),
	};
	let auth = choose("github.com");
	let mut api = choose("api.github.com");
	if !api.ends_with("api.github.com") {
		api.push_str("/api/v3");
	}
	(auth, api)
}

struct Endpoints {
	auth: String,
	token: String,
	scopes: Vec<String>,
}

async fn endpoints(
	app: &App,
	kind: Kind,
	p: &Provider,
	extra_scopes: &str,
) -> Result<Endpoints, String> {
	let extra: Vec<String> = if extra_scopes.is_empty() {
		vec![]
	} else {
		extra_scopes.split(',').map(str::to_string).collect()
	};
	match kind {
		Kind::Google => {
			let d = app.oidc.discovery(&app.http, GOOGLE_ISSUER).await?;
			let mut scopes = vec!["email".to_string(), "profile".to_string()];
			scopes.extend(extra);
			Ok(Endpoints {
				auth: d.authorization_endpoint,
				token: d.token_endpoint,
				scopes,
			})
		}
		Kind::Github => {
			let (auth, _) = github_hosts(p);
			let mut scopes = vec!["user:email".to_string()];
			scopes.extend(extra);
			Ok(Endpoints {
				auth: format!("{auth}/login/oauth/authorize"),
				token: format!("{auth}/login/oauth/access_token"),
				scopes,
			})
		}
	}
}

const RESERVED: &[&str] = &[
	"client_id",
	"client_secret",
	"redirect_uri",
	"response_type",
	"state",
	"code_challenge",
	"code_challenge_method",
	"code_verifier",
];

// ------------------------------------------------------------------------------------------
// GET /authorize

pub async fn authorize(axum::extract::State(app): Shared, req: Req) -> Response {
	match start(&app, &req).await {
		Ok(r) => r,
		Err(e) => e.render(&req.headers),
	}
}

async fn start(app: &App, req: &Req) -> ApiResult<Response> {
	let name = req.query("provider").to_string();
	let unsupported = |why: String| {
		ApiError::bad_request("validation_failed", format!("Unsupported provider: {why}"))
	};
	let (kind, p) = provider(app, &name).map_err(unsupported)?;
	let ep = endpoints(app, kind, &p, req.query("scopes"))
		.await
		.map_err(unsupported)?;
	let invite = req.query("invite_token").to_string();
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	if !invite.is_empty()
		&& tok::find_user_id(&conn, &invite, &[tok::CONFIRMATION])
			.await
			.map_err(db("Database error finding user"))?
			.is_none()
	{
		return Err(ApiError::not_found(
			"user_not_found",
			"User identified by token not found",
		));
	}
	let referrer = req.referrer(&app.config);
	let challenge = req.query("code_challenge").to_string();
	let method = req.query("code_challenge_method").to_string();
	crate::pkce::validate_params(&method, &challenge)?;
	if !challenge.is_empty() && !matches!(method.to_ascii_lowercase().as_str(), "s256" | "plain") {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Invalid code_challenge_method",
		));
	}

	// Everything else the caller put in the query goes to the provider, bar what the flow sets.
	let mut v: Vec<(String, String)> = vec![
		("response_type".into(), "code".into()),
		("client_id".into(), p.client_id[0].clone()),
	];
	v.push(("redirect_uri".into(), p.redirect_uri.clone()));
	v.push(("scope".into(), ep.scopes.join(" ")));
	let tx = conn
		.transaction()
		.await
		.map_err(db("Error creating flow state"))?;
	let flow = tok::insert_flow(
		&tx,
		&tok::NewFlow {
			provider_type: kind.name(),
			authentication_method: "oauth",
			code_challenge: &challenge,
			code_challenge_method: &method,
			user_id: None,
			invite_token: Some(invite.as_str()).filter(|s| !s.is_empty()),
			referrer: Some(referrer.as_str()).filter(|s| !s.is_empty()),
			provider_access_token: None,
			provider_refresh_token: None,
		},
	)
	.await
	.map_err(db("Error creating flow state"))?;
	tx.commit().await.map_err(db("Error creating flow state"))?;
	v.push(("state".into(), flow.id.to_string()));
	for (k, val) in &req.query {
		let lower = k.to_ascii_lowercase();
		if k == "scopes"
			|| k == "provider"
			|| (lower != "nonce" && RESERVED.contains(&lower.as_str()))
		{
			continue;
		}
		v.retain(|(x, _)| x != k);
		v.push((k.clone(), val.clone()));
	}
	v.sort_by(|a, b| a.0.cmp(&b.0));
	let query = url::form_urlencoded::Serializer::new(String::new())
		.extend_pairs(v)
		.finish();
	let sep = if ep.auth.contains('?') { '&' } else { '?' };
	Ok(go_redirect(
		req,
		&format!("{}{sep}{query}", ep.auth),
		StatusCode::FOUND,
	))
}

// ------------------------------------------------------------------------------------------
// GET/POST /callback

/// What a provider says about the person who signed in. `data`, when given, is the identity
/// data exactly (SAML builds its own); otherwise it is derived from the claims and emails.
pub(crate) struct Profile {
	pub emails: Vec<(String, bool, bool)>,
	pub claims: Map<String, Value>,
	pub data: Option<Map<String, Value>>,
}

pub async fn callback(axum::extract::State(app): Shared, req: Req) -> Response {
	// The flow first: without it there is no application to send the user back to, so any
	// failure goes to the site URL.
	let state = if req.method == axum::http::Method::POST {
		req.form_value("state")
	} else {
		req.query("state").to_string()
	};
	let flow = match load_flow(&app, &state).await {
		Ok(f) => f,
		Err(e) => {
			let q = error_query(&e);
			let pairs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
			let loc = with_query(&app.config.site_url, &pairs);
			return go_redirect(&req, &loc, StatusCode::SEE_OTHER);
		}
	};
	let referrer = flow
		.referrer
		.clone()
		.filter(|r| !r.is_empty())
		.unwrap_or_else(|| app.config.site_url.clone());
	match finish(&app, &req, flow).await {
		Ok(r) => r,
		Err(e) => {
			let mut pairs = error_query(&e);
			let (base, q, _) = split3(&referrer);
			let mut all: Vec<(String, String)> = q
				.map(|q| {
					url::form_urlencoded::parse(q.as_bytes())
						.map(|(k, v)| (k.into_owned(), v.into_owned()))
						.collect()
				})
				.unwrap_or_default();
			all.retain(|(k, _)| !pairs.iter().any(|(p, _)| p == k));
			all.extend(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())));
			all.sort_by(|a, b| a.0.cmp(&b.0));
			let query = url::form_urlencoded::Serializer::new(String::new())
				.extend_pairs(all)
				.finish();
			pairs.retain(|(k, _)| matches!(*k, "error" | "error_description" | "error_code"));
			pairs.push(("sb", String::new()));
			pairs.sort_by(|a, b| a.0.cmp(b.0));
			let frag = url::form_urlencoded::Serializer::new(String::new())
				.extend_pairs(pairs)
				.finish();
			go_redirect(&req, &format!("{base}?{query}#{frag}"), StatusCode::FOUND)
		}
	}
}

fn split3(s: &str) -> (&str, Option<&str>, Option<&str>) {
	let (a, frag) = s
		.split_once('#')
		.map(|(a, f)| (a, Some(f)))
		.unwrap_or((s, None));
	let (base, q) = a
		.split_once('?')
		.map(|(b, q)| (b, Some(q)))
		.unwrap_or((a, None));
	(base, q, frag)
}

/// The OAuth error parameters an error is reported to an application with.
pub(crate) fn error_query(e: &ApiError) -> Vec<(&'static str, String)> {
	match &*e.kind {
		ErrorKind::OAuth { error, description } => vec![
			("error", error.clone()),
			("error_description", description.clone()),
		],
		_ => {
			let error = match e.code.as_str() {
				"signup_disabled" | "user_banned" | "provider_email_needs_verification" => {
					"access_denied"
				}
				_ => match e.status.as_u16() {
					400 => "invalid_request",
					401 => "unauthorized_client",
					403 => "access_denied",
					500 => "server_error",
					503 => "temporarily_unavailable",
					_ => "server_error",
				},
			};
			vec![
				("error", error.to_string()),
				("error_description", e.message.clone()),
				("error_code", e.code.clone()),
			]
		}
	}
}

async fn load_flow(app: &App, state: &str) -> ApiResult<tok::FlowState> {
	if state.is_empty() {
		return Err(ApiError::bad_request(
			"bad_oauth_callback",
			"OAuth state parameter missing",
		));
	}
	let id = Uuid::parse_str(state).map_err(|_| {
		ApiError::bad_request("bad_oauth_state", "OAuth state parameter is invalid")
	})?;
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	let f = tok::flow_by_id(&conn, id)
		.await
		.map_err(db("Error loading flow state"))?
		.ok_or_else(|| {
			ApiError::bad_request("bad_oauth_state", "OAuth state not found or expired")
		})?;
	if f.is_expired(app.config.flow_state_expiry) {
		return Err(ApiError::bad_request(
			"bad_oauth_state",
			"OAuth state has expired",
		));
	}
	if f.is_pkce() && f.user_id.is_some() {
		return Err(ApiError::bad_request(
			"flow_state_already_used",
			"State has already been used",
		));
	}
	Ok(f)
}

async fn finish(app: &App, req: &Req, flow: tok::FlowState) -> ApiResult<Response> {
	let form = |k: &str| {
		if req.method == axum::http::Method::POST {
			req.form_value(k)
		} else {
			req.query(k).to_string()
		}
	};
	let ext_error = form("error");
	if !ext_error.is_empty() {
		return Err(ApiError::oauth(&ext_error, form("error_description")));
	}
	let code = form("code");
	if code.is_empty() {
		return Err(ApiError::bad_request(
			"bad_oauth_callback",
			"OAuth callback with missing authorization code missing",
		));
	}
	let (kind, p) = provider(app, &flow.provider_type).map_err(|e| {
		ApiError::bad_request(
			"oauth_provider_not_supported",
			format!("Unsupported provider: {e}"),
		)
	})?;
	let ep = endpoints(app, kind, &p, "").await.map_err(|e| {
		ApiError::bad_request(
			"oauth_provider_not_supported",
			format!("Unsupported provider: {e}"),
		)
	})?;
	let token = exchange(app, &ep.token, &p, &code).await.map_err(|e| {
		ApiError::internal(format!(
			"Unable to exchange external code: {}",
			&code[..code.len().min(4)]
		))
		.with_internal(e)
	})?;
	let access = token
		.get("access_token")
		.and_then(Value::as_str)
		.unwrap_or("")
		.to_string();
	let refresh = token
		.get("refresh_token")
		.and_then(Value::as_str)
		.unwrap_or("")
		.to_string();
	let profile = match kind {
		Kind::Google => google_profile(app, &p, &token).await,
		Kind::Github => github_profile(app, &p, &access).await,
	}
	.map_err(|e| {
		ApiError::internal("Error getting user profile from external provider").with_internal(e)
	})?;
	if profile.emails.is_empty() && !p.email_optional {
		return Err(ApiError::bad_request(
			"email_address_not_provided",
			"Error getting user email from external provider",
		));
	}

	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn.transaction().await.map_err(db("Database error"))?;
	let mut u = if let Some(invite) = flow.invite_token.clone().filter(|s| !s.is_empty()) {
		accept_invite(app, &tx, req, kind.name(), &invite, &profile).await?
	} else {
		match account_from_identity(app, &tx, req, kind.name(), &profile, p.email_optional).await? {
			Linked::Ok(u) => *u,
			Linked::Refused(e) => {
				tx.commit().await.map_err(db("Database error"))?;
				return Err(e);
			}
		}
	};
	let mut headers = HeaderMap::new();
	let location = if flow.is_pkce() {
		let mut f = tok::flow_by_id(&tx, flow.id)
			.await
			.map_err(db("Database error"))?
			.ok_or_else(|| ApiError::oauth("server_error", "flow state not found"))?;
		if f.user_id.is_some() {
			return Err(ApiError::bad_request(
				"flow_state_already_used",
				"State has already been used",
			));
		}
		let now = crate::json::now();
		tx.execute(
			"update flow_state set provider_access_token = $1, provider_refresh_token = $2, user_id = $3, auth_code_issued_at = $4, updated_at = $4 where id = $5",
			&[&access, &refresh, &u.id, &now, &f.id],
		)
		.await
		.map_err(|e| ApiError::oauth("server_error", e.to_string()))?;
		f.user_id = Some(u.id);
		super::verify::with_query(
			&referrer_of(app, &flow),
			&[("code", f.auth_code.as_deref().unwrap_or(""))],
		)
	} else {
		let body = issue_session(
			app,
			&tx,
			req,
			&mut headers,
			&mut u,
			"oauth",
			Grant::default(),
		)
		.await
		.map_err(|e| ApiError::oauth("server_error", e.message))?;
		tok::delete_flow(&tx, flow.id)
			.await
			.map_err(|e| ApiError::oauth("server_error", e.to_string()))?;
		let mut extra = vec![("provider_token", access.as_str())];
		if !refresh.is_empty() {
			extra.push(("provider_refresh_token", refresh.as_str()));
		}
		super::token::as_fragment(&referrer_of(app, &flow), &body, &extra)
	};
	tx.commit().await.map_err(db("Database error"))?;
	Ok(with_headers(
		go_redirect(req, &location, StatusCode::FOUND),
		headers,
	))
}

fn referrer_of(app: &App, flow: &tok::FlowState) -> String {
	flow.referrer
		.clone()
		.filter(|r| !r.is_empty())
		.unwrap_or_else(|| app.config.site_url.clone())
}

/// A code for the provider's tokens. Client credentials go in the Authorization header, and
/// again as form fields for a provider that refuses the header.
async fn exchange(app: &App, url: &str, p: &Provider, code: &str) -> Result<Value, String> {
	let form = [
		("grant_type", "authorization_code"),
		("code", code),
		("redirect_uri", p.redirect_uri.as_str()),
	];
	let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
	let res = app
		.http
		.post(url)
		.basic_auth(enc(&p.client_id[0]), Some(enc(&p.secret)))
		.form(&form)
		.send()
		.await
		.map_err(|e| e.to_string())?;
	let res = if res.status().is_success() {
		res
	} else {
		let mut with_params = form.to_vec();
		with_params.push(("client_id", p.client_id[0].as_str()));
		with_params.push(("client_secret", p.secret.as_str()));
		app.http
			.post(url)
			.form(&with_params)
			.send()
			.await
			.map_err(|e| e.to_string())?
	};
	let status = res.status();
	let ct = res
		.headers()
		.get("content-type")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.to_string();
	let body = res.text().await.map_err(|e| e.to_string())?;
	if !status.is_success() {
		return Err(format!(
			"oauth2: cannot fetch token: {status}\nResponse: {body}"
		));
	}
	let v: Value =
		if ct.starts_with("application/x-www-form-urlencoded") || ct.starts_with("text/plain") {
			Value::Object(
				url::form_urlencoded::parse(body.as_bytes())
					.map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
					.collect(),
			)
		} else {
			serde_json::from_str(&body).map_err(|e| e.to_string())?
		};
	if v.get("access_token")
		.and_then(Value::as_str)
		.unwrap_or("")
		.is_empty()
	{
		return Err("oauth2: server response missing access_token".into());
	}
	Ok(v)
}

fn put(m: &mut Map<String, Value>, k: &str, v: &str) {
	if !v.is_empty() {
		m.insert(k.into(), json!(v));
	}
}

async fn google_profile(app: &App, p: &Provider, token: &Value) -> Result<Profile, String> {
	if let Some(id_token) = token.get("id_token").and_then(Value::as_str) {
		let claims = app.oidc.verify(&app.http, GOOGLE_ISSUER, id_token).await?;
		let aud_ok = match claims.get("aud") {
			Some(Value::String(a)) => *a == p.client_id[0],
			Some(Value::Array(a)) => a
				.iter()
				.any(|x| x.as_str() == Some(p.client_id[0].as_str())),
			_ => false,
		};
		if !aud_ok {
			return Err(format!("oidc: expected audience {:?}", p.client_id[0]));
		}
		if let (Some(at_hash), Some(access)) = (
			claims.get("at_hash").and_then(Value::as_str),
			token.get("access_token").and_then(Value::as_str),
		) && !crate::oidc::at_hash_matches(at_hash, access)
		{
			return Err("access token hash does not match value in ID token".into());
		}
		return Ok(google_from_claims(&claims));
	}
	let access = token
		.get("access_token")
		.and_then(Value::as_str)
		.unwrap_or("");
	let u: Value = get_json(app, GOOGLE_USERINFO, access).await?;
	let s = |k: &str| u.get(k).and_then(Value::as_str).unwrap_or("").to_string();
	let verified = u
		.get("verified_email")
		.and_then(Value::as_bool)
		.unwrap_or(false)
		|| u.get("email_verified")
			.and_then(Value::as_bool)
			.unwrap_or(false);
	let mut emails = vec![];
	if !s("email").is_empty() {
		emails.push((s("email"), verified, true));
	}
	let mut m = Map::new();
	put(&mut m, "iss", GOOGLE_USERINFO);
	put(&mut m, "sub", &s("id"));
	put(&mut m, "name", &s("name"));
	put(&mut m, "picture", &s("picture"));
	put(&mut m, "avatar_url", &s("picture"));
	put(&mut m, "full_name", &s("name"));
	put(&mut m, "provider_id", &s("id"));
	Ok(Profile {
		emails,
		claims: m,
		data: None,
	})
}

fn google_from_claims(c: &Map<String, Value>) -> Profile {
	let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
	let verified = c
		.get("verified_email")
		.and_then(Value::as_bool)
		.unwrap_or(false)
		|| c.get("email_verified")
			.and_then(Value::as_bool)
			.unwrap_or(false);
	let mut emails = vec![];
	if !s("email").is_empty() {
		emails.push((s("email"), verified, true));
	}
	let mut m = Map::new();
	put(&mut m, "iss", &s("iss"));
	put(&mut m, "sub", &s("sub"));
	put(&mut m, "name", &s("name"));
	put(&mut m, "picture", &s("picture"));
	put(&mut m, "avatar_url", &s("picture"));
	put(&mut m, "full_name", &s("name"));
	put(&mut m, "provider_id", &s("sub"));
	if !s("hd").is_empty() {
		m.insert("custom_claims".into(), json!({ "hd": s("hd") }));
	}
	Profile {
		emails,
		claims: m,
		data: None,
	}
}

async fn get_json(app: &App, url: &str, access: &str) -> Result<Value, String> {
	let res = app
		.http
		.get(url)
		.bearer_auth(access)
		.send()
		.await
		.map_err(|e| e.to_string())?;
	let status = res.status();
	let body = res.text().await.map_err(|e| e.to_string())?;
	if !status.is_success() {
		return Err(format!("{}: {body}", status.as_u16()));
	}
	serde_json::from_str(&body).map_err(|e| e.to_string())
}

async fn github_profile(app: &App, p: &Provider, access: &str) -> Result<Profile, String> {
	let (_, api) = github_hosts(p);
	let u = get_json(app, &format!("{api}/user"), access).await?;
	let s = |k: &str| u.get(k).and_then(Value::as_str).unwrap_or("").to_string();
	let id = u
		.get("id")
		.and_then(Value::as_i64)
		.map(|n| n.to_string())
		.unwrap_or_default();
	let mut m = Map::new();
	put(&mut m, "iss", &api);
	put(&mut m, "sub", &id);
	put(&mut m, "name", &s("name"));
	put(&mut m, "preferred_username", &s("login"));
	put(&mut m, "avatar_url", &s("avatar_url"));
	put(&mut m, "full_name", &s("name"));
	put(&mut m, "provider_id", &id);
	put(&mut m, "user_name", &s("login"));
	let list = get_json(app, &format!("{api}/user/emails"), access).await?;
	let mut emails = vec![];
	for e in list.as_array().into_iter().flatten() {
		let email = e.get("email").and_then(Value::as_str).unwrap_or("");
		if !email.is_empty() {
			emails.push((
				email.to_string(),
				e.get("verified").and_then(Value::as_bool).unwrap_or(false),
				e.get("primary").and_then(Value::as_bool).unwrap_or(false),
			));
		}
	}
	Ok(Profile {
		emails,
		claims: m,
		data: None,
	})
}

// ------------------------------------------------------------------------------------------
// Which account a provider identity signs in to.

pub(crate) enum Linked {
	Ok(Box<user::User>),
	/// Refused, with what was already done (a confirmation mail) to be kept.
	Refused(ApiError),
}

/// The identity data a provider's profile becomes: its claims, and its primary (else last)
/// address with whether the provider verified it.
fn identity_data(profile: &Profile) -> (Map<String, Value>, String, bool) {
	if let Some(d) = &profile.data {
		let (email, verified) = profile
			.emails
			.first()
			.map(|(e, v, _)| (e.clone(), *v))
			.unwrap_or_default();
		return (d.clone(), email, verified);
	}
	let mut m = profile.claims.clone();
	let mut email = String::new();
	let mut verified = false;
	for (e, v, primary) in &profile.emails {
		email = e.clone();
		verified = *v;
		if *primary {
			break;
		}
	}
	// Stored lower-cased, like every address in an identity.
	put(&mut m, "email", &email.to_lowercase());
	m.insert("email_verified".into(), json!(verified));
	m.insert("phone_verified".into(), json!(false));
	(m, email, verified)
}

pub(crate) async fn account_from_identity<C: deadpool_postgres::GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	provider_name: &str,
	profile: &Profile,
	email_optional: bool,
) -> ApiResult<Linked> {
	let cfg = &app.config;
	let sso = provider_name.starts_with("sso:");
	let claims = super::optional_claims(app, req);
	let aud = super::request_aud(app, req, claims.as_ref());
	let (data, _, _) = identity_data(profile);
	let sub = profile
		.claims
		.get("sub")
		.and_then(Value::as_str)
		.unwrap_or("")
		.to_string();

	let verified: Vec<String> = profile
		.emails
		.iter()
		.filter(|(_, v, _)| *v || cfg.autoconfirm)
		.map(|(e, _, _)| e.to_lowercase())
		.collect();
	let mut candidate = profile
		.emails
		.iter()
		.find(|(_, _, p)| *p)
		.map(|(e, v, _)| (e.to_lowercase(), *v))
		.unwrap_or_default();

	// The identity is boxed so the enum is the size of a user, as Link is, rather than of both.
	enum Decision {
		Exists(user::User, Box<identity::Identity>),
		Create,
		Link(user::User),
		Multiple,
	}
	let decision = if let Some(i) = identity::by_provider(tx, &sub, provider_name)
		.await
		.map_err(db("Database error"))?
	{
		let u = user::by_id(tx, i.user_id)
			.await
			.map_err(db("Database error"))?
			.ok_or_else(|| ApiError::internal("user not found"))?;
		candidate.0 = u.email.clone();
		Decision::Exists(u, Box::new(i))
	} else if verified.is_empty() {
		if super::signup::duplicate_email(tx, &candidate.0, &aud, None)
			.await?
			.is_some()
		{
			candidate.0.clear();
		}
		Decision::Create
	} else {
		// An SSO provider is a linking domain of its own: its identities link only to each other,
		// and never to an account made any other way.
		let similar: Vec<Uuid> = if sso {
			tx.query(
				"select distinct user_id from identities where email = any($1) and provider = $2",
				&[&verified, &provider_name],
			)
			.await
		} else {
			tx.query(
				"select distinct user_id from identities where email = any($1) and provider not like 'sso:%'",
				&[&verified],
			)
			.await
		}
		.map_err(db("Database error"))?
		.iter()
		.map(|r| r.get(0))
		.collect();
		if similar.is_empty() && sso {
			Decision::Create
		} else if similar.is_empty() {
			let users: Vec<Uuid> = tx
				.query(
					"select id from users where email = any($1) and is_sso_user = false",
					&[&verified],
				)
				.await
				.map_err(db("Database error"))?
				.iter()
				.map(|r| r.get(0))
				.collect();
			match users.len() {
				0 => Decision::Create,
				1 => Decision::Link(
					user::by_id(tx, users[0])
						.await
						.map_err(db("Database error"))?
						.ok_or_else(|| ApiError::internal("user not found"))?,
				),
				_ => Decision::Multiple,
			}
		} else if similar.len() > 1 {
			Decision::Multiple
		} else {
			Decision::Link(
				user::by_id(tx, similar[0])
					.await
					.map_err(db("Database error"))?
					.ok_or_else(|| ApiError::internal("user not found"))?,
			)
		}
	};

	let (mut u, ident) = match decision {
		Decision::Link(mut u) => {
			let i = identity::insert(tx, u.id, provider_name, data.clone())
				.await
				.map_err(|e| ApiError::internal("Error creating identity").with_internal(e))?;
			u.merge_user_metadata(&data);
			user::update(tx, &mut u, &["raw_user_meta_data"])
				.await
				.map_err(db("Database error"))?;
			super::signup::set_providers(tx, &mut u).await?;
			let mut t = Map::new();
			t.insert("identity_id".into(), json!(i.id));
			t.insert("provider".into(), json!(i.provider));
			t.insert("provider_id".into(), json!(i.provider_id));
			audit(tx, &u, "identity_linked", req, Some(t)).await?;
			u.identities = identity::for_user(tx, u.id)
				.await
				.map_err(db("Database error"))?;
			(u, i)
		}
		Decision::Create => {
			if cfg.disable_signup {
				return Err(ApiError::unprocessable(
					"signup_disabled",
					"Signups not allowed for this instance",
				));
			}
			let mut nu = user::new_user(
				&candidate.0,
				"",
				Some(String::new()),
				&aud,
				Some(data.clone()),
			);
			nu.is_sso_user = sso;
			let mut app_meta = Map::new();
			app_meta.insert("provider".into(), json!(provider_name));
			app_meta.insert("providers".into(), json!([provider_name]));
			nu.app_metadata = Some(app_meta);
			super::signup::create_user(tx, &mut nu, &cfg.jwt_default_group).await?;
			let i = identity::insert(tx, nu.id, provider_name, data.clone())
				.await
				.map_err(|e| ApiError::internal("Error creating identity").with_internal(e))?;
			nu.identities.push(i.clone());
			(nu, i)
		}
		Decision::Exists(mut u, i) => {
			let mut i = *i;
			i.identity_data = data.clone();
			let now = crate::json::now();
			tx.execute(
				"update identities set identity_data = $1, last_sign_in_at = $2, updated_at = $2 where id = $3",
				&[&Value::Object(data.clone()), &now, &i.id],
			)
			.await
			.map_err(db("Database error"))?;
			u.merge_user_metadata(&data);
			user::update(tx, &mut u, &["raw_user_meta_data"])
				.await
				.map_err(db("Database error"))?;
			super::signup::set_providers(tx, &mut u).await?;
			u.identities = identity::for_user(tx, u.id)
				.await
				.map_err(db("Database error"))?;
			(u, i)
		}
		Decision::Multiple => {
			let domain = if sso { provider_name } else { "default" };
			return Err(ApiError::internal(format!(
				"Multiple accounts with the same email address in the same linking domain detected: {domain}"
			)));
		}
	};
	if u.is_banned() {
		return Err(ApiError::forbidden("user_banned", "User is banned"));
	}
	let has_emails = !email_optional || !candidate.0.is_empty();
	if has_emails && !u.is_confirmed() {
		super::signup::remove_unconfirmed_identities(tx, &mut u, &ident).await?;
		u.identities = vec![ident];
		if candidate.1 || cfg.autoconfirm {
			audit(
				tx,
				&u,
				"user_signedup",
				req,
				Some(traits(&[("provider", provider_name)])),
			)
			.await?;
			super::signup::confirm(tx, &mut u).await?;
		} else {
			if !candidate.0.is_empty() {
				super::mail::send_confirmation(app, tx, req, &mut u, false).await?;
				return Ok(Linked::Refused(ApiError::unprocessable(
					"provider_email_needs_verification",
					format!(
						"Unverified email with {provider_name}. A confirmation email has been sent to your {provider_name} email"
					),
				)));
			}
			return Ok(Linked::Refused(ApiError::unprocessable(
				"provider_email_needs_verification",
				format!(
					"Unverified email with {provider_name}. Verify the email with {provider_name} in order to sign in"
				),
			)));
		}
	} else {
		audit(
			tx,
			&u,
			"login",
			req,
			Some(traits(&[("provider", provider_name)])),
		)
		.await?;
	}
	Ok(Linked::Ok(Box::new(u)))
}

async fn accept_invite<C: deadpool_postgres::GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	provider_name: &str,
	invite: &str,
	profile: &Profile,
) -> ApiResult<user::User> {
	let _ = app;
	let id = tok::find_user_id(tx, invite, &[tok::CONFIRMATION])
		.await
		.map_err(db("Database error finding user"))?
		.ok_or_else(|| ApiError::not_found("invite_not_found", "Invite not found"))?;
	let mut u = user::by_id(tx, id)
		.await
		.map_err(db("Database error finding user"))?
		.ok_or_else(|| ApiError::not_found("invite_not_found", "Invite not found"))?;
	if !profile.emails.iter().any(|(e, _, _)| *e == u.email) {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Invited email does not match emails from external provider",
		));
	}
	let (data, _, _) = identity_data(profile);
	let i = identity::insert(tx, u.id, provider_name, data.clone())
		.await
		.map_err(|e| ApiError::internal("Error creating identity").with_internal(e))?;
	let mut am = Map::new();
	am.insert("provider".into(), json!(provider_name));
	u.merge_app_metadata(&am);
	user::update(tx, &mut u, &["raw_app_meta_data"])
		.await
		.map_err(db("Database error"))?;
	super::signup::set_providers(tx, &mut u).await?;
	u.merge_user_metadata(&data);
	user::update(tx, &mut u, &["raw_user_meta_data"])
		.await
		.map_err(|e| ApiError::internal("Database error updating user").with_internal(e))?;
	audit(
		tx,
		&u,
		"invite_accepted",
		req,
		Some(traits(&[("provider", provider_name)])),
	)
	.await?;
	super::signup::remove_unconfirmed_identities(tx, &mut u, &i).await?;
	super::signup::confirm(tx, &mut u).await?;
	Ok(u)
}

// ------------------------------------------------------------------------------------------
// POST /token?grant_type=id_token

pub async fn id_token_grant(app: &App, req: &Req) -> ApiResult<Response> {
	let p = req.params()?;
	let id_token = p.str("id_token")?;
	let access_token = p.str("access_token")?;
	let nonce = p.str("nonce")?;
	let provider_name = p.str("provider")?;
	let client_id = p.str("client_id")?;
	let issuer = p.str("issuer")?;
	if id_token.is_empty() {
		return Err(ApiError::oauth("invalid request", "id_token required"));
	}
	if provider_name.is_empty() && (client_id.is_empty() || issuer.is_empty()) {
		return Err(ApiError::oauth(
			"invalid request",
			"provider or client_id and issuer required",
		));
	}
	if p.bool("link_identity")?.unwrap_or(false) {
		return Err(ApiError::bad_request(
			"manual_linking_disabled",
			"Manual linking is disabled",
		));
	}
	if provider_name != "google" && issuer != GOOGLE_ISSUER {
		return Err(ApiError::bad_request(
			"validation_failed",
			format!("Custom OIDC provider {provider_name:?} not allowed"),
		));
	}
	let cfg = app.config.google.clone();
	if !cfg.enabled {
		return Err(ApiError::bad_request(
			"provider_disabled",
			format!("Provider (issuer {GOOGLE_ISSUER:?}) is not enabled"),
		));
	}
	let claims = app
		.oidc
		.verify(&app.http, GOOGLE_ISSUER, &id_token)
		.await
		.map_err(|e| ApiError::oauth("invalid request", "Bad ID token").with_internal(e))?;
	if let Some(at_hash) = claims.get("at_hash").and_then(Value::as_str)
		&& !access_token.is_empty()
		&& !crate::oidc::at_hash_matches(at_hash, &access_token)
	{
		return Err(ApiError::oauth("invalid request", "Bad ID token")
			.with_internal("access token hash does not match value in ID token"));
	}
	let profile = google_from_claims(&claims);
	if claims
		.get("sub")
		.and_then(Value::as_str)
		.unwrap_or("")
		.is_empty()
	{
		return Err(ApiError::oauth(
			"invalid request",
			"Missing sub claim in id_token",
		));
	}
	let audiences: Vec<String> = match claims.get("aud") {
		Some(Value::String(a)) => vec![a.clone()],
		Some(Value::Array(a)) => a
			.iter()
			.filter_map(|x| x.as_str().map(str::to_string))
			.collect(),
		_ => vec![],
	};
	if !cfg
		.client_id
		.iter()
		.filter(|c| !c.is_empty())
		.any(|c| audiences.contains(c))
	{
		return Err(ApiError::oauth(
			"invalid request",
			format!(
				"Unacceptable audience in id_token: [{}]",
				audiences.join(" ")
			),
		));
	}
	if !cfg.skip_nonce_check {
		let token_nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
		if token_nonce.is_empty() != nonce.is_empty() {
			return Err(ApiError::oauth(
				"invalid request",
				"Passed nonce and nonce in id_token should either both exist or not.",
			));
		}
		// The client may have handed the provider the nonce's hash (the usual way) or the nonce
		// itself; either binds the token to this sign-in.
		if !nonce.is_empty()
			&& token_nonce != crate::crypto::sha256_hex(&nonce)
			&& token_nonce != nonce
		{
			return Err(ApiError::oauth("invalid nonce", "Nonces mismatch"));
		}
	}
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn.transaction().await.map_err(db("Database error"))?;
	let mut u =
		match account_from_identity(app, &tx, req, "google", &profile, cfg.email_optional).await? {
			Linked::Ok(u) => *u,
			Linked::Refused(e) => {
				tx.commit().await.map_err(db("Database error"))?;
				return Err(e);
			}
		};
	let mut headers = HeaderMap::new();
	let body = issue_session(
		app,
		&tx,
		req,
		&mut headers,
		&mut u,
		"oauth",
		Grant::default(),
	)
	.await?;
	tx.commit().await.map_err(db("Database error"))?;
	Ok(with_headers(crate::json::ok(&body), headers))
}
