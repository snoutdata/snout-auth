//! SAML 2.0 service provider endpoints: our metadata (`GET /sso/saml/metadata`) and the
//! assertion consumer (`POST /sso/saml/acs`), where a browser brings back what the identity
//! provider said.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::external::{Linked, Profile, account_from_identity, error_query};
use super::token::{Grant, as_fragment, issue_session};
use super::{App, Req, Shared};
use crate::error::{ApiError, ApiResult};
use crate::models::sso::{self, Mapping};
use crate::models::token as tok;
use crate::saml::{self, Assertion};

pub use crate::saml::ServiceProvider;

fn disabled() -> ApiError {
	ApiError::not_found("saml_provider_disabled", "SAML 2.0 is disabled")
}

fn validation(msg: impl Into<String>) -> ApiError {
	ApiError::bad_request("validation_failed", msg)
}

// ------------------------------------------------------------------------------------------
// GET /sso/saml/metadata

pub async fn metadata(axum::extract::State(app): Shared, req: Req) -> Response {
	let Some(sp) = app.saml.as_ref() else {
		return req.respond(Err(disabled()));
	};
	let download = req.form_value("download") == "true";
	let body = sp.metadata(crate::json::now(), download);
	let mut h = HeaderMap::new();
	h.insert(
		header::CONTENT_TYPE,
		HeaderValue::from_static("application/xml"),
	);
	h.insert(
		header::CACHE_CONTROL,
		HeaderValue::from_static(if sp.next_cert.is_some() {
			"public, max-age=60"
		} else {
			"public, max-age=600"
		}),
	);
	if download {
		h.insert(
			header::CONTENT_DISPOSITION,
			HeaderValue::from_static("attachment; filename=\"metadata.xml\""),
		);
	}
	(StatusCode::OK, h, body).into_response()
}

// ------------------------------------------------------------------------------------------
// POST /sso/saml/acs

pub async fn acs(axum::extract::State(app): Shared, req: Req) -> Response {
	let Some(sp) = app.saml.as_ref() else {
		return req.respond(Err(disabled()));
	};
	if let Err(e) = super::limit(&app, &req, &app.limits.saml_assertion) {
		return req.respond(Err(e));
	}
	// Where a failure is reported: the application's own address once the relay state names
	// one, else the site URL.
	let mut back: Option<String> = None;
	match consume(&app, sp, &req, &mut back).await {
		Ok(r) => r,
		Err(e) => {
			if e.status.is_server_error() {
				tracing::error!(error = %e.message, internal = ?e.internal, "saml acs failed");
			} else {
				tracing::info!(error = %e.message, internal = ?e.internal, "saml acs refused");
			}
			let cfg = &app.config;
			let base = back
				.filter(|b| crate::redirect::is_valid(&cfg.site_url, &cfg.allow_list, b))
				.unwrap_or_else(|| cfg.site_url.clone());
			let q = error_query(&e);
			let pairs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
			super::verify::see_other(&req, &super::verify::with_query(&base, &pairs))
		}
	}
}

/// A form field from the POST body only.
fn posted(req: &Req, name: &str) -> String {
	url::form_urlencoded::parse(&req.body)
		.find(|(k, _)| k == name)
		.map(|(_, v)| v.into_owned())
		.unwrap_or_default()
}

/// A RelayState that is a URL: absolute, or an absolute path.
fn is_request_uri(s: &str) -> bool {
	s.starts_with('/') || url::Url::parse(s).is_ok()
}

async fn consume(
	app: &App,
	sp: &ServiceProvider,
	req: &Req,
	back: &mut Option<String>,
) -> ApiResult<Response> {
	let cfg = &app.config;
	let now = crate::json::now();
	let relay_value = req.form_value("RelayState");
	let relay_id = Uuid::parse_str(&relay_value).ok().filter(|u| !u.is_nil());
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;

	let (entity, idp_initiated, redirect_to, request_ids, flow_id) = if let Some(id) = relay_id {
		let rs = sso::relay_by_id(&conn, id)
			.await
			.map_err(crate::error::db("error loading SAML Relay State"))?
			.ok_or_else(|| {
				ApiError::not_found(
					"saml_relay_state_not_found",
					"SAML RelayState does not exist, try logging in again?",
				)
			})?;
		*back = rs.redirect_to.clone().filter(|s| !s.is_empty());
		if rs
			.created_at
			.is_none_or(|c| now - c >= cfg.saml_relay_state_validity)
		{
			sso::delete_relay(&conn, rs.id).await.map_err(|e| {
				ApiError::internal(
					"SAML RelayState has expired and destroying it failed. Try logging in again?",
				)
				.with_internal(e)
			})?;
			return Err(ApiError::unprocessable(
				"saml_relay_state_expired",
				"SAML RelayState has expired. Try logging in again?",
			));
		}
		let provider = sso::by_id(&conn, rs.sso_provider_id)
			.await
			.ok()
			.flatten()
			.ok_or_else(|| {
				ApiError::internal("Unable to find SSO Provider from SAML RelayState")
			})?;
		if !provider.is_enabled() {
			return Err(ApiError::not_found(
				"sso_provider_disabled",
				"SSO Provider assigned for this domain is currently disabled",
			));
		}
		sso::delete_relay(&conn, rs.id)
			.await
			.map_err(crate::error::db("error deleting SAML Relay State"))?;
		(
			provider.saml.entity_id,
			false,
			rs.redirect_to.unwrap_or_default(),
			vec![rs.request_id],
			rs.flow_state_id,
		)
	} else if relay_value.is_empty() || is_request_uri(&relay_value) {
		if !req.form_value("SAMLart").is_empty() {
			return Err(validation(
				"SAML Artifact response can only be used with SP initiated flow",
			));
		}
		let encoded = req.form_value("SAMLResponse");
		if encoded.is_empty() {
			return Err(validation("SAMLResponse is missing"));
		}
		let decoded = STANDARD
			.decode(encoded.as_bytes())
			.map_err(|_| validation("SAMLResponse is not a valid Base64 string"))?;
		let issuer = String::from_utf8(decoded)
			.ok()
			.and_then(|t| saml::peek_issuer(&t))
			.ok_or_else(|| validation("SAMLResponse is not a valid XML SAML assertion"))?;
		(issuer, true, relay_value.clone(), vec![], None)
	} else {
		return Err(validation("SAML RelayState is not a valid UUID or URL"));
	};

	let provider = sso::by_entity_id(&conn, &entity)
		.await
		.map_err(crate::error::db(
			"error finding SAML SSO provider by EntityID",
		))?
		.ok_or_else(|| {
			ApiError::not_found(
				"saml_idp_not_found",
				"A SAML connection has not been established with this Identity Provider",
			)
		})?;
	if !provider.is_enabled() {
		return Err(ApiError::not_found(
			"sso_provider_disabled",
			"SSO Provider assigned for this domain is currently disabled",
		));
	}
	let mut meta = saml::parse_metadata(&provider.saml.metadata_xml)
		.map_err(|e| ApiError::internal(e.clone()).with_internal(e))?;

	// Metadata held by URL is fetched again when it says it is stale; a failure keeps the old.
	let mut refreshed = None;
	if let Some(url) = provider
		.saml
		.metadata_url
		.as_deref()
		.filter(|u| !u.is_empty())
	{
		if meta.is_stale(provider.saml.updated_at.unwrap_or(now), now) {
			match super::sso::fetch_metadata(app, url)
				.await
				.map(|raw| (saml::parse_metadata(&raw), raw))
			{
				Ok((Ok(m), raw)) if m.entity_id == meta.entity_id => {
					meta = m;
					refreshed = Some(raw);
				}
				Ok((Ok(_), _)) => {
					tracing::warn!(sso_provider_id = %provider.id, "SAML Metadata from its URL names another entity, continuing with existing metadata")
				}
				Ok((Err(e), _)) => {
					tracing::warn!(sso_provider_id = %provider.id, error = %e, "SAML Metadata could not be parsed, continuing with existing metadata")
				}
				Err(e) => {
					tracing::warn!(sso_provider_id = %provider.id, error = %e.message, "SAML Metadata could not be retrieved, continuing with existing metadata")
				}
			}
		}
	} else if let Some(v) = meta.valid_until
		&& v - now <= time::Duration::days(30)
	{
		tracing::warn!(sso_provider_id = %provider.id, valid_until = %v, "SAML Metadata for identity provider will expire soon! Update its metadata_xml!");
	}

	if !idp_initiated && !posted(req, "SAMLart").is_empty() {
		return Err(validation(
			"SAML Artifact binding is not supported: configure the identity provider to answer with HTTP-POST",
		));
	}
	let invalid = |why: String| validation("SAML Assertion is not valid").with_internal(why);
	let text = STANDARD
		.decode(posted(req, "SAMLResponse").as_bytes())
		.ok()
		.and_then(|b| String::from_utf8(b).ok())
		.ok_or_else(|| invalid("cannot parse base64".into()))?;
	let certs = meta.signing_certs().map_err(invalid)?;
	let assertion = saml::validate(
		&text,
		&saml::Expect {
			idp_entity: &meta.entity_id,
			certs: &certs,
			acs: &sp.acs,
			audience: &sp.entity_id,
			request_ids: &request_ids,
			idp_initiated,
			now,
		},
	)
	.map_err(invalid)?;

	let user_id = assertion.user_id();
	if user_id.is_empty() {
		return Err(ApiError::bad_request(
			"saml_assertion_no_user_id",
			"SAML Assertion did not contain a persistent Subject Identifier attribute or Subject NameID uniquely identifying this user",
		));
	}
	let mut claims = process(&assertion, &provider.saml.attribute_mapping);
	let email = match claims.get("email") {
		Some(Value::String(s)) if !s.is_empty() => s.clone(),
		_ => assertion.email(),
	};
	if email.is_empty() {
		return Err(ApiError::bad_request(
			"saml_assertion_no_email",
			"SAML Assertion does not contain an email address",
		));
	}
	claims.insert("email".into(), json!(email));
	let data = identity_data(claims, &user_id, &meta.entity_id, &email)?;

	if let Some(raw) = &refreshed {
		sso::update_metadata(&conn, provider.saml.id, raw)
			.await
			.map_err(crate::error::db("error updating SAML Metadata"))?;
	}
	let provider_type = format!("sso:{}", provider.id);
	let profile = Profile {
		emails: vec![(email.clone(), true, true)],
		claims: data.clone(),
		data: Some(data),
	};

	let tx = conn
		.transaction()
		.await
		.map_err(crate::error::db("Database error"))?;
	let mut u = match account_from_identity(app, &tx, req, &provider_type, &profile, false).await? {
		Linked::Ok(u) => *u,
		Linked::Refused(e) => return Err(e),
	};
	let flow = match flow_id {
		Some(id) => tok::flow_by_id(&tx, id)
			.await
			.map_err(crate::error::db("Database error"))?,
		None => None,
	};
	let mut pkce_flow = None;
	if let Some(mut f) = flow.filter(|f| f.is_pkce()) {
		let locked = tx
			.query_opt(
				"select user_id from flow_state where id = $1 for update",
				&[&f.id],
			)
			.await
			.map_err(crate::error::db("Database error"))?;
		if locked.and_then(|r| r.get::<_, Option<Uuid>>(0)).is_some() {
			return Err(ApiError::bad_request(
				"flow_state_already_used",
				"State has already been used",
			));
		}
		tok::set_flow_user(&tx, &mut f, u.id)
			.await
			.map_err(crate::error::db("Database error"))?;
		pkce_flow = Some(f);
	}
	let mut headers = HeaderMap::new();
	let body = issue_session(
		app,
		&tx,
		req,
		&mut headers,
		&mut u,
		"sso/saml",
		Grant {
			factor_id: None,
			not_after: assertion.session_not_on_or_after,
			tag: None,
		},
	)
	.await
	.map_err(|e| {
		ApiError::internal("Unable to issue refresh token from SAML Assertion")
			.with_internal(e.message)
	})?;
	tx.commit()
		.await
		.map_err(crate::error::db("Database error"))?;

	let target = if crate::redirect::is_valid(&cfg.site_url, &cfg.allow_list, &redirect_to) {
		redirect_to
	} else {
		cfg.site_url.clone()
	};
	let location = match &pkce_flow {
		Some(f) => {
			super::verify::with_query(&target, &[("code", f.auth_code.as_deref().unwrap_or(""))])
		}
		None => as_fragment(&target, &body, &[]),
	};
	let mut r = super::verify::go_redirect(req, &location, StatusCode::FOUND);
	for (k, v) in headers.iter() {
		r.headers_mut().insert(k.clone(), v.clone());
	}
	Ok(r)
}

/// The claims an attribute mapping makes of an assertion's attributes.
fn process(a: &Assertion, mapping: &Mapping) -> Map<String, Value> {
	let mut out = Map::new();
	for (key, rule) in mapping.keys.iter().flatten() {
		let mut names = vec![];
		if !rule.name.is_empty() {
			names.push(rule.name.as_str());
		}
		names.extend(rule.names.iter().map(String::as_str));
		let mut set = false;
		for name in names {
			for v in a.attribute(name) {
				if v.is_empty() {
					continue;
				}
				set = true;
				if rule.array {
					match out.entry(key.clone()).or_insert_with(|| json!([])) {
						Value::Array(list) => list.push(json!(v)),
						other => *other = json!([v]),
					}
				} else {
					out.insert(key.clone(), json!(v));
					break;
				}
			}
			if set {
				break;
			}
		}
		if !set && let Some(d) = &rule.default {
			out.insert(key.clone(), d.clone());
		}
	}
	out
}

const STRING_CLAIMS: &[&str] = &[
	"iss",
	"sub",
	"name",
	"family_name",
	"given_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"email",
	"phone",
	"full_name",
	"avatar_url",
	"slug",
	"provider_id",
	"user_name",
];

/// The identity data: the standard claims the mapping produced (checked for type, as a
/// provider's claims are), our subject, issuer and address, and every other mapped claim under
/// `custom_claims`.
fn identity_data(
	mut claims: Map<String, Value>,
	user_id: &str,
	issuer: &str,
	email: &str,
) -> ApiResult<Map<String, Value>> {
	let wrong = |k: &str| {
		ApiError::internal("Mapped claims from provider could not be deserialized from JSON")
			.with_internal(format!("claim {k} has the wrong type"))
	};
	let mut known = Map::new();
	for (k, v) in &claims {
		let ok = match k.as_str() {
			k if STRING_CLAIMS.contains(&k) => v.is_string(),
			"email_verified" | "phone_verified" => v.is_boolean(),
			"iat" | "exp" => v.is_number(),
			"aud" => v.is_string() || v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
			"updated_at" => v.is_number() || v.is_string(),
			"custom_claims" => v.is_object(),
			_ => continue,
		};
		if !ok {
			return Err(wrong(k));
		}
		let empty = match v {
			Value::String(s) => s.is_empty(),
			Value::Number(n) => n.as_f64() == Some(0.0),
			Value::Array(a) => a.is_empty(),
			Value::Object(o) => o.is_empty(),
			Value::Bool(_) => false,
			Value::Null => true,
		};
		if !empty || matches!(k.as_str(), "email_verified" | "phone_verified") {
			known.insert(k.clone(), v.clone());
		}
	}
	known.insert("sub".into(), json!(user_id));
	known.insert("iss".into(), json!(issuer));
	known.insert("email".into(), json!(email.to_lowercase()));
	known.insert("email_verified".into(), json!(true));
	known.entry("phone_verified").or_insert(json!(false));
	// What the standard claims took is not repeated under custom_claims.
	for k in known.keys() {
		claims.remove(k);
	}
	claims.remove("email_verified");
	claims.remove("phone_verified");
	known.insert("custom_claims".into(), Value::Object(claims));
	Ok(known)
}
