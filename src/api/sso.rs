//! Single sign-on: the admin API for SAML identity providers (`/admin/sso/providers`), and
//! starting a sign-in with one (`POST /sso`).

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Params, Req, Shared};
use crate::error::{ApiError, ApiResult, db};
use crate::models::sso::{self, Mapping, Provider};
use crate::models::token as tok;
use crate::saml::{self, IdpMetadata};

fn formats() -> [&'static str; 4] {
	[
		saml::PERSISTENT,
		saml::EMAIL,
		saml::TRANSIENT,
		saml::UNSPECIFIED,
	]
}

fn validation(msg: impl Into<String>) -> ApiError {
	ApiError::bad_request("validation_failed", msg)
}

fn not_found() -> ApiError {
	ApiError::not_found("sso_provider_not_found", "SSO Identity Provider not found")
}

// ------------------------------------------------------------------------------------------
// Admin.

/// What a create or update carries.
struct Body {
	kind: String,
	metadata_url: String,
	metadata_xml: String,
	domains: Option<Vec<String>>,
	mapping: Mapping,
	/// `None` when not given: an update leaves the provider's as it is.
	name_id_format: Option<String>,
	resource_id: Option<String>,
	disabled: Option<bool>,
}

fn body(req: &Req) -> ApiResult<Body> {
	let p = req.params()?;
	let bad = |e: String| {
		ApiError::bad_request(
			"bad_json",
			format!("Could not parse request body as JSON: {e}"),
		)
	};
	let domains = match p.value("domains") {
		None => None,
		Some(Value::Array(a)) => Some(
			a.iter()
				.map(|d| d.as_str().map(str::to_string).ok_or_else(|| bad("json: cannot unmarshal into Go struct field CreateSSOProviderParams.domains of type string".into())))
				.collect::<ApiResult<Vec<_>>>()?,
		),
		Some(_) => return Err(bad("json: cannot unmarshal into Go struct field CreateSSOProviderParams.domains of type []string".into())),
	};
	let mapping =
		Mapping::from_json(p.value("attribute_mapping").unwrap_or(&Value::Null)).map_err(bad)?;
	let name_id_format = match p.value("name_id_format") {
		None => None,
		Some(_) => Some(p.str("name_id_format")?),
	};
	let resource_id = match p.value("resource_id") {
		None => None,
		Some(_) => Some(p.str("resource_id")?),
	};
	Ok(Body {
		kind: p.str("type")?,
		metadata_url: p.str("metadata_url")?,
		metadata_xml: p.str("metadata_xml")?,
		domains,
		mapping,
		name_id_format,
		resource_id,
		disabled: p.bool("disabled")?,
	})
}

fn validate(b: &Body, for_update: bool) -> ApiResult<()> {
	if !for_update && b.kind != "saml" {
		return Err(validation("Only 'saml' supported for SSO provider type"));
	}
	if !b.metadata_url.is_empty() && !b.metadata_xml.is_empty() {
		return Err(validation(
			"Only one of metadata_xml or metadata_url needs to be set",
		));
	}
	if !for_update && b.metadata_url.is_empty() && b.metadata_xml.is_empty() {
		return Err(validation(
			"Either metadata_xml or metadata_url must be set",
		));
	}
	if !b.metadata_url.is_empty() {
		let u = &b.metadata_url;
		let scheme = if u.starts_with('/') {
			Some("")
		} else {
			url::Url::parse(u)
				.ok()
				.map(|x| if x.scheme() == "https" { "https" } else { "" })
		};
		match scheme {
			None => return Err(validation("metadata_url is not a valid URL")),
			Some(s) if s != "https" => return Err(validation("metadata_url is not a HTTPS URL")),
			_ => {}
		}
	}
	let f = b.name_id_format.as_deref().unwrap_or("");
	if !f.is_empty() && !formats().contains(&f) {
		return Err(validation(format!(
			"name_id_format must be unspecified or one of {}",
			formats().join(", ")
		)));
	}
	Ok(())
}

/// Fetch an IdP's metadata from its URL.
pub(crate) async fn fetch_metadata(app: &super::App, url: &str) -> ApiResult<String> {
	let res = app
		.http
		.get(url)
		.header("Accept", "application/xml;charset=UTF-8")
		.header("Accept-Charset", "UTF-8")
		.send()
		.await
		.map_err(|e| ApiError::internal("Unable to fetch SAML Metadata").with_internal(e))?;
	if res.status() != StatusCode::OK {
		return Err(ApiError::bad_request(
			"saml_metadata_fetch_failed",
			format!(
				"HTTP {} error fetching SAML Metadata from URL '{url}'",
				res.status().as_u16()
			),
		));
	}
	let bytes = res
		.bytes()
		.await
		.map_err(|e| ApiError::internal("Unable to fetch SAML Metadata").with_internal(e))?;
	if bytes.len() > crate::xml::MAX_BYTES {
		return Err(validation("SAML Metadata is too large"));
	}
	String::from_utf8(bytes.to_vec()).map_err(|_| {
		validation(
			"SAML Metadata XML contains invalid UTF-8 characters, which are not supported at this time",
		)
	})
}

/// Parse and check an IdP's metadata as the admin API accepts it.
fn check_metadata(raw: &str) -> ApiResult<IdpMetadata> {
	let m = saml::parse_metadata(raw)
		.map_err(|e| validation(format!("SAML Metadata could not be parsed: {e}")))?;
	if m.entity_id.is_empty() {
		return Err(validation("SAML Metadata does not contain an EntityID"));
	}
	if m.idp_descriptors < 1 {
		return Err(validation(
			"SAML Metadata does not contain any IDPSSODescriptor",
		));
	}
	if m.idp_descriptors > 1 {
		return Err(validation(
			"SAML Metadata contains multiple IDPSSODescriptors",
		));
	}
	Ok(m)
}

async fn metadata_of(app: &super::App, b: &Body) -> ApiResult<Option<(String, IdpMetadata)>> {
	let raw = if !b.metadata_xml.is_empty() {
		b.metadata_xml.clone()
	} else if !b.metadata_url.is_empty() {
		fetch_metadata(app, &b.metadata_url).await?
	} else {
		return Ok(None);
	};
	let m = check_metadata(&raw)?;
	Ok(Some((raw, m)))
}

async fn load(app: &super::App, idp: &str) -> ApiResult<Provider> {
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	let found = if let Some(rid) = idp.strip_prefix("resource_") {
		sso::by_resource_id(&conn, rid).await
	} else {
		let id = Uuid::parse_str(idp).map_err(|_| not_found())?;
		sso::by_id(&conn, id).await
	};
	found
		.map_err(db("Database error finding SSO Identity Provider"))?
		.ok_or_else(not_found)
}

fn created(v: Value, status: StatusCode) -> Response {
	crate::json::respond(status, &v)
}

pub async fn list_providers(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let conn = app.pool.get().await.map_err(super::pool_error)?;
		let all = sso::list(
			&conn,
			req.query("resource_id"),
			req.query("resource_id_prefix"),
		)
		.await
		.map_err(db("error loading all SAML SSO providers"))?;
		let items: Vec<Value> = all.iter().map(|p| p.to_json(false)).collect();
		Ok(crate::json::ok(&json!({ "items": items })))
	}
	.await;
	req.respond(r)
}

pub async fn create_provider(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let b = body(&req)?;
		validate(&b, false)?;
		let (raw, meta) = metadata_of(&app, &b)
			.await?
			.ok_or_else(|| validation("Either metadata_xml or metadata_url must be set"))?;
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		if sso::by_entity_id(&conn, &meta.entity_id)
			.await
			.map_err(db("error finding SAML SSO provider by EntityID"))?
			.is_some()
		{
			return Err(ApiError::unprocessable(
				"saml_idp_already_exists",
				format!(
					"SAML Identity Provider with this EntityID ({}) already exists",
					meta.entity_id
				),
			));
		}
		let domains = b.domains.clone().unwrap_or_default();
		for d in &domains {
			if let Some(other) = sso::by_domain(&conn, d)
				.await
				.map_err(db("error finding SAML SSO domain"))?
			{
				return Err(ApiError::bad_request(
					"sso_domain_already_exists",
					format!(
						"SSO Domain '{d}' is already assigned to an SSO identity provider ({})",
						other.id
					),
				));
			}
		}
		let tx = conn
			.transaction()
			.await
			.map_err(db("Database error creating SSO provider"))?;
		let id = sso::create(
			&tx,
			&sso::NewProvider {
				resource_id: b.resource_id.as_deref(),
				disabled: b.disabled,
				entity_id: &meta.entity_id,
				metadata_xml: &raw,
				metadata_url: Some(b.metadata_url.as_str()).filter(|s| !s.is_empty()),
				attribute_mapping: &b.mapping,
				name_id_format: b.name_id_format.as_deref().filter(|s| !s.is_empty()),
				domains: &domains,
			},
		)
		.await
		.map_err(db("Database error creating SSO provider"))?;
		let p = sso::by_id(&tx, id)
			.await
			.map_err(db("Database error creating SSO provider"))?
			.ok_or_else(not_found)?;
		tx.commit()
			.await
			.map_err(db("Database error creating SSO provider"))?;
		Ok(created(p.to_json(true), StatusCode::CREATED))
	}
	.await;
	req.respond(r)
}

pub async fn get_provider(
	axum::extract::State(app): Shared,
	Path(idp): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		Ok(crate::json::ok(&load(&app, &idp).await?.to_json(true)))
	}
	.await;
	req.respond(r)
}

pub async fn update_provider(
	axum::extract::State(app): Shared,
	Path(idp): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let b = body(&req)?;
		validate(&b, true)?;
		let mut p = load(&app, &idp).await?;
		let mut modified = false;
		let mut update_saml = false;

		if let Some((raw, meta)) = metadata_of(&app, &b).await? {
			if p.saml.entity_id != meta.entity_id {
				return Err(ApiError::bad_request(
					"saml_entity_id_mismatch",
					format!("SAML Metadata can be updated only if the EntityID matches for the provider; expected '{}' but got '{}'", p.saml.entity_id, meta.entity_id),
				));
			}
			if !b.metadata_url.is_empty() {
				p.saml.metadata_url = Some(b.metadata_url.clone());
			}
			p.saml.metadata_xml = raw;
			update_saml = true;
			modified = true;
		}

		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let mut create = vec![];
		let mut keep = std::collections::HashSet::new();
		for d in b.domains.iter().flatten() {
			match sso::by_domain(&conn, d).await.map_err(db("error finding SAML SSO domain"))? {
				Some(other) if other.id == p.id => {
					keep.insert(d.clone());
				}
				Some(other) => {
					return Err(ApiError::bad_request("sso_domain_already_exists", format!("SSO domain '{d}' already assigned to another provider ({})", other.id)));
				}
				None => {
					modified = true;
					create.push(d.clone());
				}
			}
		}
		let mut delete = vec![];
		if b.domains.is_some() {
			for d in &p.domains {
				if !keep.contains(&d.domain) {
					modified = true;
					delete.push(d.id);
				}
			}
		}
		if b.mapping.keys.is_some() && !p.saml.attribute_mapping.same_as(&b.mapping) {
			p.saml.attribute_mapping = b.mapping.clone();
			update_saml = true;
			modified = true;
		}
		if let Some(f) = &b.name_id_format {
			let want = Some(f.clone()).filter(|s| !s.is_empty());
			if want != p.saml.name_id_format {
				p.saml.name_id_format = want;
				update_saml = true;
				modified = true;
			}
		}
		if let Some(rid) = &b.resource_id {
			if rid.is_empty() && p.resource_id.is_some() {
				p.resource_id = None;
				modified = true;
			} else if !rid.is_empty() && p.resource_id.as_deref() != Some(rid.as_str()) {
				p.resource_id = Some(rid.clone());
				modified = true;
			}
		}
		if let Some(d) = b.disabled
			&& p.disabled != Some(d) {
				p.disabled = Some(d);
				modified = true;
			}
		if !modified {
			return Ok(crate::json::ok(&p.to_json(true)));
		}
		let conflict = |e: tokio_postgres::Error| ApiError::unprocessable("conflict", "Updating SSO provider failed, likely due to a conflict. Try again?").with_internal(e);
		let tx = conn.transaction().await.map_err(conflict)?;
		sso::update_provider(&tx, &p).await.map_err(conflict)?;
		for id in delete {
			sso::delete_domain(&tx, id).await.map_err(conflict)?;
		}
		for d in &create {
			sso::insert_domain(&tx, p.id, d).await.map_err(conflict)?;
		}
		if update_saml {
			sso::update_saml(&tx, &p.saml).await.map_err(conflict)?;
		}
		let fresh = sso::by_id(&tx, p.id).await.map_err(conflict)?.ok_or_else(not_found)?;
		tx.commit().await.map_err(conflict)?;
		Ok(crate::json::ok(&fresh.to_json(true)))
	}
	.await;
	req.respond(r)
}

pub async fn delete_provider(
	axum::extract::State(app): Shared,
	Path(idp): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let p = load(&app, &idp).await?;
		let conn = app.pool.get().await.map_err(super::pool_error)?;
		sso::delete(&conn, p.id)
			.await
			.map_err(db("error deleting SSO provider"))?;
		Ok(crate::json::ok(&p.to_json(true)))
	}
	.await;
	req.respond(r)
}

// ------------------------------------------------------------------------------------------
// POST /sso

pub async fn start(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = begin(&app, &req).await;
	req.respond(r)
}

async fn begin(app: &super::App, req: &Req) -> ApiResult<Response> {
	let sp = app
		.saml
		.as_ref()
		.ok_or_else(|| ApiError::not_found("saml_provider_disabled", "SAML 2.0 is disabled"))?;
	super::limit(app, req, &app.limits.sso)?;
	let p: Params = req.params()?;
	let raw_id = p.str("provider_id")?;
	let provider_id = if raw_id.is_empty() {
		None
	} else {
		let id = Uuid::parse_str(&raw_id).map_err(|e| {
			ApiError::bad_request(
				"bad_json",
				format!("Could not parse request body as JSON: {e}"),
			)
		})?;
		Some(id).filter(|id| !id.is_nil())
	};
	let domain = p.str("domain")?;
	let redirect_to = p.str("redirect_to")?;
	let skip = p.bool("skip_http_redirect")?.unwrap_or(false);
	let challenge = p.str("code_challenge")?;
	let method = p.str("code_challenge_method")?;

	if provider_id.is_some() && !domain.is_empty() {
		return Err(validation("Only one of provider_id or domain supported"));
	}
	if provider_id.is_none() && domain.is_empty() {
		return Err(validation("A provider_id or domain needs to be provided"));
	}
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let provider = match provider_id {
		Some(id) => sso::by_id(&conn, id)
			.await
			.map_err(|e| ApiError::internal("Unable to find SSO provider by ID").with_internal(e))?
			.ok_or_else(|| ApiError::not_found("sso_provider_not_found", "No such SSO provider"))?,
		None => sso::by_domain(&conn, &domain)
			.await
			.map_err(|e| {
				ApiError::internal("Unable to find SSO provider by domain").with_internal(e)
			})?
			.ok_or_else(|| {
				ApiError::not_found(
					"sso_provider_not_found",
					"No SSO provider assigned for this domain",
				)
			})?,
	};
	if !provider.is_enabled() {
		return Err(ApiError::not_found(
			"sso_provider_disabled",
			"SSO Provider is currently disabled",
		));
	}
	crate::pkce::validate_params(&method, &challenge)?;
	if !challenge.is_empty() && !matches!(method.to_ascii_lowercase().as_str(), "s256" | "plain") {
		return Err(validation("Invalid code_challenge_method"));
	}
	let tx = conn
		.transaction()
		.await
		.map_err(|e| ApiError::internal("Error creating flow state").with_internal(e))?;
	let flow = tok::insert_flow(
		&tx,
		&tok::NewFlow {
			provider_type: "sso/saml",
			authentication_method: "sso/saml",
			code_challenge: &challenge,
			code_challenge_method: &method,
			user_id: None,
			invite_token: None,
			referrer: Some(redirect_to.as_str()).filter(|s| !s.is_empty()),
			provider_access_token: None,
			provider_refresh_token: None,
		},
	)
	.await
	.map_err(|e| ApiError::internal("Error creating flow state").with_internal(e))?;
	let meta = saml::parse_metadata(&provider.saml.metadata_xml).map_err(|e| {
		ApiError::internal("Error parsing SAML Metadata for SAML provider").with_internal(e)
	})?;
	let format = provider
		.saml
		.name_id_format
		.as_deref()
		.unwrap_or(saml::PERSISTENT);
	// The relay state's ID goes in the request URL, so it is chosen first.
	let relay_id = Uuid::new_v4();
	let (request_id, url) = sp
		.authn_request(
			meta.sso_redirect.as_deref().unwrap_or(""),
			format,
			&relay_id.to_string(),
			crate::json::now(),
		)
		.map_err(|e| {
			ApiError::internal("Error creating SAML Authentication Request").with_internal(e)
		})?;
	sso::insert_relay(
		&tx,
		relay_id,
		provider.id,
		&request_id,
		&redirect_to,
		Some(flow.id),
	)
	.await
	.map_err(|e| {
		ApiError::internal("Error creating SAML relay state from sign up").with_internal(e)
	})?;
	tx.commit()
		.await
		.map_err(|e| ApiError::internal("Error creating flow state").with_internal(e))?;
	if skip {
		return Ok(crate::json::ok(&json!({ "url": url })));
	}
	Ok(super::verify::see_other(req, &url))
}
