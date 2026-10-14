//! The admin API (the service role's): users, their factors, invitations, generated links and
//! the audit log.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{App, Req, Shared};
use crate::crypto;
use crate::error::{ApiError, ApiResult, db};
use crate::mailer;
use crate::models::{
	factor, identity, session, token as tok,
	user::{self, User},
};

/// The audit actor for an admin call: no user, the token's role as its name.
async fn audit_admin<C: GenericClient>(
	tx: &C,
	claims: &Map<String, Value>,
	action: &str,
	req: &Req,
	traits: Map<String, Value>,
) -> ApiResult<()> {
	let role = crate::jwt::string_claim(claims, "role");
	tok::audit(
		tx,
		Uuid::nil(),
		role,
		false,
		None,
		action,
		&req.ip(),
		Some(traits),
	)
	.await
	.map_err(db("Database error creating audit log entry"))
}

fn user_traits(u: &User) -> Map<String, Value> {
	let mut m = Map::new();
	m.insert("user_id".into(), json!(u.id));
	m.insert("user_email".into(), json!(u.email));
	m.insert("user_phone".into(), json!(u.phone));
	m
}

async fn load_user(app: &App, id: &str) -> ApiResult<User> {
	let id = Uuid::parse_str(id)
		.map_err(|_| ApiError::not_found("validation_failed", "user_id must be an UUID"))?;
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	user::by_id(&conn, id)
		.await
		.map_err(db("Database error loading user"))?
		.ok_or_else(|| ApiError::not_found("user_not_found", "User not found"))
}

/// A Go-style duration (`24h`, `1h30m`), or `none` for zero.
fn ban_duration(s: &str) -> ApiResult<Option<std::time::Duration>> {
	if s.is_empty() {
		return Ok(None);
	}
	if s == "none" {
		return Ok(Some(std::time::Duration::ZERO));
	}
	crate::config::parse_duration(s).map(Some).map_err(|_| {
		let why = if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
			"missing unit in duration"
		} else {
			"invalid duration"
		};
		ApiError::bad_request(
			"validation_failed",
			format!("invalid format for ban duration: time: {why} {s:?}"),
		)
	})
}

async fn ban<C: GenericClient>(tx: &C, u: &mut User, d: std::time::Duration) -> ApiResult<()> {
	u.banned_until = if d.is_zero() {
		None
	} else {
		Some(crate::json::now() + d)
	};
	user::update(tx, u, &["banned_until"])
		.await
		.map_err(db("Database error updating user"))
}

/// `Link` (next and last pages, the rest of the query kept) and `X-Total-Count`.
fn pagination_headers(resp: &mut Response, req: &Req, page: u64, per_page: u64, total: u64) {
	let pages = total.div_ceil(per_page.max(1));
	let url_with = |p: u64| {
		let mut pairs: Vec<(String, String)> = req
			.query
			.iter()
			.filter(|(k, _)| k != "page")
			.cloned()
			.collect();
		pairs.push(("page".into(), p.to_string()));
		pairs.sort_by(|a, b| a.0.cmp(&b.0));
		let q = url::form_urlencoded::Serializer::new(String::new())
			.extend_pairs(pairs)
			.finish();
		format!("{}?{q}", req.path)
	};
	let mut link = String::new();
	if pages > page {
		link.push_str(&format!("<{}>; rel=\"next\", ", url_with(page + 1)));
	}
	link.push_str(&format!("<{}>; rel=\"last\"", url_with(pages)));
	if let Ok(v) = HeaderValue::from_str(&link) {
		resp.headers_mut().insert("link", v);
	}
	resp.headers_mut().insert(
		"x-total-count",
		HeaderValue::from_str(&total.to_string()).expect("a number"),
	);
}

// ------------------------------------------------------------------------------------------
// Users.

pub async fn list_users(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let claims = super::require_admin(&app, &req).await?;
		let aud = super::request_aud(&app, &req, Some(&claims));
		let mut dir = "desc";
		if let Some((_, v)) = req.query.iter().find(|(k, _)| k == "sort") {
			let mut parts = v.splitn(2, ' ');
			let field = parts.next().unwrap_or("");
			if field != "created_at" {
				return Err(ApiError::bad_request("validation_failed", format!("Bad Sort Parameters: bad field for sort '{field}'")));
			}
			dir = match parts.next().map(str::to_ascii_uppercase).as_deref() {
				None | Some("DESC") => "desc",
				Some("ASC") => "asc",
				Some(other) => {
					return Err(ApiError::bad_request("validation_failed", format!("Bad Sort Parameters: bad direction for sort '{other}', only 'asc' and 'desc' allowed")));
				}
			};
		}
		let parse = |k: &str, default: u64| -> ApiResult<u64> {
			match req.query(k) {
				"" => Ok(default),
				v => v.parse().map_err(|e| ApiError::bad_request("validation_failed", format!("Bad Pagination Parameters: {e}"))),
			}
		};
		let page = parse("page", 1)?.max(1);
		let per_page = parse("per_page", 50)?.max(1);
		let filter = req.query("filter");
		let conn = app.pool.get().await.map_err(super::pool_error)?;
		let like = format!("%{filter}%");
		let where_ = "instance_id = '00000000-0000-0000-0000-000000000000' and aud = $1 and ($2 = '' or email like $3 or raw_user_meta_data->>'full_name' ilike $3)";
		let total: i64 = conn
			.query_one(&format!("select count(*) from users where {where_}"), &[&aud, &filter, &like])
			.await
			.map_err(db("Database error finding users"))?
			.get(0);
		let offset = ((page - 1) * per_page) as i64;
		let sql = format!("select {} from users where {where_} order by created_at {dir} limit $4 offset $5", user::COLUMNS);
		let rows = conn.query(&sql, &[&aud, &filter, &like, &(per_page as i64), &offset]).await.map_err(db("Database error finding users"))?;
		let mut users = Vec::with_capacity(rows.len());
		// The list carries each user without their identities or factors (null), as it always has.
		for r in &rows {
			let mut v = User::from_row(r).to_json();
			if let Some(o) = v.as_object_mut() {
				o.insert("identities".into(), Value::Null);
			}
			users.push(v);
		}
		let mut resp = crate::json::ok(&json!({ "users": users, "aud": aud }));
		pagination_headers(&mut resp, &req, page, per_page, total.max(0) as u64);
		Ok(resp)
	}
	.await;
	req.respond(r)
}

pub async fn get_user(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		Ok(crate::json::ok(&load_user(&app, &id).await?.to_json()))
	}
	.await;
	req.respond(r)
}

pub async fn create_user(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = create(&app, &req).await;
	req.respond(r)
}

async fn create(app: &App, req: &Req) -> ApiResult<Response> {
	let cfg = &app.config;
	let claims = super::require_admin(app, req).await?;
	let p = req.params()?;
	let mut aud = super::request_aud(app, req, Some(&claims));
	let given_aud = p.str("aud")?;
	if !given_aud.is_empty() {
		aud = given_aud;
	}
	let mut email = p.str("email")?;
	let phone = p.str("phone")?;
	if email.is_empty() && phone.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Cannot create a user without either an email or phone",
		));
	}
	if !phone.is_empty() {
		return Err(ApiError::bad_request(
			"phone_provider_disabled",
			"Phone logins are disabled",
		));
	}
	email = super::mail::validate_email(&email)?;
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	if super::signup::duplicate_email(&conn, &email, &aud, None)
		.await?
		.is_some()
	{
		return Err(ApiError::unprocessable(
			"email_exists",
			"A user with this email address has already been registered",
		));
	}
	let password = match p.value("password") {
		Some(Value::String(s)) => Some(s.clone()),
		_ => None,
	};
	let password_hash = p.str("password_hash")?;
	if password.is_some() && !password_hash.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Only a password or a password hash should be provided",
		));
	}
	if let Some(pw) = password.as_deref().filter(|p| !p.is_empty()) {
		super::signup::check_password(cfg, pw)?;
	}
	let hash = if !password_hash.is_empty() {
		if !crypto::is_valid_password_hash(&password_hash) {
			return Err(ApiError::bad_request(
				"validation_failed",
				"The password hash is not a bcrypt or argon2 hash this server can check",
			));
		}
		password_hash
	} else {
		let pw = password
			.filter(|p| !p.is_empty())
			.unwrap_or_else(|| crypto::secure_alphanumeric(64));
		if pw.len() > super::signup::MAX_PASSWORD {
			return Err(ApiError::bad_request(
				"validation_failed",
				"bcrypt: password length exceeds 72 bytes",
			));
		}
		tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
			.await
			.unwrap_or_default()
	};
	let mut u = user::new_user(&email, "", Some(hash), &aud, p.map("user_metadata")?);
	let id = p.str("id")?;
	if !id.is_empty() {
		let parsed = Uuid::parse_str(&id).map_err(|_| {
			ApiError::bad_request("validation_failed", "ID must conform to the uuid v4 format")
		})?;
		if parsed.is_nil() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"ID cannot be a nil uuid",
			));
		}
		u.id = parsed;
	}
	let mut app_meta = Map::new();
	app_meta.insert("provider".into(), json!("email"));
	app_meta.insert("providers".into(), json!(["email"]));
	u.app_metadata = Some(app_meta);
	let ban = ban_duration(&p.str("ban_duration")?)?;

	let tx = conn
		.transaction()
		.await
		.map_err(db("Database error creating new user"))?;
	let created = async {
		user::insert(&tx, &u)
			.await
			.map_err(db("Database error creating new user"))?;
		let ident = identity::insert(
			&tx,
			u.id,
			"email",
			identity::email_identity_data(u.id, &u.email),
		)
		.await
		.map_err(db("Database error creating new user"))?;
		u.identities = vec![ident];
		let mut t = user_traits(&u);
		t.insert("provider".into(), json!("email"));
		audit_admin(&tx, &claims, "user_signedup", req, t).await?;
		let role = p.str("role")?;
		u.role = if role.is_empty() {
			cfg.jwt_default_group.clone()
		} else {
			role.trim().to_string()
		};
		user::update(&tx, &mut u, &["role"])
			.await
			.map_err(db("Database error creating new user"))?;
		if let Some(am) = p.map("app_metadata")? {
			u.merge_app_metadata(&am);
			user::update(&tx, &mut u, &["raw_app_meta_data"])
				.await
				.map_err(db("Database error creating new user"))?;
		}
		if p.bool("email_confirm")?.unwrap_or(false) {
			super::signup::confirm(&tx, &mut u).await?;
		}
		if let Some(d) = ban {
			ban_fn(&tx, &mut u, d).await?;
		}
		Ok::<(), ApiError>(())
	}
	.await;
	if let Err(e) = created {
		return Err(if e.status.as_u16() >= 500 {
			ApiError::internal("Database error creating new user")
				.with_internal(e.internal.unwrap_or(e.message))
		} else {
			e
		});
	}
	tx.commit()
		.await
		.map_err(db("Database error creating new user"))?;
	user::reload(&conn, &mut u)
		.await
		.map_err(db("Database error creating new user"))?;
	user::load_relations(&conn, &mut u)
		.await
		.map_err(db("Database error creating new user"))?;
	Ok(crate::json::ok(&u.to_json()))
}

async fn ban_fn<C: GenericClient>(tx: &C, u: &mut User, d: std::time::Duration) -> ApiResult<()> {
	ban(tx, u, d).await
}

pub async fn update_user(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = update(&app, &req, &id).await;
	req.respond(r)
}

async fn update(app: &App, req: &Req, id: &str) -> ApiResult<Response> {
	let cfg = &app.config;
	let claims = super::require_admin(app, req).await?;
	let mut u = load_user(app, id).await?;
	let p = req.params()?;
	let mut email = p.str("email")?;
	if !email.is_empty() {
		email = super::mail::validate_email(&email)?;
	}
	if !p.str("phone")?.is_empty() {
		return Err(ApiError::bad_request(
			"phone_provider_disabled",
			"Phone logins are disabled",
		));
	}
	let ban = ban_duration(&p.str("ban_duration")?)?;
	let password = match p.value("password") {
		Some(Value::String(s)) => Some(s.clone()),
		_ => None,
	};
	let adding_first_password =
		password.as_deref().is_some_and(|p| !p.is_empty()) && !u.has_password();
	if let Some(pw) = &password {
		super::signup::check_password(cfg, pw)?;
		let pw = pw.clone();
		u.encrypted_password = if pw.is_empty() {
			None
		} else {
			Some(
				tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
					.await
					.unwrap_or_default(),
			)
		};
	}
	let email_confirm = p.bool("email_confirm")?.unwrap_or(false);
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let tx = conn
		.transaction()
		.await
		.map_err(db("Error updating user"))?;
	let result: ApiResult<()> = async {
		let role = p.str("role")?;
		if !role.is_empty() {
			u.role = role.trim().to_string();
			user::update(&tx, &mut u, &["role"])
				.await
				.map_err(db("Error updating user"))?;
		}
		if email_confirm {
			super::signup::confirm(&tx, &mut u).await?;
		}
		if password.is_some() {
			super::user_api::set_password(&tx, &mut u, None).await?;
		}
		if !email.is_empty() {
			match identity::by_provider(&tx, &u.id.to_string(), "email")
				.await
				.map_err(db("Error updating user"))?
			{
				None => {
					let mut data = identity::email_identity_data(u.id, &email);
					data.insert("email_verified".into(), json!(email_confirm));
					let i = identity::insert(&tx, u.id, "email", data)
						.await
						.map_err(db("Error updating user"))?;
					u.identities.push(i);
				}
				Some(mut i) => {
					let mut upd = Map::new();
					upd.insert("email".into(), json!(email));
					upd.insert("email_verified".into(), json!(email_confirm));
					identity::update_data(&tx, &mut i, &upd)
						.await
						.map_err(db("Error updating user"))?;
				}
			}
			if u.is_anonymous && email_confirm {
				u.is_anonymous = false;
				user::update(&tx, &mut u, &["is_anonymous"])
					.await
					.map_err(db("Error updating user"))?;
			}
			u.email = email.clone();
			user::update(&tx, &mut u, &["email"])
				.await
				.map_err(db("Error updating user"))?;
			clear_pending(&tx, &mut u).await?;
		}
		if adding_first_password {
			ensure_email_identity(&tx, &mut u).await?;
		}
		if let Some(am) = p.map("app_metadata")? {
			u.merge_app_metadata(&am);
			user::update(&tx, &mut u, &["raw_app_meta_data"])
				.await
				.map_err(db("Error updating user"))?;
		}
		if let Some(um) = p.map("user_metadata")? {
			u.merge_user_metadata(&um);
			user::update(&tx, &mut u, &["raw_user_meta_data"])
				.await
				.map_err(db("Error updating user"))?;
		}
		if let Some(d) = ban {
			ban_fn(&tx, &mut u, d).await?;
		}
		audit_admin(&tx, &claims, "user_modified", req, user_traits(&u)).await
	}
	.await;
	if let Err(e) = result {
		return Err(ApiError::internal("Error updating user")
			.with_internal(e.internal.unwrap_or(e.message)));
	}
	tx.commit().await.map_err(db("Error updating user"))?;
	user::reload(&conn, &mut u)
		.await
		.map_err(db("Error updating user"))?;
	user::load_relations(&conn, &mut u)
		.await
		.map_err(db("Error updating user"))?;
	Ok(crate::json::ok(&u.to_json()))
}

async fn ensure_email_identity<C: GenericClient>(tx: &C, u: &mut User) -> ApiResult<()> {
	if u.is_sso_user
		|| u.is_anonymous
		|| u.email.is_empty()
		|| !u.is_confirmed()
		|| u.identities.iter().any(|i| i.provider == "email")
	{
		return Ok(());
	}
	let mut data = identity::email_identity_data(u.id, &u.email);
	data.insert("email_verified".into(), json!(true));
	let i = identity::insert(tx, u.id, "email", data)
		.await
		.map_err(db("Error creating identity"))?;
	u.identities.push(i);
	super::signup::set_providers(tx, u).await
}

/// Void every link and code outstanding for the user: they were sent to an address that is no
/// longer theirs.
async fn clear_pending<C: GenericClient>(tx: &C, u: &mut User) -> ApiResult<()> {
	u.confirmation_token.clear();
	u.confirmation_sent_at = None;
	u.recovery_token.clear();
	u.recovery_sent_at = None;
	u.email_change.clear();
	u.email_change_token_current.clear();
	u.email_change_token_new.clear();
	u.email_change_sent_at = None;
	u.email_change_confirm_status = 0;
	u.phone_change.clear();
	u.phone_change_token.clear();
	u.phone_change_sent_at = None;
	u.reauthentication_token.clear();
	u.reauthentication_sent_at = None;
	user::update(
		tx,
		u,
		&[
			"confirmation_token",
			"confirmation_sent_at",
			"recovery_token",
			"recovery_sent_at",
			"email_change",
			"email_change_token_current",
			"email_change_token_new",
			"email_change_sent_at",
			"email_change_confirm_status",
			"phone_change",
			"phone_change_token",
			"phone_change_sent_at",
			"reauthentication_token",
			"reauthentication_sent_at",
		],
	)
	.await
	.map_err(db("Error updating user"))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(db("Error updating user"))
}

pub async fn delete_user(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		let claims = super::require_admin(&app, &req).await?;
		let u = load_user(&app, &id).await?;
		let soft = if req.body.is_empty() {
			false
		} else {
			req.params()?.bool("should_soft_delete")?.unwrap_or(false)
		};
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Database error deleting user"))?;
		audit_admin(&tx, &claims, "user_deleted", &req, user_traits(&u))
			.await
			.map_err(|e| {
				ApiError::internal("Error recording audit log entry").with_internal(e.message)
			})?;
		if soft {
			if u.deleted_at.is_none() {
				soft_delete(&tx, u).await?;
			}
		} else {
			tx.execute("delete from users where id = $1", &[&u.id])
				.await
				.map_err(db("Database error deleting user"))?;
		}
		tx.commit()
			.await
			.map_err(db("Database error deleting user"))?;
		Ok(crate::json::ok(&json!({})))
	}
	.await;
	req.respond(r)
}

fn obfuscate(id: Uuid, value: &str) -> String {
	use base64::Engine;
	use sha2::{Digest, Sha256};
	base64::engine::general_purpose::URL_SAFE_NO_PAD
		.encode(Sha256::digest(format!("{id}{value}").as_bytes()))
}

/// Keep the row (for foreign keys pointing at it) with everything that identified the person
/// replaced by hashes, and end their sessions.
async fn soft_delete<C: GenericClient>(tx: &C, mut u: User) -> ApiResult<()> {
	let e = |m: &'static str| {
		move |err: tokio_postgres::Error| ApiError::internal(m).with_internal(err)
	};
	u.email = obfuscate(u.id, &u.email);
	u.phone = obfuscate(u.id, &u.phone)[..15].to_string();
	u.email_change = obfuscate(u.id, &u.email_change);
	u.phone_change = obfuscate(u.id, &u.phone_change)[..15].to_string();
	u.encrypted_password = None;
	u.confirmation_token.clear();
	u.recovery_token.clear();
	u.email_change_token_current.clear();
	u.email_change_token_new.clear();
	u.phone_change_token.clear();
	u.deleted_at = Some(crate::json::now());
	u.user_metadata = Some(Map::new());
	u.app_metadata = Some(Map::new());
	user::update(
		tx,
		&mut u,
		&[
			"email",
			"phone",
			"encrypted_password",
			"email_change",
			"phone_change",
			"confirmation_token",
			"recovery_token",
			"email_change_token_current",
			"email_change_token_new",
			"phone_change_token",
			"deleted_at",
			"raw_user_meta_data",
			"raw_app_meta_data",
		],
	)
	.await
	.map_err(e("Error soft deleting user"))?;
	tok::clear_all(tx, u.id)
		.await
		.map_err(e("Error soft deleting user"))?;
	for mut i in identity::for_user(tx, u.id)
		.await
		.map_err(e("Error soft deleting user identities"))?
	{
		let clear: Map<String, Value> = i
			.identity_data
			.keys()
			.map(|k| (k.clone(), Value::Null))
			.collect();
		identity::update_data(tx, &mut i, &clear)
			.await
			.map_err(e("Error soft deleting user identities"))?;
		let hidden = obfuscate(i.user_id, &format!("{}:{}", i.provider, i.provider_id));
		tx.execute(
			"update identities set provider_id = $1 where id = $2",
			&[&hidden, &i.id],
		)
		.await
		.map_err(e("Error soft deleting user identities"))?;
	}
	tx.execute("delete from mfa_factors where user_id = $1", &[&u.id])
		.await
		.map_err(e("Error deleting user's factors"))?;
	tx.execute(
		"delete from webauthn_credentials where user_id = $1",
		&[&u.id],
	)
	.await
	.map_err(e("Error deleting user's WebAuthn credentials"))?;
	session::delete_all_for_user(tx, u.id)
		.await
		.map_err(e("Error deleting user's sessions"))?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// Factors.

async fn load_factor(app: &App, u: &User, id: &str) -> ApiResult<factor::Factor> {
	let fid = Uuid::parse_str(id)
		.map_err(|_| ApiError::not_found("validation_failed", "factor_id must be an UUID"))?;
	let conn = app.pool.get().await.map_err(super::pool_error)?;
	match factor::by_id(&conn, fid)
		.await
		.map_err(db("Database error loading factor"))?
	{
		Some(f) if f.user_id == u.id => Ok(f),
		_ => Err(ApiError::not_found(
			"mfa_factor_not_found",
			"Factor not found",
		)),
	}
}

pub async fn list_factors(
	axum::extract::State(app): Shared,
	Path(id): Path<String>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let u = load_user(&app, &id).await?;
		let list: Vec<Value> = u.factors.iter().map(factor::Factor::to_json).collect();
		Ok(crate::json::ok(&if list.is_empty() {
			Value::Null
		} else {
			Value::Array(list)
		}))
	}
	.await;
	req.respond(r)
}

pub async fn delete_factor(
	axum::extract::State(app): Shared,
	Path((id, fid)): Path<(String, String)>,
	req: Req,
) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let u = load_user(&app, &id).await?;
		let f = load_factor(&app, &u, &fid).await?;
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Database error deleting factor"))?;
		let mut t = Map::new();
		t.insert("user_id".into(), json!(u.id));
		t.insert("factor_id".into(), json!(f.id));
		super::token::audit(&tx, &u, "factor_deleted", &req, Some(t)).await?;
		factor::delete(&tx, f.id)
			.await
			.map_err(db("Database error deleting factor"))?;
		super::mfa::downgrade_sessions(&tx, u.id, f.id).await?;
		tx.commit()
			.await
			.map_err(db("Database error deleting factor"))?;
		Ok(crate::json::ok(&f.to_json()))
	}
	.await;
	req.respond(r)
}

pub async fn update_factor(
	axum::extract::State(app): Shared,
	Path((id, fid)): Path<(String, String)>,
	req: Req,
) -> Response {
	let r = async {
		let claims = super::require_admin(&app, &req).await?;
		let u = load_user(&app, &id).await?;
		let mut f = load_factor(&app, &u, &fid).await?;
		let p = req.params()?;
		let name = p.str("friendly_name")?;
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let tx = conn
			.transaction()
			.await
			.map_err(db("Database error updating factor"))?;
		if !name.is_empty() {
			tx.execute(
				"update mfa_factors set friendly_name = $1, updated_at = $2 where id = $3",
				&[&name, &crate::json::now(), &f.id],
			)
			.await
			.map_err(db("Database error updating factor"))?;
			f.friendly_name = name;
		}
		let mut t = Map::new();
		t.insert("user_id".into(), json!(u.id));
		t.insert("factor_id".into(), json!(f.id));
		t.insert("factor_type".into(), json!(f.factor_type));
		audit_admin(&tx, &claims, "factor_updated", &req, t).await?;
		tx.commit()
			.await
			.map_err(db("Database error updating factor"))?;
		Ok(crate::json::ok(&f.to_json()))
	}
	.await;
	req.respond(r)
}

// ------------------------------------------------------------------------------------------
// Invitations and generated links.

pub async fn invite(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		let claims = super::require_admin(&app, &req).await?;
		let p = req.params()?;
		let email = super::mail::validate_email(&p.str("email")?)?;
		let data = p.map("data")?;
		let aud = super::request_aud(&app, &req, Some(&claims));
		let mut conn = app.pool.get().await.map_err(super::pool_error)?;
		let existing = user::by_email(&conn, &email, &aud)
			.await
			.map_err(db("Database error finding user"))?;
		let tx = conn.transaction().await.map_err(db("Database error"))?;
		let mut u = match existing {
			Some(u) if u.is_confirmed() => {
				return Err(ApiError::unprocessable(
					"email_exists",
					"A user with this email address has already been registered",
				));
			}
			Some(u) => u,
			None => {
				let mut nu = user::new_user(&email, "", Some(String::new()), &aud, data);
				let mut app_meta = Map::new();
				app_meta.insert("provider".into(), json!("email"));
				app_meta.insert("providers".into(), json!(["email"]));
				nu.app_metadata = Some(app_meta);
				super::signup::create_user(&tx, &mut nu, &app.config.jwt_default_group).await?;
				let i = identity::insert(
					&tx,
					nu.id,
					"email",
					identity::email_identity_data(nu.id, &nu.email),
				)
				.await
				.map_err(db("Error creating identity"))?;
				nu.identities = vec![i];
				nu
			}
		};
		let mut t = Map::new();
		t.insert("user_id".into(), json!(u.id));
		t.insert("user_email".into(), json!(u.email));
		audit_admin(&tx, &claims, "user_invited", &req, t).await?;
		super::mail::send_invite(&app, &tx, &req, &mut u).await?;
		tx.commit().await.map_err(db("Database error"))?;
		Ok(crate::json::ok(&u.to_json()))
	}
	.await;
	req.respond(r)
}

pub async fn generate_link(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = generate(&app, &req).await;
	req.respond(r)
}

async fn generate(app: &App, req: &Req) -> ApiResult<Response> {
	let cfg = &app.config;
	let claims = super::require_admin(app, req).await?;
	let p = req.params()?;
	let mut kind = p.str("type")?;
	let email = super::mail::validate_email(&p.str("email")?)?;
	let new_email_given = p.str("new_email")?;
	let password = p.str("password")?;
	let data = p.map("data")?;
	let redirect_to = p.str("redirect_to")?;
	let mut referrer = req.referrer(cfg);
	if crate::redirect::is_valid(&cfg.site_url, &cfg.allow_list, &redirect_to) {
		referrer = redirect_to;
	}
	let aud = super::request_aud(app, req, Some(&claims));
	let mut conn = app.pool.get().await.map_err(super::pool_error)?;
	let mut found = user::by_email(&conn, &email, &aud)
		.await
		.map_err(db("Database error finding user"))?;
	let mut password = password;
	if found.is_none() {
		match kind.as_str() {
			"magiclink" => {
				kind = "signup".into();
				password = crypto::secure_alphanumeric(64);
			}
			"recovery" | "email_change_current" | "email_change_new" => {
				return Err(ApiError::not_found(
					"user_not_found",
					"User with this email not found",
				));
			}
			_ => {}
		}
	}
	if kind == "signup" && found.is_none() {
		if password.is_empty() {
			return Err(ApiError::bad_request(
				"validation_failed",
				"Signup requires a valid password",
			));
		}
		super::signup::check_password(cfg, &password)?;
	}
	let code = crypto::otp(cfg.otp_length);
	let hashed = crypto::token_hash(&app.config.jwt_secret, &email, &code);
	let tx = conn.transaction().await.map_err(db("Database error"))?;
	let path: &str;
	let token_for_link: String;
	match kind.as_str() {
		"magiclink" | "recovery" => {
			let u = found.as_mut().expect("checked above");
			super::token::audit(&tx, u, "user_recovery_requested", req, None).await?;
			u.recovery_token = hashed.clone();
			u.recovery_sent_at = Some(crate::json::now());
			user::update(&tx, u, &["recovery_token", "recovery_sent_at"])
				.await
				.map_err(db("Database error updating user for recovery"))?;
			tok::create(&tx, u.id, &u.email, &hashed, tok::RECOVERY)
				.await
				.map_err(db("Database error creating recovery token in admin"))?;
			path = &cfg.url_paths.recovery;
			token_for_link = hashed.clone();
		}
		"invite" | "signup" => {
			let invite = kind == "invite";
			if let Some(u) = found.as_ref()
				&& u.is_confirmed()
			{
				return Err(ApiError::unprocessable(
					"email_exists",
					"A user with this email address has already been registered",
				));
			}
			if found.is_none() {
				let hash = if invite {
					String::new()
				} else {
					let pw = password.clone();
					tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
						.await
						.unwrap_or_default()
				};
				let mut nu = user::new_user(&email, "", Some(hash), &aud, data.clone());
				let mut app_meta = Map::new();
				app_meta.insert("provider".into(), json!("email"));
				app_meta.insert("providers".into(), json!(["email"]));
				nu.app_metadata = Some(app_meta);
				super::signup::create_user(&tx, &mut nu, &cfg.jwt_default_group).await?;
				let i = identity::insert(
					&tx,
					nu.id,
					"email",
					identity::email_identity_data(nu.id, &nu.email),
				)
				.await
				.map_err(db("Error creating identity"))?;
				nu.identities = vec![i];
				found = Some(nu);
			} else if let (false, Some(u), Some(d)) = (invite, found.as_mut(), &data) {
				u.merge_user_metadata(d);
				user::update(&tx, u, &["raw_user_meta_data"])
					.await
					.map_err(db("Database error updating user"))?;
			}
			let u = found.as_mut().expect("present");
			if invite {
				let mut t = Map::new();
				t.insert("user_id".into(), json!(u.id));
				t.insert("user_email".into(), json!(u.email));
				audit_admin(&tx, &claims, "user_invited", req, t).await?;
			}
			let now = crate::json::now();
			u.confirmation_token = hashed.clone();
			u.confirmation_sent_at = Some(now);
			let mut cols = vec!["confirmation_token", "confirmation_sent_at"];
			if invite {
				u.invited_at = Some(now);
				cols.push("invited_at");
			}
			user::update(&tx, u, &cols)
				.await
				.map_err(db("Database error updating user for confirmation"))?;
			tok::create(&tx, u.id, &u.email, &hashed, tok::CONFIRMATION)
				.await
				.map_err(db("Database error creating confirmation token"))?;
			path = if invite {
				&cfg.url_paths.invite
			} else {
				&cfg.url_paths.confirmation
			};
			token_for_link = hashed.clone();
		}
		"email_change_current" | "email_change_new" => {
			if !cfg.secure_email_change && kind == "email_change_current" {
				return Err(ApiError::bad_request(
					"validation_failed",
					"Enable secure email change to generate link for current email",
				));
			}
			let new_email = super::mail::validate_email(&new_email_given)?;
			let u = found.as_mut().expect("checked above");
			if super::signup::duplicate_email(&tx, &new_email, &u.aud, Some(u.id))
				.await?
				.is_some()
			{
				return Err(ApiError::unprocessable(
					"email_exists",
					"A user with this email address has already been registered",
				));
			}
			u.email_change_sent_at = Some(crate::json::now());
			u.email_change = new_email.clone();
			u.email_change_confirm_status = 0;
			if kind == "email_change_current" {
				u.email_change_token_current = hashed.clone();
			} else {
				u.email_change_token_new =
					crypto::token_hash(&app.config.jwt_secret, &new_email, &code);
			}
			user::update(
				&tx,
				u,
				&[
					"email_change_token_current",
					"email_change_token_new",
					"email_change",
					"email_change_sent_at",
					"email_change_confirm_status",
				],
			)
			.await
			.map_err(db("Database error updating user for email change"))?;
			if !u.email_change_token_current.is_empty() {
				tok::create(
					&tx,
					u.id,
					&u.email,
					&u.email_change_token_current,
					tok::EMAIL_CHANGE_CURRENT,
				)
				.await
				.map_err(db("Database error"))?;
			}
			if !u.email_change_token_new.is_empty() {
				tok::create(
					&tx,
					u.id,
					&u.email_change,
					&u.email_change_token_new,
					tok::EMAIL_CHANGE_NEW,
				)
				.await
				.map_err(db("Database error"))?;
			}
			path = &cfg.url_paths.email_change;
			token_for_link = if kind == "email_change_current" {
				u.email_change_token_current.clone()
			} else {
				u.email_change_token_new.clone()
			};
		}
		other => {
			return Err(ApiError::bad_request(
				"validation_failed",
				format!("Invalid email action link type requested: {other}"),
			));
		}
	}
	let link_kind = match kind.as_str() {
		"email_change_current" | "email_change_new" => "email_change",
		k => k,
	};
	let action_link = mailer::action_link(
		&cfg.external_url,
		path,
		&token_for_link,
		link_kind,
		&referrer,
	);
	tx.commit().await.map_err(db("Database error"))?;
	let mut u = found.expect("present");
	user::load_relations(&conn, &mut u)
		.await
		.map_err(db("Database error"))?;
	let mut body = match u.to_json() {
		Value::Object(m) => m,
		_ => Map::new(),
	};
	body.insert("action_link".into(), json!(action_link));
	body.insert("email_otp".into(), json!(code));
	body.insert(
		"hashed_token".into(),
		json!(if kind == "email_change_new" {
			token_for_link.clone()
		} else {
			hashed.clone()
		}),
	);
	body.insert("verification_type".into(), json!(kind));
	body.insert("redirect_to".into(), json!(referrer));
	Ok(crate::json::ok(&Value::Object(body)))
}

// ------------------------------------------------------------------------------------------
// The audit log.

pub async fn audit_log(axum::extract::State(app): Shared, req: Req) -> Response {
	let r = async {
		super::require_admin(&app, &req).await?;
		let columns: &[&str] = match req.query("query") {
			"" => &[],
			_ => &["actor_username", "action", "log_type", "actor_id"],
		};
		let q = req.query("query");
		let page: i64 = req.query("page").parse().unwrap_or(1).max(1);
		let per_page: i64 = req.query("per_page").parse().unwrap_or(50).max(1);
		let conn = app.pool.get().await.map_err(super::pool_error)?;
		let mut where_ = "instance_id = '00000000-0000-0000-0000-000000000000'".to_string();
		let like = format!("%{q}%");
		if !columns.is_empty() {
			let ors: Vec<String> = columns.iter().map(|c| format!("payload->>'{c}' ilike $1")).collect();
			where_.push_str(&format!(" and ($1 = $1 and ({}))", ors.join(" or ")));
		} else {
			where_.push_str(" and $1 = $1");
		}
		let rows = conn
			.query(
				&format!("select id, payload, created_at, ip_address from audit_log_entries where {where_} order by created_at desc limit $2 offset $3"),
				&[&like, &per_page, &((page - 1) * per_page)],
			)
			.await
			.map_err(db("Database error finding audit log entries"))?;
		let total: i64 = conn
			.query_one(&format!("select count(*) from audit_log_entries where {where_}"), &[&like])
			.await
			.map_err(db("Database error finding audit log entries"))?
			.get(0);
		let list: Vec<Value> = rows
			.iter()
			.map(|r| {
				let id: Uuid = r.get(0);
				let payload: Option<Value> = r.get(1);
				let at: Option<time::OffsetDateTime> = r.get(2);
				let ip: String = r.get(3);
				json!({ "id": id, "payload": payload.map(crate::json::sorted), "created_at": crate::json::opt_time(at), "ip_address": ip })
			})
			.collect();
		let mut resp = crate::json::respond(StatusCode::OK, &list);
		pagination_headers(&mut resp, &req, page as u64, per_page as u64, total.max(0) as u64);
		Ok(resp)
	}
	.await;
	req.respond(r)
}
